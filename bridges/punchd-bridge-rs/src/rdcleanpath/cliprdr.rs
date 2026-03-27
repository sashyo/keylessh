/// CLIPRDR (Clipboard Virtual Channel) support for RDP file transfer.
///
/// Handles:
/// - MCS channel ID discovery (CS_NET / SC_NET parsing)
/// - TPKT frame reassembly
/// - CLIPRDR PDU parsing and construction
/// - File descriptor extraction and file content fetching
/// - Virtual channel chunk reassembly

use std::collections::HashMap;

// ── CLIPRDR message types ────────────────────────────────────────

pub const CB_MONITOR_READY: u16 = 0x0001;
pub const CB_FORMAT_LIST: u16 = 0x0002;
pub const CB_FORMAT_LIST_RESPONSE: u16 = 0x0003;
pub const CB_FORMAT_DATA_REQUEST: u16 = 0x0004;
pub const CB_FORMAT_DATA_RESPONSE: u16 = 0x0005;
pub const CB_FILECONTENTS_REQUEST: u16 = 0x0008;
pub const CB_FILECONTENTS_RESPONSE: u16 = 0x0009;

pub const CB_RESPONSE_OK: u16 = 0x0001;
pub const CB_RESPONSE_FAIL: u16 = 0x0002;

// Virtual channel chunk flags
pub const CHANNEL_FLAG_FIRST: u32 = 0x00000001;
pub const CHANNEL_FLAG_LAST: u32 = 0x00000002;

// FileContentsRequest flags
pub const FILECONTENTS_SIZE: u32 = 0x00000001;
pub const FILECONTENTS_RANGE: u32 = 0x00000002;

// Well-known clipboard format IDs
pub const CF_UNICODETEXT: u32 = 13;

// ── Data structures ──────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct ClipFormat {
    pub id: u32,
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct FileDescriptor {
    pub name: String,
    pub size: u64,
    pub attributes: u32,
}

#[derive(Debug, Clone)]
pub struct FileInfo {
    pub id: String,
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct ChunkedFetch {
    pub stream_id: u32,
    pub list_index: u32,
    pub offset: u64,
    pub total_size: u64,
}

#[derive(Debug)]
pub struct ClipdrHeader {
    pub msg_type: u16,
    pub msg_flags: u16,
    pub data_len: u32,
}

/// State machine for a CLIPRDR file transfer session.
pub struct ClipSession {
    /// CLIPRDR virtual channel ID (discovered from MCS Connect)
    pub channel_id: Option<u16>,
    /// MCS user channel / initiator (typically 1003 = 0x03EB)
    pub initiator: u16,
    /// Format ID for FileGroupDescriptorW (dynamically assigned)
    pub file_descriptor_format_id: Option<u32>,
    /// Parsed file descriptors from the last CB_FORMAT_DATA_RESPONSE
    pub file_descriptors: Vec<FileDescriptor>,
    /// Channel names from CS_NET (to find cliprdr index)
    pub channel_names: Vec<String>,
    /// Virtual channel reassembly buffer (channel_id -> accumulated data)
    pub vc_reassembly: HashMap<u16, Vec<u8>>,
    /// Stream ID counter for FileContentsRequest
    pub next_stream_id: u32,
    /// Pending file content requests (stream_id -> (list_index, accumulated data))
    pub pending_contents: HashMap<u32, (u32, Vec<u8>)>,
    /// Completed file data ready for browser download (uuid -> (name, data))
    pub completed_files: HashMap<String, (String, Vec<u8>)>,
    /// Whether we're currently fetching file contents
    pub fetching: bool,
    /// Current fetch state for chunked downloads
    pub current_fetch: Option<ChunkedFetch>,
    /// Queue of file indices to fetch
    pub fetch_queue: Vec<u32>,
    /// Files uploaded from browser, pending paste into RDP
    pub upload_files: Vec<UploadedFile>,
    /// Whether we're in "upload mode" (gateway owns the clipboard)
    pub upload_active: bool,
    /// Format ID we announce for FileGroupDescriptorW when uploading
    pub upload_format_id: u32,
}

#[derive(Debug, Clone)]
pub struct UploadedFile {
    pub name: String,
    pub data: Vec<u8>,
}

impl ClipSession {
    pub fn new() -> Self {
        Self {
            channel_id: None,
            initiator: 0x03EB, // default MCS user channel
            file_descriptor_format_id: None,
            file_descriptors: Vec::new(),
            channel_names: Vec::new(),
            vc_reassembly: HashMap::new(),
            next_stream_id: 1,
            pending_contents: HashMap::new(),
            completed_files: HashMap::new(),
            fetching: false,
            fetch_queue: Vec::new(),
            current_fetch: None,
            upload_files: Vec::new(),
            upload_active: false,
            upload_format_id: 49290, // arbitrary high format ID for FileGroupDescriptorW
        }
    }
}

// ── TPKT Framer ──────────────────────────────────────────────────

/// Buffers a raw byte stream and yields complete TPKT frames.
pub struct TpktFramer {
    buf: Vec<u8>,
}

impl TpktFramer {
    pub fn new() -> Self {
        Self { buf: Vec::with_capacity(65536) }
    }

    /// Feed raw bytes into the framer.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Extract the next complete TPKT frame, if available.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        if self.buf.len() < 4 {
            return None;
        }
        // TPKT header: [0x03, 0x00, len_hi, len_lo]
        if self.buf[0] != 0x03 || self.buf[1] != 0x00 {
            // Not a TPKT — skip one byte and try again (recovery)
            self.buf.remove(0);
            return None;
        }
        let total_len = ((self.buf[2] as usize) << 8) | (self.buf[3] as usize);
        if total_len < 4 || self.buf.len() < total_len {
            return None; // Incomplete frame
        }
        let frame = self.buf[..total_len].to_vec();
        self.buf.drain(..total_len);
        Some(frame)
    }

    /// Extract all complete frames from the buffer.
    pub fn drain_frames(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame() {
            frames.push(frame);
        }
        frames
    }
}

// ── MCS Channel Discovery ────────────────────────────────────────

/// Parse CS_NET (Client Network Data, type 0xC003) from MCS Connect Initial
/// to extract requested channel names.
pub fn parse_cs_net_channel_names(mcs_data: &[u8]) -> Vec<String> {
    let mut names = Vec::new();
    // Scan for CS_NET type marker (0x03, 0xC0 in LE = 0xC003)
    for i in 0..mcs_data.len().saturating_sub(8) {
        if mcs_data[i] == 0x03 && mcs_data[i + 1] == 0xC0 {
            let block_len = u16::from_le_bytes([mcs_data[i + 2], mcs_data[i + 3]]) as usize;
            if block_len < 8 || i + block_len > mcs_data.len() {
                continue;
            }
            let block = &mcs_data[i + 4..i + block_len];
            if block.len() < 4 {
                continue;
            }
            let channel_count = u32::from_le_bytes([block[0], block[1], block[2], block[3]]) as usize;
            let mut offset = 4;
            for _ in 0..channel_count {
                if offset + 12 > block.len() {
                    break;
                }
                // Channel name: 8 bytes, null-padded ASCII
                let name_bytes = &block[offset..offset + 8];
                let name = name_bytes
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as char)
                    .collect::<String>();
                names.push(name);
                offset += 12; // 8 name + 4 options
            }
            break;
        }
    }
    names
}

/// Inject a "cliprdr" channel into CS_NET if not already present.
/// Modifies the MCS Connect Initial in-place, updating channel count,
/// CS_NET block length, and all outer length fields (TPKT, X.224, BER, PER).
/// Returns true if injection was performed.
pub fn inject_cliprdr_channel(data: &mut Vec<u8>) -> bool {
    // Find CS_NET block
    let cs_net_pos = match find_cs_net_position(data) {
        Some(pos) => pos,
        None => return false,
    };

    let block_len = u16::from_le_bytes([data[cs_net_pos + 2], data[cs_net_pos + 3]]) as usize;
    if block_len < 8 || cs_net_pos + block_len > data.len() {
        return false;
    }

    // Check if cliprdr already exists
    let channel_count = u32::from_le_bytes([
        data[cs_net_pos + 4], data[cs_net_pos + 5],
        data[cs_net_pos + 6], data[cs_net_pos + 7],
    ]) as usize;

    let mut offset = cs_net_pos + 8;
    for _ in 0..channel_count {
        if offset + 12 > data.len() { break; }
        let name: String = data[offset..offset + 8]
            .iter()
            .take_while(|&&b| b != 0)
            .map(|&b| b as char)
            .collect();
        if name.eq_ignore_ascii_case("cliprdr") {
            return false; // Already present
        }
        offset += 12;
    }

    // Build the new channel entry: 8 bytes name + 4 bytes options
    let mut entry = [0u8; 12];
    let name_bytes = b"cliprdr\0";
    entry[..8].copy_from_slice(name_bytes);
    // Channel options: CHANNEL_OPTION_INITIALIZED | CHANNEL_OPTION_ENCRYPT_RDP
    let options: u32 = 0x80000000 | 0x40000000;
    entry[8..12].copy_from_slice(&options.to_le_bytes());

    // Insert the entry at the end of CS_NET channels
    let insert_pos = cs_net_pos + block_len;
    data.splice(insert_pos..insert_pos, entry.iter().cloned());

    // Update channel count (+1)
    let new_count = (channel_count + 1) as u32;
    data[cs_net_pos + 4..cs_net_pos + 8].copy_from_slice(&new_count.to_le_bytes());

    // Update CS_NET block length (+12)
    let new_block_len = (block_len + 12) as u16;
    data[cs_net_pos + 2..cs_net_pos + 4].copy_from_slice(&new_block_len.to_le_bytes());

    // Update TPKT length (first 4 bytes: [0x03, 0x00, len_hi, len_lo])
    if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 {
        let old_tpkt_len = u16::from_be_bytes([data[2], data[3]]);
        let new_tpkt_len = old_tpkt_len + 12;
        data[2..4].copy_from_slice(&new_tpkt_len.to_be_bytes());
    }

    // Update BER/PER lengths in MCS Connect Initial
    // The MCS Connect Initial has nested length fields that need updating.
    // Rather than parsing the full ASN.1/PER structure, we update all
    // length fields between TPKT header and CS_NET by scanning for them.
    update_mcs_lengths(data, 12);

    true
}

/// Find the byte offset of CS_NET (type 0xC003) in the data.
fn find_cs_net_position(data: &[u8]) -> Option<usize> {
    for i in 0..data.len().saturating_sub(8) {
        if data[i] == 0x03 && data[i + 1] == 0xC0 {
            let block_len = u16::from_le_bytes([data[i + 2], data[i + 3]]) as usize;
            if block_len >= 8 && i + block_len <= data.len() {
                return Some(i);
            }
        }
    }
    None
}

/// Update MCS Connect Initial length fields after inserting `added` bytes
/// into the user data area. Updates right-to-left to avoid position shifts.
///
/// Structure: TPKT(4) + X.224(3) + [0x7F,0x65] + BER_len + ... + [0x04] + BER_len + GCC... + "Duca" + PER_len + blocks
fn update_mcs_lengths(data: &mut Vec<u8>, added: usize) {
    let x224_end = 7; // TPKT(4) + X.224(3)
    if data.len() < x224_end + 4 { return; }
    if data[x224_end] != 0x7F || data[x224_end + 1] != 0x65 { return; }

    // 1. Find all three length positions WITHOUT modifying data
    let mcs_len_pos = x224_end + 2;
    let mcs_len_size = ber_length_size(&data[mcs_len_pos..]);
    let mcs_len_val = read_ber_length(&data[mcs_len_pos..]);

    // Skip BER TLVs to find [0x04] userData tag
    let mut pos = mcs_len_pos + mcs_len_size;
    let mut ud_len_pos = 0usize;
    let mut ud_len_size = 0usize;
    for _ in 0..10 {
        if pos >= data.len() { return; }
        if data[pos] == 0x04 {
            ud_len_pos = pos + 1;
            ud_len_size = ber_length_size(&data[ud_len_pos..]);
            break;
        }
        pos += 1;
        if pos >= data.len() { return; }
        let ls = ber_length_size(&data[pos..]);
        let lv = read_ber_length(&data[pos..]);
        pos += ls + lv;
    }
    if ud_len_pos == 0 { return; }
    let ud_len_val = read_ber_length(&data[ud_len_pos..]);

    // Find "Duca" and the PER length after it
    let mut per_len_pos = 0usize;
    for j in (ud_len_pos + ud_len_size)..data.len().saturating_sub(6) {
        if data[j] == 0x44 && data[j+1] == 0x75 && data[j+2] == 0x63 && data[j+3] == 0x61 {
            per_len_pos = j + 4;
            break;
        }
    }
    if per_len_pos == 0 || per_len_pos >= data.len() { return; }

    // 2. Update right-to-left so positions don't shift

    // PER length (rightmost)
    let per_shift = write_per_length(data, per_len_pos, added);
    let shift1 = per_shift.max(0) as usize;

    // userData BER length (middle) — shifted by PER expansion
    let ud_shift = write_ber_length(data, ud_len_pos + shift1, ud_len_val + added);
    let shift2 = shift1 + ud_shift.max(0) as usize;

    // MCS Connect-Initial BER length (leftmost) — shifted by both
    write_ber_length(data, mcs_len_pos + shift2, mcs_len_val + added);
}

fn ber_length_size(data: &[u8]) -> usize {
    if data.is_empty() { return 1; }
    if data[0] & 0x80 == 0 { 1 }
    else { 1 + (data[0] & 0x7F) as usize }
}

fn read_ber_length(data: &[u8]) -> usize {
    if data.is_empty() { return 0; }
    if data[0] & 0x80 == 0 {
        data[0] as usize
    } else {
        let n = (data[0] & 0x7F) as usize;
        let mut val = 0usize;
        for i in 0..n.min(data.len() - 1) {
            val = (val << 8) | data[1 + i] as usize;
        }
        val
    }
}

/// Write a BER length at `pos`, replacing old encoding. Returns bytes added (0 or positive).
fn write_ber_length(data: &mut Vec<u8>, pos: usize, new_val: usize) -> isize {
    if pos >= data.len() { return 0; }
    let old_size = ber_length_size(&data[pos..]) as isize;
    let mut new_bytes = Vec::new();
    if new_val < 0x80 {
        new_bytes.push(new_val as u8);
    } else if new_val < 0x100 {
        new_bytes.push(0x81);
        new_bytes.push(new_val as u8);
    } else {
        new_bytes.push(0x82);
        new_bytes.push((new_val >> 8) as u8);
        new_bytes.push((new_val & 0xFF) as u8);
    }
    let new_size = new_bytes.len() as isize;
    data.splice(pos..pos + old_size as usize, new_bytes);
    new_size - old_size
}

/// Update a PER length at `pos` by adding `added`. Returns bytes inserted (0 or 1).
fn write_per_length(data: &mut Vec<u8>, pos: usize, added: usize) -> isize {
    if pos >= data.len() { return 0; }
    if data[pos] & 0x80 == 0 {
        let old = data[pos] as usize;
        let new_len = old + added;
        if new_len < 0x80 {
            data[pos] = new_len as u8;
            0
        } else {
            data[pos] = ((new_len >> 8) & 0x3F) as u8 | 0x80;
            data.insert(pos + 1, (new_len & 0xFF) as u8);
            1
        }
    } else {
        if pos + 1 >= data.len() { return 0; }
        let old = (((data[pos] & 0x3F) as usize) << 8) | data[pos + 1] as usize;
        let new_len = old + added;
        data[pos] = ((new_len >> 8) & 0x3F) as u8 | 0x80;
        data[pos + 1] = (new_len & 0xFF) as u8;
        0
    }
}

/// Inject an entire CS_NET block (with a single cliprdr channel) into an
/// MCS Connect Initial that has no CS_NET. Inserts after the last GCC user data block.
pub fn inject_cs_net_with_cliprdr(data: &mut Vec<u8>) -> bool {
    // Find "Duca" H.221 key to locate the GCC user data area
    let duca_pos = match find_duca_position(data) {
        Some(p) => p,
        None => return false,
    };

    // Find the PER length after "Duca"
    let per_pos = duca_pos + 4;
    if per_pos >= data.len() { return false; }

    let (ud_len, per_size) = read_per_length(&data[per_pos..]);
    let ud_start = per_pos + per_size;
    let ud_end = ud_start + ud_len;

    if ud_end > data.len() { return false; }

    // Build CS_NET block: type(2) + len(2) + channelCount(4) + 1 channel entry(12) = 20 bytes
    let cs_net_len: u16 = 20;
    let mut cs_net = Vec::with_capacity(20);
    cs_net.extend_from_slice(&0xC003u16.to_le_bytes()); // CS_NET type
    cs_net.extend_from_slice(&cs_net_len.to_le_bytes()); // block length
    cs_net.extend_from_slice(&1u32.to_le_bytes()); // channelCount = 1
    // Channel entry: "cliprdr\0" + options
    cs_net.extend_from_slice(b"cliprdr\0");
    let options: u32 = 0x80000000 | 0x40000000; // INITIALIZED | ENCRYPT_RDP
    cs_net.extend_from_slice(&options.to_le_bytes());

    let added = cs_net.len(); // 20 bytes

    // Insert CS_NET at the end of user data blocks
    data.splice(ud_end..ud_end, cs_net);

    // Update TPKT length
    if data.len() >= 4 && data[0] == 0x03 && data[1] == 0x00 {
        let old_tpkt = u16::from_be_bytes([data[2], data[3]]);
        let new_tpkt = old_tpkt + added as u16;
        data[2..4].copy_from_slice(&new_tpkt.to_be_bytes());
    }

    // Update all MCS/GCC length fields
    update_mcs_lengths(data, added);

    true
}

fn find_duca_position(data: &[u8]) -> Option<usize> {
    for i in 7..data.len().saturating_sub(6) {
        if data[i] == 0x44 && data[i + 1] == 0x75 && data[i + 2] == 0x63 && data[i + 3] == 0x61 {
            return Some(i);
        }
    }
    None
}

fn read_per_length(data: &[u8]) -> (usize, usize) {
    if data.is_empty() { return (0, 1); }
    if data[0] & 0x80 == 0 {
        (data[0] as usize, 1)
    } else if data.len() >= 2 {
        let len = (((data[0] & 0x3F) as usize) << 8) | data[1] as usize;
        (len, 2)
    } else {
        (0, 1)
    }
}

/// Parse SC_NET (Server Network Data, type 0x0C03) from MCS Connect Response
/// to extract assigned channel IDs.
pub fn parse_sc_net_channel_ids(mcs_data: &[u8]) -> Vec<u16> {
    let mut ids = Vec::new();
    // Scan for SC_NET type marker (0x03, 0x0C in LE = 0x0C03)
    for i in 0..mcs_data.len().saturating_sub(8) {
        if mcs_data[i] == 0x03 && mcs_data[i + 1] == 0x0C {
            let block_len = u16::from_le_bytes([mcs_data[i + 2], mcs_data[i + 3]]) as usize;
            if block_len < 8 || i + block_len > mcs_data.len() {
                continue;
            }
            let block = &mcs_data[i + 4..i + block_len];
            if block.len() < 4 {
                continue;
            }
            let _mcs_channel_id = u16::from_le_bytes([block[0], block[1]]);
            let channel_count = u16::from_le_bytes([block[2], block[3]]) as usize;
            let mut offset = 4;
            for _ in 0..channel_count {
                if offset + 2 > block.len() {
                    break;
                }
                let id = u16::from_le_bytes([block[offset], block[offset + 1]]);
                ids.push(id);
                offset += 2;
            }
            break;
        }
    }
    ids
}

/// Given channel names (from CS_NET) and channel IDs (from SC_NET),
/// find the CLIPRDR channel ID.
pub fn find_cliprdr_channel_id(names: &[String], ids: &[u16]) -> Option<u16> {
    for (idx, name) in names.iter().enumerate() {
        if name.eq_ignore_ascii_case("cliprdr") {
            return ids.get(idx).copied();
        }
    }
    None
}

// ── MCS PDU Parsing ──────────────────────────────────────────────

/// Parse a TPKT frame to extract the MCS channel ID and the virtual channel payload.
/// Returns (channel_id, vc_header_total_len, vc_flags, cliprdr_payload).
/// Returns None if the frame is not an MCS Send Data Indication/Request.
pub fn parse_mcs_send_data(frame: &[u8]) -> Option<(u16, u32, u32, Vec<u8>)> {
    // TPKT(4) + X.224 Data(3) + MCS...
    if frame.len() < 8 {
        return None;
    }
    // X.224 Data header should be: length=2, code=0xF0, EOT=0x80
    let x224_start = 4;
    if frame.len() <= x224_start + 2 {
        return None;
    }

    let mcs_start = x224_start + 3; // skip X.224 data header (3 bytes)
    if mcs_start >= frame.len() {
        return None;
    }

    let mcs_type = frame[mcs_start] >> 2; // top 6 bits
    // Send Data Indication = 26 (0x1A), Send Data Request = 25 (0x19)
    if mcs_type != 26 && mcs_type != 25 {
        return None;
    }

    // Parse BER-encoded fields after the type byte
    let mut pos = mcs_start + 1;

    // Initiator (user ID): 2 bytes big-endian
    if pos + 2 > frame.len() { return None; }
    pos += 2; // skip initiator

    // Channel ID: 2 bytes big-endian
    if pos + 2 > frame.len() { return None; }
    let channel_id = ((frame[pos] as u16) << 8) | (frame[pos + 1] as u16);
    pos += 2;

    // Data priority + segmentation: 1 byte
    if pos >= frame.len() { return None; }
    pos += 1;

    // User data length (BER): variable
    if pos >= frame.len() { return None; }
    let (user_data_len, consumed) = parse_ber_length(&frame[pos..])?;
    pos += consumed;

    if pos + user_data_len > frame.len() {
        return None;
    }
    let user_data = &frame[pos..pos + user_data_len];

    // Virtual Channel PDU header: totalLength(u32LE) + flags(u32LE)
    if user_data.len() < 8 {
        return None;
    }
    let vc_total_len = u32::from_le_bytes([user_data[0], user_data[1], user_data[2], user_data[3]]);
    let vc_flags = u32::from_le_bytes([user_data[4], user_data[5], user_data[6], user_data[7]]);
    let vc_payload = user_data[8..].to_vec();

    Some((channel_id, vc_total_len, vc_flags, vc_payload))
}

/// Parse BER length encoding. Returns (length, bytes_consumed).
fn parse_ber_length(data: &[u8]) -> Option<(usize, usize)> {
    if data.is_empty() {
        return None;
    }
    if data[0] & 0x80 == 0 {
        // Short form
        Some((data[0] as usize, 1))
    } else {
        let num_bytes = (data[0] & 0x7F) as usize;
        if num_bytes == 0 || num_bytes > 3 || data.len() < 1 + num_bytes {
            return None;
        }
        let mut len: usize = 0;
        for i in 0..num_bytes {
            len = (len << 8) | (data[1 + i] as usize);
        }
        Some((len, 1 + num_bytes))
    }
}

// ── Virtual Channel Reassembly ───────────────────────────────────

/// Process a virtual channel chunk and return the complete PDU if reassembly is done.
pub fn reassemble_vc_chunk(
    session: &mut ClipSession,
    channel_id: u16,
    _vc_total_len: u32,
    vc_flags: u32,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let is_first = (vc_flags & CHANNEL_FLAG_FIRST) != 0;
    let is_last = (vc_flags & CHANNEL_FLAG_LAST) != 0;

    if is_first && is_last {
        // Single chunk — complete PDU
        return Some(payload.to_vec());
    }

    if is_first {
        session.vc_reassembly.insert(channel_id, payload.to_vec());
        return None;
    }

    if let Some(buf) = session.vc_reassembly.get_mut(&channel_id) {
        buf.extend_from_slice(payload);
        if is_last {
            return session.vc_reassembly.remove(&channel_id);
        }
    }

    None
}

// ── CLIPRDR PDU Parsing ──────────────────────────────────────────

pub fn parse_cliprdr_header(data: &[u8]) -> Option<ClipdrHeader> {
    if data.len() < 8 {
        return None;
    }
    Some(ClipdrHeader {
        msg_type: u16::from_le_bytes([data[0], data[1]]),
        msg_flags: u16::from_le_bytes([data[2], data[3]]),
        data_len: u32::from_le_bytes([data[4], data[5], data[6], data[7]]),
    })
}

/// Parse CB_FORMAT_LIST (Long Format) to extract format names.
/// Returns list of (formatId, formatName) pairs.
pub fn parse_format_list(data: &[u8]) -> Vec<ClipFormat> {
    let header = match parse_cliprdr_header(data) {
        Some(h) if h.msg_type == CB_FORMAT_LIST => h,
        _ => return Vec::new(),
    };

    let payload = &data[8..];
    let end = (header.data_len as usize).min(payload.len());
    let mut formats = Vec::new();
    let mut pos = 0;

    while pos + 4 < end {
        let format_id = u32::from_le_bytes([payload[pos], payload[pos + 1], payload[pos + 2], payload[pos + 3]]);
        pos += 4;

        // Format name: null-terminated UTF-16LE
        let mut name_chars: Vec<u16> = Vec::new();
        while pos + 1 < end {
            let c = u16::from_le_bytes([payload[pos], payload[pos + 1]]);
            pos += 2;
            if c == 0 {
                break;
            }
            name_chars.push(c);
        }
        let name = String::from_utf16_lossy(&name_chars);
        formats.push(ClipFormat { id: format_id, name });
    }

    formats
}

/// Parse FileGroupDescriptorW from CB_FORMAT_DATA_RESPONSE payload.
/// The payload starts after the 8-byte CLIPRDR header.
pub fn parse_file_group_descriptor(data: &[u8]) -> Vec<FileDescriptor> {
    // data is the raw CLIPRDR payload (after header)
    if data.len() < 4 {
        return Vec::new();
    }

    let count = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let mut descriptors = Vec::new();
    let mut pos = 4;

    // Each FILEDESCRIPTORW is 592 bytes
    const FD_SIZE: usize = 592;
    for _ in 0..count {
        if pos + FD_SIZE > data.len() {
            break;
        }
        let fd = &data[pos..pos + FD_SIZE];

        let flags = u32::from_le_bytes([fd[0], fd[1], fd[2], fd[3]]);
        let attributes = u32::from_le_bytes([fd[4], fd[5], fd[6], fd[7]]);

        // File size: nFileSizeHigh(u32LE at offset 32) + nFileSizeLow(u32LE at offset 36)
        // But in FILEDESCRIPTORW, the layout is:
        //   flags(4) + reserved1(32) + dwFileAttributes(4) + reserved2(16)
        //   + ftCreationTime(8) + ftLastAccessTime(8) + ftLastWriteTime(8)
        //   + nFileSizeHigh(4) + nFileSizeLow(4) + fileName(520)
        // Total offsets:
        //   0: dwFlags(4)
        //   4: clsid(16)
        //   20: sizel(8)
        //   28: pointl(8)
        //   36: dwFileAttributes(4)
        //   40: ftCreationTime(8)
        //   48: ftLastAccessTime(8)
        //   56: ftLastWriteTime(8)
        //   64: nFileSizeHigh(4)
        //   68: nFileSizeLow(4)
        //   72: fileName(520 = 260 * 2 for UTF-16LE)
        let _ = flags;
        let attrs = u32::from_le_bytes([fd[36], fd[37], fd[38], fd[39]]);
        let size_high = u32::from_le_bytes([fd[64], fd[65], fd[66], fd[67]]) as u64;
        let size_low = u32::from_le_bytes([fd[68], fd[69], fd[70], fd[71]]) as u64;
        let size = (size_high << 32) | size_low;

        // File name: UTF-16LE at offset 72, 520 bytes (260 chars max)
        let name_bytes = &fd[72..72 + 520];
        let name_chars: Vec<u16> = name_bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&c| c != 0)
            .collect();
        let name = String::from_utf16_lossy(&name_chars);

        descriptors.push(FileDescriptor {
            name,
            size,
            attributes: attrs,
        });
        pos += FD_SIZE;
    }

    descriptors
}

// ── CLIPRDR PDU Construction ─────────────────────────────────────

/// Build a CB_FORMAT_DATA_REQUEST PDU.
pub fn build_format_data_request(format_id: u32) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(12);
    pdu.extend_from_slice(&CB_FORMAT_DATA_REQUEST.to_le_bytes()); // msgType
    pdu.extend_from_slice(&0u16.to_le_bytes()); // msgFlags
    pdu.extend_from_slice(&4u32.to_le_bytes()); // dataLen
    pdu.extend_from_slice(&format_id.to_le_bytes()); // requestedFormatId
    pdu
}

/// Build a CB_FORMAT_LIST_RESPONSE PDU (success).
pub fn build_format_list_response() -> Vec<u8> {
    let mut pdu = Vec::with_capacity(8);
    pdu.extend_from_slice(&CB_FORMAT_LIST_RESPONSE.to_le_bytes());
    pdu.extend_from_slice(&CB_RESPONSE_OK.to_le_bytes());
    pdu.extend_from_slice(&0u32.to_le_bytes()); // dataLen = 0
    pdu
}

/// Build a CB_FILECONTENTS_REQUEST PDU.
pub fn build_file_contents_request(
    stream_id: u32,
    list_index: u32,
    flags: u32,
    position: u64,
    cb_requested: u32,
) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(36);
    pdu.extend_from_slice(&CB_FILECONTENTS_REQUEST.to_le_bytes()); // msgType
    pdu.extend_from_slice(&0u16.to_le_bytes()); // msgFlags
    pdu.extend_from_slice(&28u32.to_le_bytes()); // dataLen
    pdu.extend_from_slice(&stream_id.to_le_bytes());
    pdu.extend_from_slice(&list_index.to_le_bytes());
    pdu.extend_from_slice(&flags.to_le_bytes());
    pdu.extend_from_slice(&(position as u32).to_le_bytes()); // nPositionLow
    pdu.extend_from_slice(&((position >> 32) as u32).to_le_bytes()); // nPositionHigh
    pdu.extend_from_slice(&cb_requested.to_le_bytes());
    // No clipDataId for simplicity
    pdu
}

/// Wrap a CLIPRDR PDU in MCS Send Data Request + X.224 + TPKT framing.
pub fn wrap_cliprdr_pdu(cliprdr_pdu: &[u8], channel_id: u16, initiator: u16) -> Vec<u8> {
    // Virtual channel PDU header: totalLength(u32LE) + flags(u32LE)
    let vc_flags: u32 = CHANNEL_FLAG_FIRST | CHANNEL_FLAG_LAST;
    let vc_total_len = cliprdr_pdu.len() as u32;

    let mut vc_data = Vec::with_capacity(8 + cliprdr_pdu.len());
    vc_data.extend_from_slice(&vc_total_len.to_le_bytes());
    vc_data.extend_from_slice(&vc_flags.to_le_bytes());
    vc_data.extend_from_slice(cliprdr_pdu);

    // MCS Send Data Request
    let user_data_len = vc_data.len();
    let mut mcs = Vec::with_capacity(6 + user_data_len + 3);
    mcs.push(0x64); // MCS Send Data Request (type 25 << 2 = 0x64)
    // Initiator: 2 bytes big-endian
    mcs.push((initiator >> 8) as u8);
    mcs.push((initiator & 0xFF) as u8);
    // Channel ID: 2 bytes big-endian
    mcs.push((channel_id >> 8) as u8);
    mcs.push((channel_id & 0xFF) as u8);
    // Data priority (high) + segmentation (begin+end): 0x70
    mcs.push(0x70);
    // User data length (BER)
    encode_ber_length(&mut mcs, user_data_len);
    mcs.extend_from_slice(&vc_data);

    // X.224 Data header
    let x224: [u8; 3] = [0x02, 0xF0, 0x80];

    // TPKT
    let total = 4 + x224.len() + mcs.len();
    let mut frame = Vec::with_capacity(total);
    frame.push(0x03);
    frame.push(0x00);
    frame.push((total >> 8) as u8);
    frame.push((total & 0xFF) as u8);
    frame.extend_from_slice(&x224);
    frame.extend_from_slice(&mcs);

    frame
}

fn encode_ber_length(buf: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push((len & 0xFF) as u8);
    }
}

// ── Parse CB_FILECONTENTS_RESPONSE ───────────────────────────────

/// Parse CB_FILECONTENTS_RESPONSE. Returns (stream_id, data).
pub fn parse_file_contents_response(cliprdr_data: &[u8]) -> Option<(u32, Vec<u8>)> {
    let header = parse_cliprdr_header(cliprdr_data)?;
    if header.msg_type != CB_FILECONTENTS_RESPONSE || header.msg_flags != CB_RESPONSE_OK {
        return None;
    }
    let payload = &cliprdr_data[8..];
    if payload.len() < 4 {
        return None;
    }
    let stream_id = u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let data = payload[4..].to_vec();
    Some((stream_id, data))
}

// ── Upload direction (browser → RDP) PDU builders ────────────────

/// Build a CB_FORMAT_LIST announcing CF_UNICODETEXT (so the server knows we accept text).
pub fn build_format_list_with_text() -> Vec<u8> {
    // Short format: formatId(u32LE) + empty name (just null terminator in UTF-16LE)
    let entry_len = 4 + 2; // formatId + null terminator (UTF-16LE)
    let mut pdu = Vec::with_capacity(8 + entry_len);
    pdu.extend_from_slice(&CB_FORMAT_LIST.to_le_bytes()); // msgType
    pdu.extend_from_slice(&0u16.to_le_bytes()); // msgFlags
    pdu.extend_from_slice(&(entry_len as u32).to_le_bytes()); // dataLen
    pdu.extend_from_slice(&CF_UNICODETEXT.to_le_bytes()); // formatId
    pdu.extend_from_slice(&0u16.to_le_bytes()); // null terminator
    pdu
}

/// Build a CB_FORMAT_LIST announcing FileGroupDescriptorW (Long Format).
pub fn build_format_list_with_files(format_id: u32) -> Vec<u8> {
    let name = "FileGroupDescriptorW";
    // UTF-16LE encode the name + null terminator
    let name_utf16: Vec<u8> = name.encode_utf16()
        .chain(std::iter::once(0u16))
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let entry_len = 4 + name_utf16.len(); // formatId(4) + name(UTF-16LE null-terminated)
    let mut pdu = Vec::with_capacity(8 + entry_len);
    pdu.extend_from_slice(&CB_FORMAT_LIST.to_le_bytes()); // msgType
    pdu.extend_from_slice(&0u16.to_le_bytes()); // msgFlags
    pdu.extend_from_slice(&(entry_len as u32).to_le_bytes()); // dataLen
    pdu.extend_from_slice(&format_id.to_le_bytes());
    pdu.extend_from_slice(&name_utf16);
    pdu
}

/// Build a CB_FORMAT_DATA_RESPONSE containing a FileGroupDescriptorW.
pub fn build_file_group_descriptor_response(files: &[UploadedFile]) -> Vec<u8> {
    const FD_SIZE: usize = 592;
    let count = files.len();
    let payload_len = 4 + count * FD_SIZE;

    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(&(count as u32).to_le_bytes());

    for file in files {
        let mut fd = vec![0u8; FD_SIZE];

        // dwFlags: FD_FILESIZE (0x40) | FD_ATTRIBUTES (0x04)
        let flags: u32 = 0x40 | 0x04;
        fd[0..4].copy_from_slice(&flags.to_le_bytes());

        // dwFileAttributes at offset 36: FILE_ATTRIBUTE_NORMAL = 0x80
        fd[36..40].copy_from_slice(&0x80u32.to_le_bytes());

        // nFileSizeHigh at offset 64, nFileSizeLow at offset 68
        let size = file.data.len() as u64;
        fd[64..68].copy_from_slice(&((size >> 32) as u32).to_le_bytes());
        fd[68..72].copy_from_slice(&((size & 0xFFFFFFFF) as u32).to_le_bytes());

        // fileName at offset 72: UTF-16LE, max 260 chars
        let name_chars: Vec<u16> = file.name.encode_utf16().take(259).collect();
        for (i, ch) in name_chars.iter().enumerate() {
            let off = 72 + i * 2;
            if off + 2 <= FD_SIZE {
                fd[off..off + 2].copy_from_slice(&ch.to_le_bytes());
            }
        }

        payload.extend_from_slice(&fd);
    }

    // Wrap in CLIPRDR header
    let mut pdu = Vec::with_capacity(8 + payload.len());
    pdu.extend_from_slice(&CB_FORMAT_DATA_RESPONSE.to_le_bytes());
    pdu.extend_from_slice(&CB_RESPONSE_OK.to_le_bytes());
    pdu.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    pdu.extend_from_slice(&payload);
    pdu
}

/// Build a CB_FILECONTENTS_RESPONSE with file size.
pub fn build_file_contents_size_response(stream_id: u32, size: u64) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(20);
    pdu.extend_from_slice(&CB_FILECONTENTS_RESPONSE.to_le_bytes());
    pdu.extend_from_slice(&CB_RESPONSE_OK.to_le_bytes());
    pdu.extend_from_slice(&12u32.to_le_bytes()); // dataLen: streamId(4) + size(8)
    pdu.extend_from_slice(&stream_id.to_le_bytes());
    pdu.extend_from_slice(&(size as u32).to_le_bytes()); // low
    pdu.extend_from_slice(&((size >> 32) as u32).to_le_bytes()); // high
    pdu
}

/// Build a CB_FILECONTENTS_RESPONSE with file data chunk.
pub fn build_file_contents_range_response(stream_id: u32, data: &[u8]) -> Vec<u8> {
    let data_len = 4 + data.len();
    let mut pdu = Vec::with_capacity(8 + data_len);
    pdu.extend_from_slice(&CB_FILECONTENTS_RESPONSE.to_le_bytes());
    pdu.extend_from_slice(&CB_RESPONSE_OK.to_le_bytes());
    pdu.extend_from_slice(&(data_len as u32).to_le_bytes());
    pdu.extend_from_slice(&stream_id.to_le_bytes());
    pdu.extend_from_slice(data);
    pdu
}

/// Parse CB_FORMAT_DATA_REQUEST. Returns the requested format ID.
pub fn parse_format_data_request(data: &[u8]) -> Option<u32> {
    let header = parse_cliprdr_header(data)?;
    if header.msg_type != CB_FORMAT_DATA_REQUEST {
        return None;
    }
    let payload = &data[8..];
    if payload.len() < 4 {
        return None;
    }
    Some(u32::from_le_bytes([payload[0], payload[1], payload[2], payload[3]]))
}

/// Parse CB_FILECONTENTS_REQUEST. Returns (stream_id, list_index, flags, offset, cb_requested).
pub fn parse_file_contents_request(data: &[u8]) -> Option<(u32, u32, u32, u64, u32)> {
    let header = parse_cliprdr_header(data)?;
    if header.msg_type != CB_FILECONTENTS_REQUEST {
        return None;
    }
    let p = &data[8..];
    if p.len() < 24 {
        return None;
    }
    let stream_id = u32::from_le_bytes([p[0], p[1], p[2], p[3]]);
    let list_index = u32::from_le_bytes([p[4], p[5], p[6], p[7]]);
    let flags = u32::from_le_bytes([p[8], p[9], p[10], p[11]]);
    let pos_low = u32::from_le_bytes([p[12], p[13], p[14], p[15]]) as u64;
    let pos_high = u32::from_le_bytes([p[16], p[17], p[18], p[19]]) as u64;
    let cb_requested = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
    Some((stream_id, list_index, flags, (pos_high << 32) | pos_low, cb_requested))
}
