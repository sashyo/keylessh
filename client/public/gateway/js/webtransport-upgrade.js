/**
 * WebTransport upgrade disabled — using WebRTC DataChannels for all browser connections.
 * QUIC/WebTransport is reserved for the native VPN client only.
 */
(function () {
  "use strict";
  window.__quicActive = false;
  window.__quicFailed = true;
  console.log("[QUIC] WebTransport disabled — using WebRTC for HTTP/RDP/SSH");
})();
