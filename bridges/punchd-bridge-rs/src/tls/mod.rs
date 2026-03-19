// Self-signed TLS certificate generation using rcgen.

use std::net::{IpAddr, Ipv4Addr};

use rcgen::{CertificateParams, KeyPair, SanType};

pub struct TlsCert {
    pub key_pem: String,
    pub cert_pem: String,
}

pub fn generate_self_signed(hostname: &str) -> TlsCert {
    let mut params = CertificateParams::new(vec![hostname.to_string(), "localhost".to_string()])
        .expect("failed to create cert params");
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let key_pair = KeyPair::generate().expect("failed to generate key pair");
    let cert = params
        .self_signed(&key_pair)
        .expect("failed to create self-signed cert");

    TlsCert {
        key_pem: key_pair.serialize_pem(),
        cert_pem: cert.pem(),
    }
}
