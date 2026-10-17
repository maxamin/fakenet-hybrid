//! TLS termination: a per-run certificate authority that mints a certificate for whatever
//! hostname each client asks for (SNI). Install the CA (written to the output directory) in
//! the analysis VM, and clients see valid certificates.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::{anyhow, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use time::{Duration, OffsetDateTime};

pub const DEFAULT_HOSTNAME: &str = "fakenet.local";

pub struct TlsAuthority {
    issuer: Issuer<'static, KeyPair>,
    ca_der: CertificateDer<'static>,
    ca_pem: String,
    cache: Mutex<HashMap<String, Arc<CertifiedKey>>>,
}

impl std::fmt::Debug for TlsAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TlsAuthority")
    }
}

impl TlsAuthority {
    pub fn generate() -> Result<TlsAuthority> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "FakeNet Hybrid CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign, KeyUsagePurpose::DigitalSignature];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(1);
        params.not_after = now + Duration::days(365);
        let key = KeyPair::generate()?;
        let cert = params.self_signed(&key)?;
        Ok(TlsAuthority {
            ca_der: cert.der().clone(),
            ca_pem: cert.pem(),
            issuer: Issuer::new(params, key),
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn ca_pem(&self) -> &str {
        &self.ca_pem
    }

    pub fn ca_der(&self) -> &CertificateDer<'static> {
        &self.ca_der
    }

    pub fn certificate_for(&self, hostname: &str) -> Result<Arc<CertifiedKey>> {
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = cache.get(&hostname) {
            return Ok(existing.clone());
        }
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname.clone());
        params.subject_alt_names = vec![match hostname.parse::<std::net::IpAddr>() {
            Ok(ip) => SanType::IpAddress(ip),
            Err(_) => SanType::DnsName(hostname.clone().try_into().map_err(|e| anyhow!("invalid hostname {hostname}: {e:?}"))?),
        }];
        // Strict verifiers (e.g. Python 3.13+) require the authority key identifier
        params.use_authority_key_identifier_extension = true;
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature, KeyUsagePurpose::KeyEncipherment];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Like a real site's certificate: issued weeks or months ago (a certificate minted
        // a minute ago is a sandbox tell), a common lifetime, a random serial
        let random = random_bytes::<16>();
        let issued_days_ago = 30 + i64::from(u16::from_le_bytes([random[0], random[1]]) % 170);
        let lifetime_days = [90, 365, 397][usize::from(random[2]) % 3];
        let now = OffsetDateTime::now_utc();
        params.not_before = now - Duration::days(issued_days_ago) - Duration::seconds(i64::from(random[3]) * 337);
        params.not_after = params.not_before + Duration::days(lifetime_days).max(Duration::days(issued_days_ago + 30));
        let mut serial = random.to_vec();
        serial[0] &= 0x7f; // A positive integer
        params.serial_number = Some(rcgen::SerialNumber::from_slice(&serial));
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.issuer)?;
        let private_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der()));
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key).map_err(|e| anyhow!("{e}"))?;
        let certified = Arc::new(CertifiedKey::new(vec![cert.der().clone(), self.ca_der.clone()], signing_key));
        cache.insert(hostname, certified.clone());
        Ok(certified)
    }

    /// A config presenting the certificate for `name` (a hostname or IP), whatever the SNI
    pub fn config_for(&self, name: &str, alpn: Vec<Vec<u8>>) -> anyhow::Result<Arc<rustls::ServerConfig>> {
        let certified = self.certificate_for(name).or_else(|_| self.certificate_for(DEFAULT_HOSTNAME))?;
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Fixed(certified)));
        config.alpn_protocols = alpn;
        Ok(Arc::new(config))
    }

    pub fn server_config(self: &Arc<Self>, alpn: &[&[u8]]) -> Arc<rustls::ServerConfig> {
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(Resolver(self.clone())));
        config.alpn_protocols = alpn.iter().map(|p| p.to_vec()).collect();
        Arc::new(config)
    }
}

fn random_bytes<const N: usize>() -> [u8; N] {
    use rustls::crypto::ring::default_provider;
    let mut out = [0u8; N];
    if default_provider().secure_random.fill(&mut out).is_err() {
        // Not security-relevant (serials & dates): fall back to the clock
        let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = (nanos >> ((i % 16) * 8)) as u8;
        }
    }
    out
}

#[derive(Debug)]
struct Fixed(Arc<CertifiedKey>);

impl ResolvesServerCert for Fixed {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.clone())
    }
}

#[derive(Debug)]
struct Resolver(Arc<TlsAuthority>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let hostname = hello.server_name().unwrap_or(DEFAULT_HOSTNAME);
        self.0.certificate_for(hostname).or_else(|_| self.0.certificate_for(DEFAULT_HOSTNAME)).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mints_cached_certificates_per_hostname() {
        let ca = TlsAuthority::generate().unwrap();
        let a = ca.certificate_for("c2.example").unwrap();
        assert!(Arc::ptr_eq(&a, &ca.certificate_for("C2.example.").unwrap()));
        assert_eq!(a.cert.len(), 2);
        assert!(ca.certificate_for("10.0.0.1").is_ok());
        assert!(ca.ca_pem().starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn leaf_certificates_look_long_established() {
        let ca = TlsAuthority::generate().unwrap();
        let der = ca.certificate_for("example.com").unwrap().cert[0].clone();
        let (_, cert) = x509_parser::parse_x509_certificate(der.as_ref()).unwrap();
        let validity = cert.validity();
        let now = time::OffsetDateTime::now_utc().unix_timestamp();
        let age_days = (now - validity.not_before.timestamp()) / 86400;
        assert!((30..=200).contains(&age_days), "issued {age_days} days ago");
        assert!(validity.not_after.timestamp() > now + 86400 * 20);
        assert!(cert.raw_serial().len() >= 15);
    }
}
