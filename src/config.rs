use std::{
    fs,
    net::{IpAddr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use hickory_proto::rr::Name;
use serde::Deserialize;
use url::Url;
use zeroize::Zeroizing;

use crate::{names::canonical_name, protocol::Secret};

pub struct Config {
    pub listen: Vec<SocketAddr>,
    pub upstreams: Vec<Upstream>,
    pub discovery: Vec<Discovery>,
    pub hex_zones: Vec<Name>,
    pub ttl: u32,
    pub valid_for: Duration,
    pub upstream_timeout: Duration,
    pub request_timeout: Duration,
    pub cache_capacity: usize,
    pub max_inflight: usize,
}

#[derive(Clone)]
pub struct Discovery {
    pub domain: Name,
    pub key: Arc<Secret>,
}

#[derive(Clone, Debug)]
pub enum Upstream {
    Plain(SocketAddr),
    Doh { url: Url, bootstrap: Vec<IpAddr> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default = "default_listen")]
    listen: Vec<SocketAddr>,
    #[serde(default)]
    upstreams: Vec<RawUpstream>,
    #[serde(default)]
    discovery: Vec<RawDiscovery>,
    #[serde(default)]
    hex_zones: Vec<String>,
    #[serde(default = "default_ttl")]
    ttl: u32,
    #[serde(default = "default_validity")]
    valid_for: String,
    #[serde(default = "default_upstream_timeout")]
    upstream_timeout: String,
    #[serde(default = "default_request_timeout")]
    request_timeout: String,
    #[serde(default = "default_capacity")]
    cache_capacity: usize,
    #[serde(default = "default_inflight")]
    max_inflight: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, tag = "type", rename_all = "lowercase")]
enum RawUpstream {
    Plain { address: SocketAddr },
    Doh { url: String, bootstrap: Vec<IpAddr> },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDiscovery {
    domain: String,
    key: String,
}

fn default_listen() -> Vec<SocketAddr> {
    vec!["0.0.0.0:5300".parse().expect("literal address")]
}
fn default_ttl() -> u32 {
    60
}
fn default_validity() -> String {
    "24h".into()
}
fn default_upstream_timeout() -> String {
    "3s".into()
}
fn default_request_timeout() -> String {
    "10s".into()
}
fn default_capacity() -> usize {
    1024
}
fn default_inflight() -> usize {
    256
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            Zeroizing::new(fs::read_to_string(path).context("cannot read configuration file")?);
        Self::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Self> {
        // TOML's Display includes source lines, which can contain discovery keys.
        let raw: RawConfig = toml::from_str(text).map_err(|_| {
            anyhow::anyhow!("invalid TOML configuration; check field names and types")
        })?;
        ensure!(!raw.listen.is_empty(), "configure at least one listener");
        ensure!(
            raw.listen.iter().all(|addr| addr.port() != 0),
            "listener port must be nonzero"
        );
        ensure!(raw.ttl > 0, "ttl must be positive");
        ensure!(
            raw.cache_capacity > 0 && raw.cache_capacity <= 65_536,
            "cache_capacity must be 1-65536"
        );
        ensure!(
            raw.max_inflight > 0 && raw.max_inflight <= 65_536,
            "max_inflight must be 1-65536"
        );
        let mut discovery: Vec<Discovery> = Vec::new();
        for item in raw.discovery {
            let key = Zeroizing::new(item.key);
            let domain = canonical_name(&item.domain).context("invalid discovery domain")?;
            ensure!(
                !discovery.iter().any(|d| d.domain == domain),
                "duplicate discovery domain"
            );
            discovery.push(Discovery {
                domain,
                key: Arc::new(Secret::decode(&key)?),
            });
        }
        discovery.sort_by_key(|d| std::cmp::Reverse(d.domain.num_labels()));
        let mut hex_zones: Vec<Name> = Vec::new();
        for item in raw.hex_zones {
            let domain = canonical_name(&item).context("invalid hex zone")?;
            ensure!(
                !hex_zones
                    .iter()
                    .any(|d| d.zone_of(&domain) || domain.zone_of(d)),
                "hex zones must not overlap"
            );
            ensure!(
                !discovery
                    .iter()
                    .any(|d| d.domain.zone_of(&domain) || domain.zone_of(&d.domain)),
                "hex and discovery domains must not overlap"
            );
            hex_zones.push(domain);
        }
        let mut upstreams = Vec::new();
        for item in raw.upstreams {
            upstreams.push(match item {
                RawUpstream::Plain { address } => {
                    ensure!(
                        address.port() != 0 && !address.ip().is_unspecified(),
                        "upstream requires a concrete address and port"
                    );
                    ensure!(
                        !raw.listen
                            .iter()
                            .any(|listen| listen.port() == address.port()
                                && (listen.ip() == address.ip()
                                    || (listen.ip().is_unspecified()
                                        && address.ip().is_loopback()))),
                        "upstream points to our listener"
                    );
                    Upstream::Plain(address)
                }
                RawUpstream::Doh { url, bootstrap } => {
                    let url = Url::parse(&url).context("invalid DoH URL")?;
                    ensure!(
                        url.scheme() == "https"
                            && url.host_str().is_some()
                            && url.username().is_empty()
                            && url.password().is_none()
                            && url.fragment().is_none(),
                        "DoH URL must be HTTPS without credentials or fragment"
                    );
                    ensure!(
                        !bootstrap.is_empty() && bootstrap.iter().all(|ip| !ip.is_unspecified()),
                        "DoH requires explicit bootstrap IP addresses"
                    );
                    Upstream::Doh { url, bootstrap }
                }
            });
        }
        Ok(Self {
            listen: raw.listen,
            upstreams,
            discovery,
            hex_zones,
            ttl: raw.ttl,
            valid_for: duration(&raw.valid_for, "valid_for")?,
            upstream_timeout: duration(&raw.upstream_timeout, "upstream_timeout")?,
            request_timeout: duration(&raw.request_timeout, "request_timeout")?,
            cache_capacity: raw.cache_capacity,
            max_inflight: raw.max_inflight,
        })
    }

    pub fn discovery_for(&self, name: &Name) -> Option<&Discovery> {
        self.discovery.iter().find(|d| d.domain.zone_of(name))
    }
}

fn duration(value: &str, name: &str) -> Result<Duration> {
    let result =
        humantime::parse_duration(value).with_context(|| format!("invalid {name} duration"))?;
    ensure!(result.as_secs() > 0, "{name} must be at least one second");
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

    #[test]
    fn parses_config_and_selects_longest_domain() {
        let config = Config::parse(&format!(
            r#"
            hex_zones = ["hex.example.net"]
            [[upstreams]]
            type = "plain"
            address = "1.1.1.1:53"
            [[upstreams]]
            type = "doh"
            url = "https://dns.example/dns-query"
            bootstrap = ["192.0.2.1", "2001:db8::1"]
            [[discovery]]
            domain = "example.com"
            key = "{KEY}"
            [[discovery]]
            domain = "inner.example.com"
            key = "{KEY}"
        "#
        ))
        .unwrap();
        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(
            config
                .discovery_for(&canonical_name("a.inner.example.com").unwrap())
                .unwrap()
                .domain
                .to_ascii(),
            "inner.example.com."
        );
        assert!(
            config
                .discovery_for(&canonical_name("badexample.com").unwrap())
                .is_none()
        );
    }

    #[test]
    fn rejects_bad_configs_without_printing_secrets() {
        for text in [
            "ttl = 0".to_owned(),
            "listen = []".to_owned(),
            "unknown = 1".to_owned(),
            "hex_zones = ['x.com', 'a.x.com']".to_owned(),
            format!(
                "hex_zones = ['a.example.com']\n[[discovery]]\ndomain='example.com'\nkey='{KEY}'"
            ),
            format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}SECRET'"),
            format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}SECRET"),
            "[[upstreams]]\ntype='doh'\nurl='http://example.com/dns-query'\nbootstrap=['1.1.1.1']"
                .to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://example.com/dns-query'\nbootstrap=[]"
                .to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='127.0.0.1:5300'".to_owned(),
        ] {
            let error = Config::parse(&text)
                .err()
                .expect("invalid config")
                .to_string();
            assert!(!error.contains(KEY));
        }
    }

    #[test]
    fn rejects_ambiguous_zones_invalid_limits_and_unsupported_upstreams() {
        let discovery = format!("[[discovery]]\ndomain='example.com'\nkey='{KEY}'\n");
        for text in [
            "listen=['0.0.0.0:0']".to_owned(),
            "cache_capacity=0".to_owned(), "cache_capacity=65537".to_owned(),
            "max_inflight=0".to_owned(), "max_inflight=65537".to_owned(),
            "valid_for='0s'".to_owned(), "upstream_timeout='500ms'".to_owned(),
            "request_timeout='not a duration'".to_owned(),
            "hex_zones=['EXAMPLE.COM', 'example.com.']".to_owned(),
            "hex_zones=['a.example.com', 'example.com']".to_owned(),
            format!("hex_zones=['com']\n{discovery}"),
            format!("{discovery}[[discovery]]\ndomain='EXAMPLE.COM.'\nkey='{KEY}'"),
            "[[upstreams]]\ntype='dot'\naddress='1.1.1.1:853'".to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='0.0.0.0:53'".to_owned(),
            "[[upstreams]]\ntype='plain'\naddress='1.1.1.1:0'".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://user:secret@dns.test/dns-query'\nbootstrap=['1.1.1.1']".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://dns.test/dns-query#fragment'\nbootstrap=['1.1.1.1']".to_owned(),
            "[[upstreams]]\ntype='doh'\nurl='https://dns.test/dns-query'\nbootstrap=['::']".to_owned(),
        ] {
            let error = Config::parse(&text).err().expect("invalid configuration accepted");
            assert!(!format!("{error:#}").contains(KEY));
        }
        let defaults = Config::parse("").unwrap();
        assert!(
            defaults.upstreams.is_empty(),
            "offline key/TXT generation needs no upstream"
        );
        assert_eq!(defaults.listen, vec!["0.0.0.0:5300".parse().unwrap()]);
        assert!(Config::parse("cache_capacity=65536\nmax_inflight=65536").is_ok());
    }
}
