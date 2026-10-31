use std::{
    collections::{HashMap, HashSet},
    net::Ipv4Addr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail, ensure};
use hickory_proto::{
    op::{Edns, Message, Metadata, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record, RecordType,
        rdata::{A, AAAA, CNAME},
    },
};
use tokio::{sync::Mutex, time::Instant};

use crate::{
    config::{Config, Discovery},
    protocol::{self, Entry, Publication, Value},
    upstream::Exchange,
};

pub trait Clock: Send + Sync {
    fn now(&self) -> Result<u64>;
}

pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<u64> {
        Ok(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before Unix epoch")?
            .as_secs())
    }
}

pub struct Resolver {
    config: Arc<Config>,
    upstream: Arc<dyn Exchange>,
    clock: Arc<dyn Clock>,
    cache: Mutex<HashMap<Name, Arc<Mutex<Option<Cached>>>>>,
}

#[derive(Clone)]
struct Cached {
    publication: Option<Arc<Publication>>,
    until: Instant,
}

enum Local {
    Forward,
    Missing,
    Found { entries: Vec<Entry>, ttl: u32 },
}

impl Resolver {
    pub fn new(config: Arc<Config>, upstream: Arc<dyn Exchange>) -> Self {
        Self::with_clock(config, upstream, Arc::new(SystemClock))
    }

    pub fn with_clock(
        config: Arc<Config>,
        upstream: Arc<dyn Exchange>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            config,
            upstream,
            clock,
            cache: Mutex::new(HashMap::new()),
        }
    }

    pub async fn answer(&self, request: Message) -> Result<Message> {
        ensure!(request.queries.len() == 1, "expected one question");
        let question = &request.queries[0];
        let mut name = question.name().to_lowercase();
        let kind = question.query_type();
        let mut seen = HashSet::new();
        let mut response = local_response(&request, ResponseCode::NoError);
        for _ in 0..16 {
            ensure!(seen.insert(name.clone()), "CNAME loop");
            match self.local(&name).await? {
                Local::Forward => {
                    let mut forwarded = request.clone();
                    forwarded.queries = vec![Query::query(name, kind)];
                    let mut result = self.upstream.exchange(forwarded).await?;
                    result.metadata.id = request.metadata.id;
                    result.queries = request.queries.clone();
                    if !response.answers.is_empty() {
                        response.answers.append(&mut result.answers);
                        result.answers = response.answers;
                        result.metadata.authentic_data = false;
                        result.metadata.authoritative = false;
                    }
                    return Ok(result);
                }
                Local::Missing => {
                    response.metadata.response_code = ResponseCode::NXDomain;
                    return Ok(response);
                }
                Local::Found { entries, ttl } => {
                    if let Some(target) = entries.iter().find_map(|entry| match &entry.value {
                        Value::Cname(target) => Some(target),
                        _ => None,
                    }) {
                        response.answers.push(Record::from_rdata(
                            name.clone(),
                            ttl,
                            RData::CNAME(CNAME(target.clone())),
                        ));
                        if matches!(kind, RecordType::CNAME | RecordType::ANY) {
                            return Ok(response);
                        }
                        name = target.clone();
                        continue;
                    }
                    for entry in entries {
                        let data = match entry.value {
                            Value::A(ip) if matches!(kind, RecordType::A | RecordType::ANY) => {
                                Some(RData::A(A(ip)))
                            }
                            Value::Aaaa(ip)
                                if matches!(kind, RecordType::AAAA | RecordType::ANY) =>
                            {
                                Some(RData::AAAA(AAAA(ip)))
                            }
                            _ => None,
                        };
                        if let Some(data) = data {
                            let record = Record::from_rdata(name.clone(), ttl, data);
                            if !response.answers.contains(&record) {
                                response.answers.push(record);
                            }
                        }
                    }
                    return Ok(response);
                }
            }
        }
        bail!("CNAME chain exceeds 16 names")
    }

    async fn local(&self, name: &Name) -> Result<Local> {
        for zone in &self.config.hex_zones {
            if !zone.zone_of(name) {
                continue;
            }
            if name == zone {
                return Ok(Local::Found {
                    entries: Vec::new(),
                    ttl: self.config.ttl,
                });
            }
            if name.num_labels() != zone.num_labels() + 1 {
                return Ok(Local::Missing);
            }
            let Some(label) = name.iter().next() else {
                return Ok(Local::Missing);
            };
            if label.len() != 8 || !label.iter().all(u8::is_ascii_hexdigit) {
                return Ok(Local::Missing);
            }
            let hex = std::str::from_utf8(label).expect("ASCII hex");
            let ip = Ipv4Addr::from(u32::from_str_radix(hex, 16).expect("validated hex"));
            return Ok(Local::Found {
                entries: vec![Entry {
                    subdomain: String::new(),
                    value: Value::A(ip),
                }],
                ttl: self.config.ttl,
            });
        }
        let Some(discovery) = self.config.discovery_for(name) else {
            return Ok(Local::Forward);
        };
        let parent = name.base_name();
        if discovery.domain.zone_of(&parent) {
            let label = name.iter().next().context("missing child label")?;
            let label = std::str::from_utf8(label).context("invalid child label")?;
            if let Some(found) = self.entries(&parent, label, discovery).await? {
                return Ok(found);
            }
        }
        Ok(self
            .entries(name, "", discovery)
            .await?
            .unwrap_or(Local::Missing))
    }

    async fn entries(
        &self,
        owner: &Name,
        subdomain: &str,
        discovery: &Discovery,
    ) -> Result<Option<Local>> {
        let cached = self.publication(owner, discovery).await?;
        let Some(publication) = cached.publication else {
            return Ok(None);
        };
        let now = self.clock.now()?;
        publication.validate_time(now)?;
        let entries: Vec<_> = publication
            .entries
            .iter()
            .filter(|entry| entry.subdomain == subdomain)
            .cloned()
            .collect();
        // An owner with hidden children exists, even without records of its own.
        if entries.is_empty() && !subdomain.is_empty() {
            return Ok(None);
        }
        let ttl = (cached
            .until
            .saturating_duration_since(Instant::now())
            .as_secs()
            .min(u64::from(self.config.ttl))
            .min(publication.expires_at - now)) as u32;
        Ok(Some(Local::Found { entries, ttl }))
    }

    async fn publication(&self, owner: &Name, discovery: &Discovery) -> Result<Cached> {
        let slot = {
            let mut cache = self.cache.lock().await;
            if let Some(slot) = cache.get(owner) {
                slot.clone()
            } else {
                if cache.len() >= self.config.cache_capacity
                    && let Some(evicted) = cache.keys().next().cloned()
                {
                    cache.remove(&evicted);
                }
                let slot = Arc::new(Mutex::new(None));
                cache.insert(owner.clone(), slot.clone());
                slot
            }
        };
        // Serialize only this owner's fetch; unrelated names can resolve concurrently.
        let mut state = slot.lock().await;
        if let Some(cached) = state.as_ref() {
            let now = self.clock.now()?;
            if cached.until > Instant::now()
                && cached
                    .publication
                    .as_ref()
                    .is_none_or(|p| p.validate_time(now).is_ok())
            {
                return Ok(cached.clone());
            }
        }
        *state = None;
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query
            .queries
            .push(Query::query(owner.clone(), RecordType::TXT));
        query.edns = Some(Edns::new());
        query.edns.as_mut().expect("set EDNS").set_max_payload(1232);
        let answer = self.upstream.exchange(query).await?;
        let now = self.clock.now()?;
        let (publication, ttl) =
            collect_publications(&answer, owner, discovery, now, self.config.ttl)?;
        let cached = Cached {
            publication: publication.map(Arc::new),
            until: Instant::now() + Duration::from_secs(u64::from(ttl)),
        };
        *state = Some(cached.clone());
        Ok(cached)
    }
}

pub fn local_response(request: &Message, code: ResponseCode) -> Message {
    let mut result = Message::response(request.metadata.id, request.metadata.op_code);
    result.metadata = Metadata::response_from_request(&request.metadata);
    result.metadata.response_code = code;
    result.metadata.recursion_available = true;
    result.metadata.authoritative = false;
    result.metadata.authentic_data = false;
    result.queries = request.queries.clone();
    if let Some(edns) = &request.edns {
        let mut reply = Edns::new();
        reply.set_max_payload(edns.max_payload().clamp(512, 1232));
        result.edns = Some(reply);
    }
    result
}

fn collect_publications(
    response: &Message,
    owner: &Name,
    discovery: &Discovery,
    now: u64,
    ttl_cap: u32,
) -> Result<(Option<Publication>, u32)> {
    ensure!(!response.metadata.truncation, "truncated TXT response");
    ensure!(
        matches!(
            response.metadata.response_code,
            ResponseCode::NoError | ResponseCode::NXDomain
        ),
        "TXT lookup failed"
    );
    ensure!(
        !response
            .answers
            .iter()
            .any(|r| r.name == *owner && matches!(r.data, RData::CNAME(_))),
        "TXT CNAME indirection is not supported"
    );
    let mut candidates = 0;
    let mut total = 0;
    let mut combined: Option<Publication> = None;
    let mut ttl = ttl_cap;
    for record in &response.answers {
        if record.name != *owner || record.dns_class != DNSClass::IN {
            continue;
        }
        let RData::TXT(txt) = &record.data else {
            continue;
        };
        candidates += 1;
        total += txt.txt_data.iter().map(|chunk| chunk.len()).sum::<usize>();
        ensure!(
            candidates <= 16 && total <= protocol::MAX_ENCODED * 16,
            "TXT response exceeds limits"
        );
        let value: Vec<u8> = txt
            .txt_data
            .iter()
            .flat_map(|s| s.iter().copied())
            .collect();
        let prefix = value.split(|byte| *byte == b'.').next().unwrap_or_default();
        let is_encrypted = prefix
            .strip_prefix(b"td")
            .is_some_and(|version| !version.is_empty() && version.iter().all(u8::is_ascii_digit));
        if !is_encrypted {
            continue;
        }
        // A bad sibling value may contain the queried hidden label. It is not a miss.
        let publication = protocol::decrypt(&value, &discovery.key, owner, now)?;
        ensure!(
            response.metadata.response_code == ResponseCode::NoError,
            "contradictory TXT response"
        );
        ttl = ttl.min(record.ttl);
        if let Some(previous) = &mut combined {
            previous.issued_at = previous.issued_at.min(publication.issued_at);
            previous.expires_at = previous.expires_at.min(publication.expires_at);
            for entry in publication.entries {
                if !previous.entries.contains(&entry) {
                    previous.entries.push(entry);
                }
            }
            previous.validate(owner)?;
        } else {
            combined = Some(publication);
        }
    }
    if let Some(publication) = combined {
        ttl = u64::from(ttl).min(publication.expires_at - now) as u32;
        return Ok((Some(publication), ttl));
    }
    let ttl = response
        .authorities
        .iter()
        .filter_map(|r| match &r.data {
            RData::SOA(soa) if r.name.zone_of(owner) => Some(r.ttl.min(soa.minimum).min(ttl_cap)),
            _ => None,
        })
        .min()
        .unwrap_or(0);
    Ok((None, ttl))
}

pub fn validate_request(request: &Message) -> Option<ResponseCode> {
    if request.metadata.op_code != OpCode::Query {
        return Some(ResponseCode::NotImp);
    }
    if request.queries.len() != 1 {
        return Some(ResponseCode::FormErr);
    }
    if request.signature.is_some() {
        return Some(ResponseCode::Refused);
    }
    let query = &request.queries[0];
    if query.query_class() != DNSClass::IN
        || matches!(query.query_type(), RecordType::AXFR | RecordType::IXFR)
    {
        return Some(ResponseCode::Refused);
    }
    if request.edns.as_ref().is_some_and(|e| e.version() != 0) {
        return Some(ResponseCode::BADVERS);
    }
    None
}
