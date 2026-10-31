use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::{
    op::{Message, OpCode, Query, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, CNAME, SOA, TXT},
    },
};
use tendns::{
    config::Config,
    names::canonical_name,
    protocol::{Entry, Publication, Value, encrypt},
    resolver::{Clock, Resolver},
    upstream::Exchange,
};

const KEY: &str = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc";

#[derive(Default)]
struct Mock {
    replies: Mutex<HashMap<(Name, RecordType), Message>>,
    calls: Mutex<Vec<(Name, RecordType)>>,
}

impl Mock {
    fn set(&self, owner: &str, kind: RecordType, message: Message) {
        self.replies
            .lock()
            .unwrap()
            .insert((canonical_name(owner).unwrap(), kind), message);
    }

    fn calls(&self) -> Vec<(String, RecordType)> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(name, kind)| (name.to_ascii(), *kind))
            .collect()
    }
}

#[async_trait]
impl Exchange for Mock {
    async fn exchange(&self, query: Message) -> Result<Message> {
        let key = (
            query.queries[0].name().clone(),
            query.queries[0].query_type(),
        );
        self.calls.lock().unwrap().push(key.clone());
        self.replies
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .context("mock upstream failure")
    }
}

struct FakeClock(AtomicU64);
impl Clock for FakeClock {
    fn now(&self) -> Result<u64> {
        Ok(self.0.load(Ordering::SeqCst))
    }
}

fn config() -> Arc<Config> {
    Arc::new(
        Config::parse(&format!(
            "hex_zones=['hex.test']\n[[discovery]]\ndomain='example.com'\nkey='{KEY}'"
        ))
        .unwrap(),
    )
}

fn query(name: &str, kind: RecordType) -> Message {
    let mut message = Message::query();
    message.metadata.id = 1234;
    message.metadata.recursion_desired = true;
    message
        .queries
        .push(Query::query(canonical_name(name).unwrap(), kind));
    message
}

fn reply() -> Message {
    Message::response(0, OpCode::Query)
}

fn entry(label: &str, ip: &str) -> Entry {
    Entry {
        subdomain: label.into(),
        value: Value::A(ip.parse().unwrap()),
    }
}

fn publication(entries: Vec<Entry>, issued_at: u64) -> Publication {
    Publication {
        issued_at,
        expires_at: issued_at + 100,
        entries,
    }
}

fn txt(config: &Config, owner: &str, publication: &Publication, ttl: u32) -> Record {
    let name = canonical_name(owner).unwrap();
    let encoded = encrypt(
        publication,
        &config.discovery_for(&name).unwrap().key,
        &name,
    )
    .unwrap();
    // Providers may split at any character boundary, even inside the prefix.
    Record::from_rdata(
        name,
        ttl,
        RData::TXT(TXT::from_bytes(encoded.as_bytes().chunks(3).collect())),
    )
}

fn setup() -> (Arc<Config>, Arc<Mock>, Arc<FakeClock>, Resolver) {
    let config = config();
    let mock = Arc::new(Mock::default());
    let clock = Arc::new(FakeClock(AtomicU64::new(100)));
    let resolver = Resolver::with_clock(config.clone(), mock.clone(), clock.clone());
    (config, mock, clock, resolver)
}

#[tokio::test]
async fn parent_first_hidden_names_and_type_precedence() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("nas", "192.0.2.1")], 100),
        60,
    ));
    parent.metadata.authentic_data = true;
    mock.set("example.com", RecordType::TXT, parent);
    let mut direct = reply();
    direct.answers.push(txt(
        &config,
        "nas.example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    mock.set("nas.example.com", RecordType::TXT, direct);
    let mut question = query("nas.example.com", RecordType::A);
    question.queries[0].set_name(Name::from_ascii("NaS.Example.COM.").unwrap());
    let result = resolver.answer(question.clone()).await.unwrap();
    assert_eq!(
        result.queries[0].name().to_ascii(),
        question.queries[0].name().to_ascii()
    );
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(result.answers[0].name.to_ascii(), "nas.example.com.");
    assert!(!result.metadata.authentic_data);
    assert!(!result.metadata.authoritative);
    assert!(result.metadata.recursion_available);
    let result = resolver
        .answer(query("nas.example.com", RecordType::AAAA))
        .await
        .unwrap();
    assert!(result.answers.is_empty());
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn confirmed_miss_tries_direct_only_then_nxdomain() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("other", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, parent);
    let mut direct = reply();
    direct.answers.push(txt(
        &config,
        "nas.example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    mock.set("nas.example.com", RecordType::TXT, direct);
    let result = resolver
        .answer(query("nas.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.2".parse().unwrap()))
    );
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("nas.example.com.".into(), RecordType::TXT)
        ]
    );
    mock.set("missing.example.com", RecordType::TXT, reply());
    let result = resolver
        .answer(query("missing.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
    assert!(
        mock.calls()
            .iter()
            .all(|(_, kind)| *kind == RecordType::TXT)
    );
}

#[tokio::test]
async fn parent_errors_never_leak_child_queries() {
    for invalid in [
        None,
        Some("td1.invalid"),
        Some("td2.unsupported"),
        Some("td10.unsupported"),
        Some("td1"),
    ] {
        let (_, mock, _, resolver) = setup();
        if let Some(value) = invalid {
            let mut parent = reply();
            parent.answers.push(Record::from_rdata(
                canonical_name("example.com").unwrap(),
                60,
                RData::TXT(TXT::new(vec![value.into()])),
            ));
            mock.set("example.com", RecordType::TXT, parent);
        }
        assert!(
            resolver
                .answer(query("secret.example.com", RecordType::A))
                .await
                .is_err()
        );
        assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
    }
}

#[tokio::test]
async fn split_txt_values_combine_independent_entries_and_reject_alias_conflicts() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("", "192.0.2.1")], 90),
        60,
    ));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("", "192.0.2.2")], 100),
        60,
    ));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: String::new(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap()),
            }],
            100,
        ),
        60,
    ));
    answer.answers.push(answer.answers[1].clone());
    mock.set("example.com", RecordType::TXT, answer.clone());
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.answers.len(), 2);
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    assert_eq!(
        result.answers[1].data,
        RData::A(A("192.0.2.2".parse().unwrap()))
    );
    let ipv6 = resolver
        .answer(query("example.com", RecordType::AAAA))
        .await
        .unwrap();
    assert_eq!(ipv6.answers.len(), 1);
    assert!(matches!(ipv6.answers[0].data, RData::AAAA(_)));
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: String::new(),
                value: Value::Cname(canonical_name("target.net").unwrap()),
            }],
            100,
        ),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(config, mock, Arc::new(FakeClock(AtomicU64::new(100))));
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn invalid_sibling_value_is_not_a_confirmed_hidden_name_miss() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("public", "192.0.2.1")], 100),
        60,
    ));
    answer.answers.push(Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::TXT(TXT::new(vec!["td1.invalid".into()])),
    ));
    mock.set("example.com", RecordType::TXT, answer);
    assert!(
        resolver
            .answer(query("secret.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn expiry_bounds_ttl_and_invalidates_cached_payload() {
    let (config, mock, clock, resolver) = setup();
    let mut answer = reply();
    let mut p = publication(vec![entry("", "192.0.2.1")], 100);
    p.expires_at = 105;
    answer.answers.push(txt(&config, "example.com", &p, 600));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert!(result.answers[0].ttl <= 5);
    clock.0.store(105, Ordering::SeqCst);
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls().len(), 2);
}

#[tokio::test]
async fn cname_chain_loop_and_txt_indirection() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    let alias = Entry {
        subdomain: "www".into(),
        value: Value::Cname(canonical_name("nas.example.com").unwrap()),
    };
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![alias, entry("nas", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("www.example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.answers.len(), 2);
    assert!(matches!(result.answers[0].data, RData::CNAME(_)));
    assert!(matches!(result.answers[1].data, RData::A(_)));
    assert_eq!(
        resolver
            .answer(query("www.example.com", RecordType::CNAME))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    let mut answer = reply();
    let alias = Entry {
        subdomain: "www".into(),
        value: Value::Cname(canonical_name("www.example.com").unwrap()),
    };
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![alias], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(
        config.clone(),
        mock.clone(),
        Arc::new(FakeClock(AtomicU64::new(100))),
    );
    assert!(
        resolver
            .answer(query("www.example.com", RecordType::A))
            .await
            .is_err()
    );
    let mut answer = reply();
    answer.answers.push(Record::from_rdata(
        canonical_name("example.com").unwrap(),
        60,
        RData::CNAME(CNAME(canonical_name("elsewhere.com").unwrap())),
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(config, mock, Arc::new(FakeClock(AtomicU64::new(100))));
    assert!(
        resolver
            .answer(query("example.com", RecordType::A))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn hex_synthesis_is_exact_and_never_calls_upstream() {
    let (_, mock, _, resolver) = setup();
    for (hex, address) in [
        ("c0000201", "192.0.2.1"),
        ("01020304", "1.2.3.4"),
        ("FFFFFFFF", "255.255.255.255"),
        ("00000000", "0.0.0.0"),
        ("7f000001", "127.0.0.1"),
    ] {
        let result = resolver
            .answer(query(&format!("{hex}.hex.test"), RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            result.answers[0].data,
            RData::A(A(address.parse().unwrap()))
        );
        let result = resolver
            .answer(query(&format!("{hex}.hex.test"), RecordType::AAAA))
            .await
            .unwrap();
        assert!(result.answers.is_empty());
        assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    }
    for name in [
        "0000000.hex.test",
        "000000000.hex.test",
        "zzzzzzzz.hex.test",
        "a.c0000201.hex.test",
    ] {
        assert_eq!(
            resolver
                .answer(query(name, RecordType::A))
                .await
                .unwrap()
                .metadata
                .response_code,
            ResponseCode::NXDomain
        );
    }
    let apex = resolver
        .answer(query("hex.test", RecordType::A))
        .await
        .unwrap();
    assert_eq!(apex.metadata.response_code, ResponseCode::NoError);
    assert!(apex.answers.is_empty());
    assert!(mock.calls().is_empty());
}

#[tokio::test]
async fn forwarding_preserves_sections_and_flags() {
    let (_, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.metadata.authentic_data = true;
    answer.metadata.response_code = ResponseCode::NXDomain;
    answer.authorities.push(Record::from_rdata(
        canonical_name("external.net").unwrap(),
        60,
        RData::SOA(SOA::new(
            canonical_name("ns.external.net").unwrap(),
            canonical_name("admin.external.net").unwrap(),
            1,
            60,
            60,
            60,
            60,
        )),
    ));
    mock.set("absent.external.net", RecordType::A, answer.clone());
    let result = resolver
        .answer(query("absent.external.net", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.id, 1234);
    assert!(result.metadata.authentic_data);
    assert_eq!(result.authorities, answer.authorities);
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
}

#[tokio::test]
async fn concurrent_parent_queries_share_one_fetch() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("a", "192.0.2.1"), entry("b", "192.0.2.2")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let (a, b) = tokio::join!(
        resolver.answer(query("a.example.com", RecordType::A)),
        resolver.answer(query("b.example.com", RecordType::A))
    );
    assert!(a.is_ok() && b.is_ok());
    assert_eq!(mock.calls().len(), 1);
}

#[tokio::test]
async fn hidden_children_do_not_make_their_parent_nxdomain() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "example.com",
        &publication(vec![entry("child", "192.0.2.1")], 100),
        60,
    ));
    mock.set("example.com", RecordType::TXT, answer);
    let result = resolver
        .answer(query("example.com", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NoError);
    assert!(result.answers.is_empty());
    assert_eq!(
        resolver
            .answer(query("child.example.com", RecordType::A))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
}

#[tokio::test]
async fn parent_search_stops_at_the_most_specific_configured_domain() {
    let config = Arc::new(Config::parse(&format!(
        "[[discovery]]\ndomain='example.com'\nkey='{KEY}'\n[[discovery]]\ndomain='inner.example.com'\nkey='{KEY}'"
    )).unwrap());
    let mock = Arc::new(Mock::default());
    let mut answer = reply();
    answer.answers.push(txt(
        &config,
        "inner.example.com",
        &publication(vec![entry("", "192.0.2.1")], 100),
        60,
    ));
    mock.set("inner.example.com", RecordType::TXT, answer);
    let resolver = Resolver::with_clock(
        config,
        mock.clone(),
        Arc::new(FakeClock(AtomicU64::new(100))),
    );
    assert_eq!(
        resolver
            .answer(query("inner.example.com", RecordType::A))
            .await
            .unwrap()
            .answers
            .len(),
        1
    );
    assert_eq!(
        mock.calls(),
        vec![("inner.example.com.".into(), RecordType::TXT)]
    );
}

#[tokio::test]
async fn dns_ttl_refreshes_positive_and_negative_cache_entries() {
    for positive in [false, true] {
        let (config, mock, _, resolver) = setup();
        let mut answer = reply();
        if positive {
            answer.answers.push(txt(
                &config,
                "example.com",
                &publication(vec![entry("", "192.0.2.1")], 100),
                1,
            ));
        } else {
            answer.metadata.response_code = ResponseCode::NXDomain;
            answer.authorities.push(Record::from_rdata(
                canonical_name("example.com").unwrap(),
                30,
                RData::SOA(SOA::new(
                    canonical_name("ns.example.com").unwrap(),
                    canonical_name("admin.example.com").unwrap(),
                    1,
                    30,
                    30,
                    30,
                    1,
                )),
            ));
        }
        mock.set("example.com", RecordType::TXT, answer);
        for _ in 0..2 {
            let result = resolver
                .answer(query("example.com", RecordType::A))
                .await
                .unwrap();
            assert_eq!(result.answers.len(), usize::from(positive));
        }
        assert_eq!(mock.calls().len(), 1);
        let mut answer = reply();
        answer.answers.push(txt(
            &config,
            "example.com",
            &publication(vec![entry("", "192.0.2.2")], 100),
            60,
        ));
        mock.set("example.com", RecordType::TXT, answer);
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        let result = resolver
            .answer(query("example.com", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            result.answers[0].data,
            RData::A(A("192.0.2.2".parse().unwrap()))
        );
        assert_eq!(mock.calls().len(), 2);
    }
}

#[tokio::test]
async fn oversized_parent_rrset_fails_without_querying_hidden_child() {
    let (config, mock, _, resolver) = setup();
    let mut answer = reply();
    let record = txt(
        &config,
        "example.com",
        &publication(vec![entry("a", "192.0.2.1")], 100),
        60,
    );
    answer.answers = vec![record; 17];
    mock.set("example.com", RecordType::TXT, answer);
    assert!(
        resolver
            .answer(query("a.example.com", RecordType::A))
            .await
            .is_err()
    );
    assert_eq!(mock.calls(), vec![("example.com.".into(), RecordType::TXT)]);
}

#[tokio::test]
async fn cname_into_forwarded_dns_preserves_chain_without_claiming_validation() {
    let (config, mock, _, resolver) = setup();
    let mut parent = reply();
    parent.answers.push(txt(
        &config,
        "example.com",
        &publication(
            vec![Entry {
                subdomain: "alias".into(),
                value: Value::Cname(canonical_name("external.net").unwrap()),
            }],
            100,
        ),
        60,
    ));
    mock.set("example.com", RecordType::TXT, parent);
    let mut target = reply();
    target.metadata.authentic_data = true;
    target.answers.push(Record::from_rdata(
        canonical_name("external.net").unwrap(),
        60,
        RData::A(A("192.0.2.1".parse().unwrap())),
    ));
    mock.set("external.net", RecordType::A, target);
    let question = query("alias.example.com", RecordType::A);
    let answer = resolver.answer(question.clone()).await.unwrap();
    assert_eq!(answer.queries, question.queries);
    assert!(!answer.metadata.authentic_data);
    assert!(!answer.metadata.authoritative);
    assert_eq!(answer.answers.len(), 2);
    assert!(matches!(answer.answers[0].data, RData::CNAME(_)));
    assert!(matches!(answer.answers[1].data, RData::A(_)));
    assert_eq!(
        mock.calls(),
        vec![
            ("example.com.".into(), RecordType::TXT),
            ("external.net.".into(), RecordType::A)
        ]
    );
}
