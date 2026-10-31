use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use bytes::Bytes;
use hickory_proto::{
    op::{Edns, Message, OpCode, Query, ResponseCode},
    rr::{
        RData, Record, RecordType,
        rdata::{A, SOA, TXT},
    },
};
use hickory_resolver::TlsConfig;
use hickory_server::Server;
use rustls::{
    RootCertStore,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
};
use tendns::{
    config::{Config, Upstream},
    names::canonical_name,
    protocol::{Entry, Publication, Value, encrypt},
    resolver::{Clock, Resolver, SystemClock},
    server::Handler,
    upstream::{Exchange, Forwarder},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tokio_rustls::TlsAcceptor;

fn query(name: &str, kind: RecordType) -> Message {
    let mut query = Message::query();
    query.metadata.id = 4242;
    query.metadata.recursion_desired = true;
    query
        .queries
        .push(Query::query(canonical_name(name).unwrap(), kind));
    query
}

fn response(query: &Message) -> Message {
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.queries = query.queries.clone();
    response
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

async fn tcp_read(stream: &mut TcpStream) -> Message {
    let length = stream.read_u16().await.unwrap() as usize;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await.unwrap();
    Message::from_vec(&bytes).unwrap()
}

async fn tcp_write(stream: &mut TcpStream, response: &Message) {
    let bytes = response.to_vec().unwrap();
    stream.write_u16(bytes.len() as u16).await.unwrap();
    stream.write_all(&bytes).await.unwrap();
}

#[tokio::test]
async fn plain_upstream_retries_truncated_udp_and_reconnects_closed_tcp() {
    let tcp = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(tcp.local_addr().unwrap().port());
    let udp = UdpSocket::bind(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        address.port(),
    ))
    .await
    .unwrap();
    let udp_task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        for _ in 0..2 {
            let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let query = Message::from_vec(&bytes[..length]).unwrap();
            let mut reply = response(&query);
            reply.metadata.truncation = true;
            udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
        }
    });
    let tcp_task = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = tcp.accept().await.unwrap();
            let query = tcp_read(&mut stream).await;
            let mut reply = response(&query);
            reply.metadata.authentic_data = true;
            reply.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                123,
                RData::A(A("192.0.2.42".parse().unwrap())),
            ));
            tcp_write(&mut stream, &reply).await;
        }
    });
    let upstream = Forwarder::new(&[Upstream::Plain(address)], Duration::from_secs(2)).unwrap();
    for _ in 0..2 {
        let result = upstream
            .exchange(query("external.example", RecordType::A))
            .await
            .unwrap();
        assert_eq!(result.metadata.id, 4242);
        assert!(!result.metadata.truncation);
        assert!(result.metadata.authentic_data);
        assert_eq!(
            result.answers[0].data,
            RData::A(A("192.0.2.42".parse().unwrap()))
        );
    }
    udp_task.await.unwrap();
    tcp_task.await.unwrap();
}

#[tokio::test]
async fn negative_response_preserves_soa_and_does_not_trigger_tcp() {
    let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(udp.local_addr().unwrap().port());
    let task = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (length, peer) = udp.recv_from(&mut bytes).await.unwrap();
        let query = Message::from_vec(&bytes[..length]).unwrap();
        let mut reply = response(&query);
        reply.metadata.response_code = ResponseCode::NXDomain;
        reply.authorities.push(Record::from_rdata(
            canonical_name("example").unwrap(),
            30,
            RData::SOA(SOA::new(
                canonical_name("ns.example").unwrap(),
                canonical_name("admin.example").unwrap(),
                1,
                30,
                30,
                30,
                30,
            )),
        ));
        udp.send_to(&reply.to_vec().unwrap(), peer).await.unwrap();
    });
    let upstream = Forwarder::new(&[Upstream::Plain(address)], Duration::from_secs(2)).unwrap();
    let result = upstream
        .exchange(query("missing.example", RecordType::A))
        .await
        .unwrap();
    assert_eq!(result.metadata.response_code, ResponseCode::NXDomain);
    assert_eq!(result.authorities.len(), 1);
    task.await.unwrap();
}

#[tokio::test]
async fn upstream_failover_uses_the_next_configured_resolver() {
    let mut upstreams = Vec::new();
    let mut tasks = Vec::new();
    for failure in [true, false] {
        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();
        upstreams.push(Upstream::Plain(localhost(udp.local_addr().unwrap().port())));
        tasks.push(tokio::spawn(async move {
            let mut bytes = [0; 4096];
            let (len, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let question = Message::from_vec(&bytes[..len]).unwrap();
            let mut answer = response(&question);
            if failure {
                answer.metadata.response_code = ResponseCode::ServFail;
            } else {
                answer.answers.push(Record::from_rdata(
                    question.queries[0].name().clone(),
                    60,
                    RData::A(A("192.0.2.11".parse().unwrap())),
                ));
            }
            udp.send_to(&answer.to_vec().unwrap(), peer).await.unwrap();
        }));
    }
    let forwarder = Forwarder::new(&upstreams, Duration::from_secs(2)).unwrap();
    let answer = forwarder
        .exchange(query("external.net", RecordType::A))
        .await
        .unwrap();
    assert_eq!(
        answer.answers[0].data,
        RData::A(A("192.0.2.11".parse().unwrap()))
    );
    for task in tasks {
        task.await.unwrap();
    }
}

async fn doh_server() -> (Upstream, TlsConfig, tokio::task::JoinHandle<()>) {
    let cert = rcgen::generate_simple_self_signed(vec!["dns.test".into()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut tls = TlsConfig::new().unwrap();
    tls.config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let private = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    let mut server = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], private)
        .unwrap();
    server.alpn_protocols = vec![b"h2".to_vec()];
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(Arc::new(server));
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut connection = h2::server::handshake(stream).await.unwrap();
                while let Some(request) = connection.accept().await {
                    let (request, mut sender) = request.unwrap();
                    assert_eq!(request.method(), "POST");
                    assert_eq!(request.uri().path(), "/dns-query");
                    assert_eq!(request.headers()["content-type"], "application/dns-message");
                    let mut body = request.into_body();
                    let mut bytes = Vec::new();
                    while let Some(chunk) = body.data().await {
                        let chunk = chunk.unwrap();
                        body.flow_control().release_capacity(chunk.len()).unwrap();
                        bytes.extend_from_slice(&chunk);
                    }
                    let query = Message::from_vec(&bytes).unwrap();
                    let mut answer = response(&query);
                    answer.answers.push(Record::from_rdata(
                        query.queries[0].name().clone(),
                        60,
                        RData::A(A("192.0.2.99".parse().unwrap())),
                    ));
                    let reply = http::Response::builder()
                        .status(200)
                        .header("content-type", "application/dns-message")
                        .body(())
                        .unwrap();
                    let mut body = sender.send_response(reply, false).unwrap();
                    body.send_data(Bytes::from(answer.to_vec().unwrap()), true)
                        .unwrap();
                }
            });
        }
    });
    (
        Upstream::Doh {
            url: format!("https://dns.test:{port}/dns-query")
                .parse()
                .unwrap(),
            bootstrap: vec![Ipv4Addr::LOCALHOST.into()],
        },
        tls,
        task,
    )
}

#[tokio::test]
async fn doh_uses_bootstrap_with_certificate_and_hostname_validation() {
    let (upstream, tls, task) = doh_server().await;
    let forwarder =
        Forwarder::with_tls(std::slice::from_ref(&upstream), Duration::from_secs(2), tls).unwrap();
    for _ in 0..2 {
        let answer = forwarder
            .exchange(query("external.example", RecordType::A))
            .await
            .unwrap();
        assert_eq!(
            answer.answers[0].data,
            RData::A(A("192.0.2.99".parse().unwrap()))
        );
        assert_eq!(answer.metadata.id, 4242);
    }
    // The same self-signed server must fail with the normal public trust roots.
    let untrusted =
        Forwarder::new(std::slice::from_ref(&upstream), Duration::from_secs(2)).unwrap();
    assert!(
        untrusted
            .exchange(query("external.example", RecordType::A))
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
    let (mut upstream, tls, task) = doh_server().await;
    if let Upstream::Doh { url, .. } = &mut upstream {
        url.set_host(Some("wrong.test")).unwrap();
    }
    let wrong_host = Forwarder::with_tls(&[upstream], Duration::from_secs(2), tls).unwrap();
    assert!(
        wrong_host
            .exchange(query("external.example", RecordType::A))
            .await
            .is_err()
    );
    task.abort();
    let _ = task.await;
}

struct LargeAnswer;
#[async_trait::async_trait]
impl Exchange for LargeAnswer {
    async fn exchange(&self, query: Message) -> anyhow::Result<Message> {
        let mut response = response(&query);
        for i in 0..20 {
            response.answers.push(Record::from_rdata(
                query.queries[0].name().clone(),
                60,
                RData::TXT(TXT::new(vec![format!("{i:03}{}", "x".repeat(197))])),
            ));
        }
        Ok(response)
    }
}

#[tokio::test]
async fn listeners_support_udp_tcp_edns_truncation_and_shutdown() {
    let config = Arc::new(Config::parse("hex_zones = ['hex.test']").unwrap());
    let resolver = Arc::new(Resolver::new(config, Arc::new(LargeAnswer)));
    let mut server = Server::new(Handler::new(resolver, 8, Duration::from_secs(2)));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(listener.local_addr().unwrap().port());
    let udp = UdpSocket::bind(SocketAddr::new(
        Ipv4Addr::UNSPECIFIED.into(),
        address.port(),
    ))
    .await
    .unwrap();
    server.register_socket(udp);
    server.register_listener(listener, Duration::from_secs(2), 8);
    let cancellation = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let mut bytes = [0; 65535];
    for max_size in [512, 1232] {
        let mut question = query("large.external", RecordType::TXT);
        if max_size > 512 {
            question.edns = Some(Edns::new());
            question.edns.as_mut().unwrap().set_max_payload(max_size);
        }
        client
            .send_to(&question.to_vec().unwrap(), address)
            .await
            .unwrap();
        let (length, _) =
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut bytes))
                .await
                .unwrap()
                .unwrap();
        assert!(length <= max_size as usize);
        let result = Message::from_vec(&bytes[..length]).unwrap();
        assert!(result.metadata.truncation);
        assert_eq!(result.edns.is_some(), max_size > 512);
    }
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &query("large.external", RecordType::TXT)).await;
    let result = tcp_read(&mut stream).await;
    assert!(!result.metadata.truncation);
    assert_eq!(result.answers.len(), 20);
    tcp_write(&mut stream, &query("c0000201.hex.test", RecordType::A)).await;
    let result = tcp_read(&mut stream).await;
    assert_eq!(
        result.answers[0].data,
        RData::A(A("192.0.2.1".parse().unwrap()))
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.metadata.op_code = OpCode::Update;
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::NotImp
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.queries.push(invalid.queries[0].clone());
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::FormErr
    );
    let mut invalid = query("example.com", RecordType::A);
    invalid.queries[0].set_query_class(hickory_proto::rr::DNSClass::CH);
    tcp_write(&mut stream, &invalid).await;
    assert_eq!(
        tcp_read(&mut stream).await.metadata.response_code,
        ResponseCode::Refused
    );
    let mut invalid = query("example.com", RecordType::A);
    let mut edns = Edns::new();
    edns.set_version(1);
    invalid.edns = Some(edns);
    tcp_write(&mut stream, &invalid).await;
    let bad_version = tcp_read(&mut stream).await;
    // BADVERS and BADSIG share wire code 16; Hickory decodes it as BADSIG.
    assert_eq!(u16::from(bad_version.metadata.response_code), 16);
    assert_eq!(bad_version.edns.unwrap().version(), 0);
    drop(stream);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn encrypted_txt_resolves_through_real_dns_listeners() {
    let upstream_socket = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let upstream_address = localhost(upstream_socket.local_addr().unwrap().port());
    let config = Arc::new(Config::parse(&format!(
        "[[upstreams]]\ntype='plain'\naddress='{upstream_address}'\n[[discovery]]\ndomain='example.com'\nkey='BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc'"
    )).unwrap());
    let now = SystemClock.now().unwrap();
    let value = encrypt(
        &Publication {
            issued_at: now,
            expires_at: now + 3600,
            entries: vec![Entry {
                subdomain: "nas".into(),
                value: Value::A("192.0.2.10".parse().unwrap()),
            }],
        },
        &config.discovery[0].key,
        &canonical_name("example.com").unwrap(),
    )
    .unwrap();
    let publisher = tokio::spawn(async move {
        let mut bytes = [0; 4096];
        let (len, peer) = upstream_socket.recv_from(&mut bytes).await.unwrap();
        let question = Message::from_vec(&bytes[..len]).unwrap();
        assert_eq!(
            question.queries,
            vec![Query::query(
                canonical_name("example.com").unwrap(),
                RecordType::TXT
            )]
        );
        let mut answer = response(&question);
        answer.answers.push(Record::from_rdata(
            canonical_name("example.com").unwrap(),
            60,
            RData::TXT(TXT::from_bytes(value.as_bytes().chunks(20).collect())),
        ));
        upstream_socket
            .send_to(&answer.to_vec().unwrap(), peer)
            .await
            .unwrap();
    });
    let forwarder = Arc::new(Forwarder::new(&config.upstreams, Duration::from_secs(2)).unwrap());
    let resolver = Arc::new(Resolver::new(config, forwarder));
    let mut server = Server::new(Handler::new(resolver, 8, Duration::from_secs(3)));
    let listener = TcpListener::bind("0.0.0.0:0").await.unwrap();
    let address = localhost(listener.local_addr().unwrap().port());
    server.register_socket(
        UdpSocket::bind(SocketAddr::new(
            Ipv4Addr::UNSPECIFIED.into(),
            address.port(),
        ))
        .await
        .unwrap(),
    );
    server.register_listener(listener, Duration::from_secs(2), 8);
    let cancellation = server.shutdown_token().clone();
    let task = tokio::spawn(async move {
        server.block_until_done().await.unwrap();
    });
    let client = UdpSocket::bind("0.0.0.0:0").await.unwrap();
    let question = query("nas.example.com", RecordType::A);
    client
        .send_to(&question.to_vec().unwrap(), address)
        .await
        .unwrap();
    let mut bytes = [0; 4096];
    let (len, _) = tokio::time::timeout(Duration::from_secs(4), client.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    let answer = Message::from_vec(&bytes[..len]).unwrap();
    assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
    assert_eq!(
        answer.answers[0].data,
        RData::A(A("192.0.2.10".parse().unwrap()))
    );
    publisher.await.unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    tcp_write(&mut stream, &question).await;
    let cached = tcp_read(&mut stream).await;
    assert_eq!(cached.answers[0].data, answer.answers[0].data);
    assert!(!cached.metadata.authentic_data);
    drop(stream);
    cancellation.cancel();
    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .unwrap()
        .unwrap();
}
