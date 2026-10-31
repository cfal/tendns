use std::{sync::Arc, time::Duration};

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::{Header, HeaderCounts, Message, ResponseCode};
use hickory_server::{
    Server,
    net::runtime::Time,
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Semaphore,
};

use crate::{
    config::Config,
    resolver::{Resolver, local_response, validate_request},
    upstream::Forwarder,
};

pub struct Handler {
    resolver: Arc<Resolver>,
    permits: Semaphore,
    timeout: Duration,
}

impl Handler {
    pub fn new(resolver: Arc<Resolver>, max_inflight: usize, timeout: Duration) -> Self {
        Self {
            resolver,
            permits: Semaphore::new(max_inflight),
            timeout,
        }
    }
}

#[async_trait]
impl RequestHandler for Handler {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let parsed = Message::from_vec(request.as_slice());
        let response = match parsed {
            Ok(message) => {
                if let Some(code) = validate_request(&message) {
                    local_response(&message, code)
                } else if let Ok(_permit) = self.permits.try_acquire() {
                    match tokio::time::timeout(self.timeout, self.resolver.answer(message.clone()))
                        .await
                    {
                        Ok(Ok(response)) => response,
                        _ => local_response(&message, ResponseCode::ServFail),
                    }
                } else {
                    local_response(&message, ResponseCode::ServFail)
                }
            }
            Err(_) => Message::error_msg(
                request.metadata.id,
                request.metadata.op_code,
                ResponseCode::FormErr,
            ),
        };
        let mut builder = MessageResponseBuilder::from_message_request(request);
        // Use the downstream payload limit, not the upstream's advertised limit.
        let mut edns = response.edns.clone();
        if let Some(client_edns) = &request.edns {
            edns.get_or_insert_with(Default::default)
                .set_max_payload(client_edns.max_payload().clamp(512, 1232));
        } else {
            edns = None;
        }
        if let Some(edns) = &edns {
            builder.edns(edns);
        }
        let message = builder.build(
            response.metadata,
            &response.answers,
            &response.authorities,
            std::iter::empty(),
            &response.additionals,
        );
        response_handle
            .send_response(message)
            .await
            .unwrap_or_else(|_| {
                let mut metadata = response.metadata;
                metadata.response_code = ResponseCode::ServFail;
                Header {
                    metadata,
                    counts: HeaderCounts::default(),
                }
                .into()
            })
    }
}

pub async fn serve(config: Config) -> Result<()> {
    let config = Arc::new(config);
    let upstream = Arc::new(Forwarder::new(&config.upstreams, config.upstream_timeout)?);
    let resolver = Arc::new(Resolver::new(config.clone(), upstream));
    let mut server = Server::new(Handler::new(
        resolver,
        config.max_inflight,
        config.request_timeout,
    ));
    // Bind everything before starting listeners, so a partial startup is not advertised.
    let mut sockets = Vec::new();
    for address in &config.listen {
        let udp = UdpSocket::bind(address)
            .await
            .with_context(|| format!("cannot bind UDP listener {address}"))?;
        let tcp = TcpListener::bind(address)
            .await
            .with_context(|| format!("cannot bind TCP listener {address}"))?;
        sockets.push((udp, tcp));
    }
    for (udp, tcp) in sockets {
        server.register_socket(udp);
        server.register_listener(tcp, Duration::from_secs(30), 32);
    }
    for address in &config.listen {
        eprintln!("listening on {address} (UDP/TCP)");
    }
    tokio::select! {
        result = server.block_until_done() => result.context("DNS server stopped"),
        result = shutdown_signal() => {
            result?;
            tokio::time::timeout(Duration::from_secs(5), server.shutdown_gracefully()).await.context("DNS shutdown timed out")??;
            Ok(())
        }
    }
}

async fn shutdown_signal() -> Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result?,
            _ = terminate.recv() => {},
        }
    }
    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await?;
    Ok(())
}
