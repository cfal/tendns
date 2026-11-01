//! Encrypted TXT discovery and hexadecimal IPv4 resolution.
//!
//! Disable default features to embed the resolver without the CLI, HTTP servers,
//! Cloudflare client, or built-in network transport. Supply an [`Exchange`]
//! implementation backed by the application's existing DNS resolver.
//! The core still needs Tokio (with a time driver) and AWS-LC's C toolchain.
//! Use the re-exported [`hickory_proto`] to match the DNS types in this API.
//!
//! # Embedding
//!
//! This adapter wraps an async raw-DNS callback. That callback must satisfy the
//! full [`Exchange`] contract, including response association, reliable fallback
//! after UDP truncation, and bypassing this wrapper for internal TXT lookups.
//! The example uses `anyhow`, `async-trait`, and Tokio in addition to tendns.
//!
//! ```
//! use std::{future::Future, net::IpAddr, sync::Arc, time::Duration};
//! use async_trait::async_trait;
//! use tendns::{Discovery, Exchange, IpStrategy, Policy, Resolver};
//! use tendns::{names::canonical_name, protocol::Secret};
//! use tendns::hickory_proto::{op::Message, rr::Name};
//! use tokio::time::Instant;
//!
//! struct RawDns<F>(F);
//!
//! #[async_trait]
//! impl<F, Fut> Exchange for RawDns<F>
//! where
//!     F: Fn(Message) -> Fut + Send + Sync,
//!     Fut: Future<Output = anyhow::Result<Message>> + Send,
//! {
//!     async fn exchange(&self, request: Message) -> anyhow::Result<Message> {
//!         (self.0)(request).await
//!     }
//! }
//!
//! fn make_resolver(upstream: Arc<dyn Exchange>, encoded_key: &str)
//!     -> anyhow::Result<Resolver>
//! {
//!     let policy = Policy::new(
//!         vec![Discovery {
//!             domain: canonical_name("example.com")?,
//!             key: Arc::new(Secret::decode(encoded_key)?),
//!         }],
//!         vec![canonical_name("hex.internal")?],
//!         60,
//!         1024,
//!     )?;
//!     Ok(Resolver::new(Arc::new(policy), upstream))
//! }
//!
//! async fn lookup<F, Fut>(resolver: &Resolver, name: Name, native: F)
//!     -> anyhow::Result<Vec<IpAddr>>
//! where
//!     F: FnOnce(Name, Instant) -> Fut,
//!     Fut: Future<Output = anyhow::Result<Vec<IpAddr>>>,
//! {
//!     let deadline = Instant::now() + Duration::from_secs(5);
//!     resolver.lookup_ip(name, IpStrategy::Ipv4AndIpv6, deadline, native).await
//! }
//! # fn main() -> anyhow::Result<()> {
//! # tokio::runtime::Builder::new_current_thread().enable_time().build()?.block_on(async {
//! # let upstream = Arc::new(RawDns(|_: Message| async {
//! #     anyhow::bail!("hex and public fallback must not fetch TXT")
//! # }));
//! # let resolver = make_resolver(upstream, &Secret::generate()?)?;
//! # let ips = lookup(&resolver, canonical_name("0a14001e.hex.internal")?, |_, _| async {
//! #     anyhow::bail!("hex lookup must not use native fallback")
//! # }).await?;
//! # assert_eq!(ips, vec!["10.20.0.30".parse::<IpAddr>()?]);
//! # let ips = lookup(&resolver, canonical_name("public.example.net")?, |name, deadline| async move {
//! #     assert_eq!(name.to_ascii(), "public.example.net.");
//! #     assert!(deadline > Instant::now());
//! #     Ok(vec!["192.0.2.1".parse()?])
//! # }).await?;
//! # assert_eq!(ips, vec!["192.0.2.1".parse::<IpAddr>()?]);
//! # Ok::<_, anyhow::Error>(())
//! # })
//! # }
//! ```
//!
//! Create `RawDns(your_raw_exchange_callback)` once, retain the resolver, and pass
//! your native address resolver to `lookup`. Native fallback receives only an
//! unclaimed name, at most once, never a private miss or authentication failure.
//! For strict namespace protection, use absolute names and prevent native
//! search/alias expansion into protected namespaces. Do not add a fixed-lifetime
//! cache around address results: they have no TTL and could outlive publication
//! expiry. Admission limits and destination filtering belong to the host.
//!
//! [`LookupError`] distinguishes missing names from absent address families;
//! [`TimeoutError`] identifies tendns-enforced deadline expiry. Both can be
//! inspected through `anyhow::Error::downcast_ref`. Other errors include tendns
//! authentication, format, expiry, and alias failures, plus transport/application
//! errors. Packet-serving callers instead use
//! [`Resolver::answer_with_deadline`] with [`resolver::validate_request`].

/// Cloudflare publication management (requires the default `cli` feature).
#[cfg(feature = "cli")]
pub mod cloudflare;
/// Standalone TOML configuration (requires the default `cli` feature).
#[cfg(feature = "cli")]
pub mod config;
mod deadline;
pub mod names;
pub mod policy;
pub mod protocol;
pub mod resolver;
/// Standalone listeners and request admission (requires the default `cli` feature).
#[cfg(feature = "cli")]
pub mod server;
pub mod upstream;

pub use deadline::TimeoutError;
pub use hickory_proto;
pub use policy::{Discovery, Policy};
pub use resolver::{IpStrategy, LookupError, Resolver};
pub use upstream::Exchange;
