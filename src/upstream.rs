//! Application-provided DNS transport.

use anyhow::{Context, Result};
use async_trait::async_trait;
use hickory_proto::op::Message;
use tokio::time::Instant;

use crate::deadline;

#[cfg(feature = "cli")]
mod forwarder;
/// Built-in UDP/TCP/DoH transport (requires the default `cli` feature).
#[cfg(feature = "cli")]
pub use forwarder::Forwarder;

/// Exchanges raw DNS messages without re-entering tendns namespace handling.
///
/// Implementations must associate responses with their requests, and retry
/// truncated UDP responses over a reliable transport before returning them.
/// Return complete DNS messages, preserving RCODE, TTLs, TXT record/chunk
/// boundaries, and negative-answer SOA records. NXDOMAIN is a response, not a
/// transport error. Discovery reads only exact-owner IN TXT answers, not
/// additionals; wrong response association can look like absence and cause a
/// direct-owner query that discloses a hidden child label.
///
/// Calls may be concurrent. Caller cancellation or deadline expiry can drop the
/// future; implementations must keep transport resources cancellation-safe.
#[async_trait]
pub trait Exchange: Send + Sync {
    /// Performs one raw exchange, including transport-specific validation and retries.
    async fn exchange(&self, message: Message) -> Result<Message>;

    /// Uses the caller's absolute deadline, rather than restarting a timeout for
    /// each TXT owner or CNAME. Override when the underlying resolver supports it.
    /// The default uses Tokio time and returns an error containing
    /// [`crate::TimeoutError`] on expiry. Overrides must honor the same deadline.
    async fn exchange_with_deadline(&self, message: Message, deadline: Instant) -> Result<Message> {
        deadline::timeout_at(deadline, async { self.exchange(message).await })
            .await
            .context("DNS exchange timed out")?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::pending, time::Duration};

    struct PendingExchange;

    #[async_trait]
    impl Exchange for PendingExchange {
        async fn exchange(&self, _: Message) -> Result<Message> {
            pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn default_exchange_enforces_the_callers_deadline() {
        let deadline = Instant::now() + Duration::from_secs(2);
        let error = PendingExchange
            .exchange_with_deadline(Message::query(), deadline)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS exchange timed out");
        assert!(error.is::<crate::TimeoutError>());
        assert_eq!(Instant::now(), deadline);
    }

    #[tokio::test(start_paused = true)]
    async fn default_exchange_does_not_poll_work_after_its_deadline() {
        struct UnusedExchange;

        #[async_trait]
        impl Exchange for UnusedExchange {
            async fn exchange(&self, _: Message) -> Result<Message> {
                panic!("expired deadline must not poll the exchange");
            }
        }

        let error = UnusedExchange
            .exchange_with_deadline(Message::query(), Instant::now())
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "DNS exchange timed out");
        assert!(error.is::<crate::TimeoutError>());
    }
}
