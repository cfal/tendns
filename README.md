# tendns

A Rust DNS forwarder with ordinary UDP/TCP and DoH upstreams, encrypted TXT
discovery, and hexadecimal IPv4 names. Built on Hickory DNS.

## Build and run

Requires Rust 1.88 or newer and a C toolchain for AWS-LC.

```sh
CARGO_BUILD_JOBS=1 cargo build --release
target/release/tendns keygen
target/release/tendns --config tendns.toml serve
```

Use `tendns.example.toml` as the configuration reference. Set a fresh generated
key for each discovery domain. The example binds UDP and TCP on `0.0.0.0:5300`.
Port 53 may require elevated binding privileges. Keeping the listener internal
is the operator's responsibility; there is no access-control layer.

Use port 53 for clients whose resolver configuration cannot specify a port.
For a quick check of the example's listener:

```sh
dig @127.0.0.1 -p 5300 c0000201.hex.example.net A
dig @127.0.0.1 -p 5300 example.net A +tcp
```

Protect configuration files containing keys with appropriate filesystem
permissions, such as mode `0600`. `tendns.toml` is ignored by Git. Keys are
32 random bytes represented as unpadded base64url, not passwords.

## Generate TXT values

The `txt` command is offline: it loads the same config as the server, selects
the most-specific discovery domain containing `--name`, and prints one encrypted
TXT value. No running server, DNS lookup, or provider API is needed.
The examples below assume `tendns` is on PATH; otherwise use `target/release/tendns`.

```sh
tendns --config tendns.toml txt --name home.example.com \
  --a 192.0.2.1 --aaaa 2001:db8::1 --valid-for 24h
```

Publish the output as TXT at exactly `home.example.com`. A client using tendns
can then query `home.example.com` for A or AAAA. `--a` and `--aaaa` are repeatable.
The configured `valid_for` supplies the default validity when the flag is absent.

For a hidden child name:

```sh
tendns --config tendns.toml txt --name example.com \
  --subdomain nas --a 192.0.2.10
```

Publish at `example.com`, not `nas.example.com`. The server answers A queries
for `nas.example.com` using that parent record without querying the child name
upstream when the parent entry is present and valid.

For multiple names in one publication:

```sh
tendns --config tendns.toml txt --name example.com \
  --entry '@:A:192.0.2.1' \
  --entry 'nas:AAAA:2001:db8::1' \
  --entry 'www:CNAME:target.example.net.'
```

`--entry` is repeatable and uses `LABEL:TYPE:VALUE`; `@` selects the public TXT
owner. Labels contain at most 63 ASCII letters/digits/hyphens, not dots.
Internationalized names must use Punycode. `--cname target.example.net` is a
shortcut for an alias at the owner or the current `--subdomain`. An alias cannot
coexist with another entry at the same resulting hostname.

The value begins `td1.` and uses AES-256-GCM-SIV with a fresh random IV and an
authentication tag. It is bound to the public TXT owner: moving it to a different
name will not work. The CLI prints only the value on stdout; errors use stderr.
Values longer than 255 bytes must be split into adjacent character-strings
within **one** TXT record, with no inserted spaces in the data. Do not publish
the fragments as separate records. The server concatenates strings per RR.

## Lookup behavior

For a discovery query such as `a.example.com`, tendns first checks TXT at its
immediate parent for a hidden `a` entry, then checks TXT at the queried name for
an entry without a subdomain. Parent entries win, including when they lack the
requested address family. Only one hidden label is supported. Parent lookup
does not cross the selected discovery domain's boundary.

A timeout, invalid ciphertext, unsupported encrypted version, or expired
publication is an error, not permission to try the child. Confirmed absence
does permit a direct TXT lookup, which exposes the queried name upstream. For
both locations, absence produces NXDOMAIN; an existing name without the
requested type produces NODATA. There is no fallback to plaintext A/AAAA inside
a discovery domain. CNAME targets are followed with loop/depth bounds.
An owner containing only hidden children, and the hex-zone apex, return NODATA
rather than NXDOMAIN so downstream caches do not suppress their children.

Multiple encrypted TXT values contribute independent entries. Duplicate entries
are deduplicated; CNAME/address conflicts at the same hostname are errors.
Publish independent `td1.` values as separate TXT records, not strings within one RR.
Timestamps validate freshness, not replacement order. Replace or remove old TXT
values explicitly when updating. An invalid or expired encrypted value fails the
lookup, including when other values are valid: it might contain the hidden label
being queried. Publication is manual; regenerate and republish before expiry,
including when addresses are unchanged.

For a configured hex zone, `c0000201.hex.example.net` resolves to `192.0.2.1`.
Exactly one eight-character ASCII hexadecimal label is accepted, including
uppercase. All IPv4 addresses are permitted, including private and loopback
addresses. AAAA and other unsupported types return NODATA; invalid names within
the zone return NXDOMAIN. Hex and discovery zones cannot overlap.

Names outside configured zones are forwarded. Plain upstreams use UDP with TCP
fallback. DoH uses certificate-verified HTTPS/HTTP2 with explicit bootstrap IPs,
so starting the proxy does not depend on the system DNS resolver. Upstreams are
tried in configured order. Plain fallback exists only when explicitly configured.
Transfers, updates, TSIG, and multi-question requests are not supported.

Discovery caching is bounded and never extends the source TTL or authenticated
expiry. Concurrent requests for the same cached owner share a fetch. Generic
forwarding uses upstream caches rather than adding another response cache.
Synthetic answers do not assert DNSSEC validation. Operators using downstream
DNSSEC validation must configure the local namespaces accordingly.

## Security limits

Internal clients receive plaintext addresses through ordinary DNS. Anyone with
the configured key can decrypt and create publications for its domain. Public
TXT owners, query patterns, ciphertext sizes, and update timing remain visible.
Hex labels directly disclose the encoded address. Service authentication and
network access control remain separate from discovery.

There is no persistent replay state. Authentic older values may be accepted
until expiry; a reasonably correct clock is required. SIV is a safety net against
accidental nonce reuse, not replay protection. Removing a TXT record does not
erase addresses clients already learned. Configuration keys are separate from
provider API credentials; tendns does not need provider credentials.

## Check

```sh
CARGO_BUILD_JOBS=1 cargo test --all-targets
CARGO_BUILD_JOBS=1 cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

Tests use local DNS and HTTPS fixtures; they do not require a public resolver.
The server exits gracefully on SIGINT or SIGTERM.
