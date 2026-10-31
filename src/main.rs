use std::{
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Parser, Subcommand};
use tendns::{
    config::Config,
    names::{canonical_name, validate_label},
    protocol::{self, Entry, Publication, Secret, Value},
    resolver::{Clock, SystemClock},
};

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[arg(long, global = true, default_value = "tendns.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve ordinary DNS over UDP and TCP.
    Serve,
    /// Generate an encrypted TXT value without making network requests.
    Txt(TxtArgs),
    /// Generate a random base64url discovery key for the TOML configuration.
    Keygen,
}

#[derive(Args)]
struct TxtArgs {
    /// Public TXT owner name; authenticated and bound to this publication.
    #[arg(long)]
    name: String,
    /// Optional hidden single-label prefix for --a, --aaaa, and --cname.
    #[arg(long, default_value = "")]
    subdomain: String,
    #[arg(long, action = clap::ArgAction::Append)]
    a: Vec<Ipv4Addr>,
    #[arg(long, action = clap::ArgAction::Append)]
    aaaa: Vec<Ipv6Addr>,
    #[arg(long)]
    cname: Option<String>,
    /// Repeatable LABEL:TYPE:VALUE entry; use @ for the TXT owner.
    #[arg(long = "entry", value_name = "LABEL:TYPE:VALUE")]
    entries: Vec<String>,
    /// Validity duration, for example 24h or 7days; defaults to the config.
    #[arg(long)]
    valid_for: Option<String>,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(error) = run(Cli::parse()).await {
        eprintln!("error: {error:#}");
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Serve => {
            let config = Config::load(&cli.config)?;
            tendns::server::serve(config).await?;
        }
        Command::Txt(args) => {
            let config = Config::load(&cli.config)?;
            println!("{}", generate_txt(&config, args)?);
        }
        Command::Keygen => println!("{}", Secret::generate()?),
    }
    Ok(())
}

fn generate_txt(config: &Config, args: TxtArgs) -> Result<String> {
    let owner = canonical_name(&args.name)?;
    let discovery = config
        .discovery_for(&owner)
        .context("TXT owner is not within a configured discovery domain")?;
    let subdomain = args.subdomain.to_ascii_lowercase();
    if !subdomain.is_empty() {
        validate_label(&subdomain)?;
    }
    let mut entries = Vec::new();
    for ip in args.a {
        entries.push(Entry {
            subdomain: subdomain.clone(),
            value: Value::A(ip),
        });
    }
    for ip in args.aaaa {
        entries.push(Entry {
            subdomain: subdomain.clone(),
            value: Value::Aaaa(ip),
        });
    }
    if let Some(target) = args.cname {
        entries.push(Entry {
            subdomain,
            value: Value::Cname(canonical_name(&target)?),
        });
    }
    for entry in args.entries {
        entries.push(parse_entry(&entry)?);
    }
    let validity = match args.valid_for {
        Some(value) => humantime::parse_duration(&value).context("invalid --valid-for duration")?,
        None => config.valid_for,
    };
    ensure!(
        validity.as_secs() > 0,
        "validity must be at least one second"
    );
    let issued_at = SystemClock.now()?;
    let expires_at = issued_at
        .checked_add(validity.as_secs())
        .context("expiry overflows timestamp")?;
    let publication = Publication {
        issued_at,
        expires_at,
        entries,
    };
    protocol::encrypt(&publication, &discovery.key, &owner)
}

fn parse_entry(text: &str) -> Result<Entry> {
    let mut parts = text.splitn(3, ':');
    let label = parts.next().context("missing entry label")?;
    let kind = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let value = parts.next().context("entry must be LABEL:TYPE:VALUE")?;
    let subdomain = if label == "@" {
        String::new()
    } else {
        validate_label(label)?;
        label.to_ascii_lowercase()
    };
    let value = match kind.to_ascii_uppercase().as_str() {
        "A" => Value::A(value.parse().context("invalid A address")?),
        "AAAA" => Value::Aaaa(value.parse().context("invalid AAAA address")?),
        "CNAME" => Value::Cname(canonical_name(value)?),
        _ => bail!("entry type must be A, AAAA, or CNAME"),
    };
    Ok(Entry { subdomain, value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_syntax_handles_ipv6_and_relative_labels() {
        assert_eq!(
            parse_entry("NAS:AAAA:2001:db8::1").unwrap(),
            Entry {
                subdomain: "nas".into(),
                value: Value::Aaaa("2001:db8::1".parse().unwrap())
            }
        );
        assert_eq!(parse_entry("@:A:192.0.2.1").unwrap().subdomain, "");
        for entry in ["a.b:A:192.0.2.1", "nas:MX:x", "A:192.0.2.1", ":A:192.0.2.1"] {
            assert!(parse_entry(entry).is_err());
        }
    }
}
