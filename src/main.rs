use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use config::FileFormat;
use directories::ProjectDirs;
use hamsando::{
    domain::{Domain, Root},
    record::{Content, Record, Type},
    Client,
};
use itertools::Itertools;
use log::{debug, info, warn, LevelFilter};
use pnet::{
    datalink::{self, NetworkInterface},
    ipnetwork::IpNetwork,
};
use serde::Deserialize;
use strum_macros::IntoStaticStr;
use url::Url;

#[derive(Deserialize)]
struct ApiConfig {
    endpoint: Option<Url>,
    apikey: String,
    secretapikey: String,
}

#[derive(Deserialize)]
struct IpConfig {
    ip_oracle: Url,
}

#[derive(Debug, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
enum Ipv4Scope {
    Private,
    Public,
}

impl Ipv4Scope {
    fn as_str(&self) -> &'static str {
        self.into()
    }
}

#[derive(Debug, Deserialize)]
struct DomainConfig {
    name: Box<Domain>,
    ipv4: Option<Ipv4Scope>,
    #[serde(default)]
    ipv6: bool,
}

#[derive(Deserialize)]
struct Config {
    api: ApiConfig,
    #[serde(default = "default_ip_config")]
    ip: IpConfig,
    domains: Vec<DomainConfig>,
}

fn default_ip_config() -> IpConfig {
    IpConfig {
        ip_oracle: "https://api.ipify.org/"
            .parse()
            .expect("unable to parse the default IP oracle"),
    }
}

fn ipv4_is_eligible(ip: Ipv4Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_link_local()
        && !ip.is_documentation()
        && !ip.is_broadcast()
}

fn ipv6_is_eligible(ip: Ipv6Addr) -> bool {
    !ip.is_unspecified()
        && !ip.is_loopback()
        && !ip.is_unique_local()
        && !ip.is_unicast_link_local()
}

fn get_ipv4_private(interfaces: &[NetworkInterface]) -> Result<Ipv4Addr> {
    interfaces
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .flat_map(|i| i.ips.iter())
        .find_map(|ip| match ip {
            IpNetwork::V4(ip) if ipv4_is_eligible(ip.ip()) => Some(ip.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no IPv4 address found"))
}

fn get_ipv4_public(ip_oracle: Url) -> Result<Ipv4Addr> {
    Ok(reqwest::blocking::get(ip_oracle)?
        .error_for_status()?
        .text()?
        .trim()
        .parse()?)
}

fn get_ipv6(interfaces: &[NetworkInterface]) -> Result<Ipv6Addr> {
    interfaces
        .iter()
        .filter(|i| i.is_up() && !i.is_loopback() && !i.ips.is_empty())
        .flat_map(|i| i.ips.iter())
        .find_map(|ip| match ip {
            IpNetwork::V6(ip) if ipv6_is_eligible(ip.ip()) => Some(ip.ip()),
            _ => None,
        })
        .ok_or_else(|| anyhow!("no IPv6 address found"))
}

fn update_dns(
    client: &Client,
    entries: &HashMap<&Root, Vec<Record>>,
    domain: &Domain,
    content: &Content,
) -> Result<()> {
    let dns: Vec<&Record> = entries[domain.root()]
        .iter()
        .filter(|record| {
            record.name.as_ref() == domain && Type::from(&record.content) == Type::from(content)
        })
        .collect();
    match dns.len().cmp(&1) {
        Ordering::Less => {
            client.create_dns(&domain, content, None, None)?;
            info!("successfully created DNS record");
        }
        Ordering::Equal => {
            if dns[0].content == *content {
                info!("DNS record already set");
                return Ok(());
            }
            client.edit_dns(&domain, dns[0].id, content, None, None)?;
            info!("successfully updated DNS record");
        }
        Ordering::Greater => bail!("multiple DNS records for domain {}", domain.as_str()),
    }
    Ok(())
}

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Set a custom config file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Control the logging level
    #[arg(short, action = clap::ArgAction::Count)]
    verbosity: u8,
}

fn init_logger(level: LevelFilter) -> Result<()> {
    #[cfg(not(any(feature = "env_logger", feature = "syslog")))]
    compile_error!("no logger selected");
    #[cfg(all(feature = "env_logger", feature = "syslog"))]
    compile_error!("more than 1 logger selected");

    #[cfg(feature = "env_logger")]
    env_logger::builder()
        .filter_level(level)
        .parse_default_env()
        .init();

    #[cfg(feature = "syslog")]
    syslog::init_unix(syslog::Facility::LOG_USER, level)?;

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let log_level = match cli.verbosity {
        0 => LevelFilter::Error,
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    };

    init_logger(log_level)?;

    let config_file = match cli.config {
        Some(config) => config,
        None => {
            let project_dirs = ProjectDirs::from("", "", "hamsando")
                .ok_or_else(|| anyhow!("unable to find home directory"))?;
            project_dirs.config_dir().join("config.toml")
        }
    };

    debug!(
        "loading configuration from {:?} and environment",
        config_file.display()
    );

    let config = config::Config::builder()
        .add_source(config::File::new(
            config_file
                .to_str()
                .ok_or_else(|| anyhow!("config file path is not valid UTF-8"))?,
            FileFormat::Toml,
        ))
        .add_source(config::Environment::with_prefix("HAMSANDO"))
        .build()?;

    let config: Config = config.try_deserialize()?;

    let client = Client::builder()
        .apikey(&config.api.apikey)
        .secretapikey(&config.api.secretapikey)
        .endpoint_if_some(config.api.endpoint.as_ref())
        .build()?;
    client.test_auth()?;
    info!("successfully authenticated");

    let interfaces = datalink::interfaces();

    let ipv4_private = get_ipv4_private(&interfaces);
    if let Ok(ip) = ipv4_private {
        info!("private IPv4 address found: {ip}");
    };
    let ipv4_public = get_ipv4_public(config.ip.ip_oracle);
    if let Ok(ip) = ipv4_public {
        info!("public IPv4 address found: {ip}");
    };
    let ipv6 = get_ipv6(&interfaces);
    if let Ok(ip) = ipv6 {
        info!("IPv6 address found: {ip}");
    };

    let domains: Vec<&DomainConfig> = config.domains.iter().unique_by(|d| &d.name).collect();

    let entries: HashMap<&Root, Vec<Record>> = domains
        .iter()
        .unique_by(|d| d.name.root())
        .filter_map(|d| {
            let records = match client.retrieve_dns(d.name.root(), None) {
                Ok(records) => records,
                Err(e) => {
                    warn!(
                        "unable to retrieve records for domain name {}: {e}",
                        d.name.root()
                    );
                    return None;
                }
            };
            Some((d.name.root(), records))
        })
        .collect();

    for domain in domains.iter() {
        if let Some(scope) = &domain.ipv4 {
            info!(
                "updating IPv4 to {} IP for domain {}",
                scope.as_str(),
                domain.name
            );
            let ipv4 = match scope {
                Ipv4Scope::Private => &ipv4_private,
                Ipv4Scope::Public => &ipv4_public,
            };
            match ipv4 {
                Ok(ipv4) => {
                    if let Err(e) = update_dns(&client, &entries, &domain.name, &Content::A(*ipv4))
                    {
                        warn!("updating A record for {} failed: {e}", domain.name);
                    }
                }
                Err(e) => {
                    warn!("unable to update IPv4: {e}");
                }
            };
        }

        if domain.ipv6 {
            info!("updating IPv6 for domain {}", domain.name);
            match &ipv6 {
                Ok(ipv6) => {
                    if let Err(e) =
                        update_dns(&client, &entries, &domain.name, &Content::Aaaa(*ipv6))
                    {
                        warn!("updating AAAA record for {} failed: {e}", domain.name);
                    }
                }
                Err(e) => {
                    warn!("unable to update IPv6: {e}");
                }
            };
        }
    }

    Ok(())
}
