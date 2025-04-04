use std::{
    cmp::Ordering,
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
};

use addr::{domain, parse_domain_name};
use anyhow::{anyhow, bail, Result};
use config::FileFormat;
use directories::ProjectDirs;
use itertools::Itertools;
use log::{debug, info, warn, LevelFilter};
use serde::Deserialize;
use strum_macros::IntoStaticStr;
use url::Url;

use hamsando::{
    record::{Content, Record, Type},
    Client,
};

#[derive(Deserialize)]
struct ApiConfig {
    endpoint: Option<Url>,
    apikey: String,
    secretapikey: String,
}

#[derive(Deserialize)]
struct IpConfig {
    device: String,
    #[serde(default = "default_ip_oracle")]
    ip_oracle: Url,
}

fn default_ip_oracle() -> Url {
    "https://api.ipify.org/"
        .parse()
        .expect("unable to parse the default IP oracle")
}

#[derive(Debug, Deserialize, IntoStaticStr)]
#[serde(rename_all = "lowercase")]
#[strum(serialize_all = "lowercase")]
enum Ipv4Scope {
    Private,
    Public,
}

#[derive(Debug, Deserialize)]
struct DomainConfig {
    name: String,
    ipv4: Option<Ipv4Scope>,
    #[serde(default)]
    ipv6: bool,
}

#[derive(Deserialize)]
struct Config {
    api: ApiConfig,
    ip: IpConfig,
    domains: Vec<DomainConfig>,
}

enum IpVersion {
    Ipv4,
    Ipv6,
}

fn run_ip_command(device: &str, ip_version: &IpVersion) -> Result<String> {
    let ip_version_arg = match ip_version {
        IpVersion::Ipv4 => "-4",
        IpVersion::Ipv6 => "-6",
    };
    let ip_output = Command::new("ip")
        .arg(ip_version_arg)
        .arg("-o")
        .arg("address")
        .arg("show")
        .arg("scope")
        .arg("global")
        .arg("dev")
        .arg(device)
        .output()?;

    let ip_output = String::from_utf8(ip_output.stdout)?;

    let first_line = ip_output
        .lines()
        .next()
        .ok_or(anyhow!("empty output from ip command"))?;

    let ip_with_subnet = first_line
        .split_whitespace()
        .nth(3)
        .ok_or(anyhow!("nothing found at expected position"))?;

    let ip = ip_with_subnet
        .split('/')
        .next()
        .ok_or(anyhow!("malformed IP with subnet: {ip_with_subnet:?}"))?;
    Ok(ip.to_string())
}

fn get_ipv4_private(device: &str) -> Result<Ipv4Addr> {
    let ip = run_ip_command(device, &IpVersion::Ipv4)?;
    Ok(ip.parse()?)
}

fn get_ipv4_public(ip_oracle: Url) -> Result<Ipv4Addr> {
    Ok(reqwest::blocking::get(ip_oracle)?
        .error_for_status()?
        .text()?
        .trim()
        .parse()?)
}

fn get_ipv6(device: &str) -> Result<Ipv6Addr> {
    let ip = run_ip_command(device, &IpVersion::Ipv6)?;
    Ok(ip.parse()?)
}

fn update_dns(
    client: &Client,
    entries: &HashMap<&str, Vec<Record>>,
    domain: &domain::Name,
    content: &Content,
) -> Result<()> {
    let root = domain
        .root()
        .ok_or(anyhow!("domain name {domain} has no root"))?;
    let dns: Vec<&Record> = entries[root]
        .iter()
        .filter(|record| {
            record.name == domain.as_str() && Type::from(&record.content) == Type::from(&content)
        })
        .collect();
    Ok(match dns.len().cmp(&1) {
        Ordering::Less => client.create_dns(domain, content, None, None).map(|_| ())?,
        Ordering::Equal => {
            if dns[0].content == *content {
                return Ok(());
            }
            client.edit_dns(domain, dns[0].id, content, None, None)?
        }
        Ordering::Greater => bail!("multiple DNS records for domain {domain}"),
    })
}

#[derive(Debug)]
struct DomainInfo<'a> {
    config: &'a DomainConfig,
    name: domain::Name<'a>,
    root: domain::Name<'a>,
}

fn main() -> Result<()> {
    env_logger::builder()
        .filter_level(LevelFilter::max())
        .parse_default_env()
        .init();

    let project_dirs =
        ProjectDirs::from("", "", "hamsando").ok_or(anyhow!("unable to find home directory"))?;
    let config_file = project_dirs.config_dir().join("config.toml");

    debug!(
        "loading configuration from {:?} and environment",
        config_file.display()
    );

    let config = config::Config::builder()
        .add_source(config::File::new(
            config_file
                .to_str()
                .ok_or(anyhow!("config file path is not valid UTF-8"))?,
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

    let ipv4_private = get_ipv4_private(&config.ip.device);
    let ipv4_public = get_ipv4_public(config.ip.ip_oracle);
    let ipv6 = get_ipv6(&config.ip.device);

    let domains: Vec<DomainInfo> = config
        .domains
        .iter()
        .filter_map(|config| {
            let name = match parse_domain_name(&config.name) {
                Ok(name) => name,
                Err(e) => {
                    warn!("unable to parse domain name {}: {e}", config.name);
                    return None;
                }
            };
            let root = match name.root() {
                Some(root) => root,
                None => {
                    warn!("domain name {name} has no root");
                    return None;
                }
            };
            let root = match parse_domain_name(root) {
                Ok(root) => root,
                Err(e) => {
                    warn!("unable to parse root {root}: {e}");
                    return None;
                }
            };

            Some(DomainInfo { config, name, root })
        })
        .unique_by(|info| info.name)
        .collect();

    let entries: HashMap<&str, Vec<Record>> = domains
        .iter()
        .unique_by(|info| info.root)
        .filter_map(|info| {
            let records = match client.retrieve_dns(&info.root, None) {
                Ok(records) => records,
                Err(e) => {
                    warn!(
                        "unable to retrieve records for domain name {}: {e}",
                        info.root
                    );
                    return None;
                }
            };
            Some((info.root.as_str(), records))
        })
        .collect();

    for domain in domains.iter() {
        if let Some(scope) = &domain.config.ipv4 {
            info!(
                "updating IPv4 to {} IP for domain {}",
                Into::<&'static str>::into(scope),
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
                    };
                }
                Err(e) => {
                    warn!("unable to get IPv4: {e}");
                }
            };
        }

        if domain.config.ipv6 {
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
                    warn!("unable to get IPv6: {e}");
                }
            };
        }
    }

    Ok(())
}
