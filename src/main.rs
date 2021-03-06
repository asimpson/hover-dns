use std::env;
use std::net::{IpAddr, Ipv4Addr};

use anyhow::{anyhow, Result};
use argh::FromArgs;
use serde::Deserialize;
use trust_dns_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use trust_dns_resolver::Resolver;
use ureq::{json, Response};

#[derive(FromArgs, Debug)]
#[argh(description = "hover-dns: dynamic dns for hover.com domains")]
struct Args {
    #[argh(subcommand)]
    commands: Commands,
}

#[derive(FromArgs, Debug)]
#[argh(subcommand)]
enum Commands {
    Update(Update),
    Ip(Ip),
}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    description = "Convenience command to return public IP",
    name = "ip"
)]
pub struct Ip {}

#[derive(FromArgs, Debug)]
#[argh(
    subcommand,
    description = "Set a domain hosted on hover.com to your public IP address.",
    name = "update"
)]
pub struct Update {
    #[argh(option, short = 'd', description = "the domain to modify")]
    domain: String,
    #[argh(
        option,
        short = 's',
        description = "the subdomain to modify",
        default = "String::from(\"@\")"
    )]
    subdomain: String,
}

#[derive(Deserialize, Debug)]
struct Overview {
    domains: Vec<Domain>,
}

#[derive(Deserialize, Debug)]
struct Domain {
    domain_name: String,
    entries: Vec<Entry>,
    id: String,
}

#[derive(Deserialize, Debug)]
struct Entry {
    content: String,
    id: String,
    name: String,
    r#type: String,
}

impl Overview {
    fn compare(&self, state: &State) {
        for entry in self.domains[0].entries.iter() {
            if entry.name == state.subdomain && entry.r#type == "A" && state.ip != entry.content {
                self.update(&entry.id, state);
            }
        }
    }

    fn update(&self, id: &str, state: &State) {
        let put_req = ureq::put("https://www.hover.com/api/control_panel/dns")
            .set("Cookie", &state.cookie)
            .send_json(json!({
              "domain": {
                "dns_records": [{
                  "id": id,
                }],
                "id": format!("domain-{}", state.domain)
              },
              "fields": {
                "content": state.ip
              }
            }));

        println!("{:?}: {:?}", put_req.status(), put_req.into_json());
    }
}

#[derive(Debug)]
struct State {
    ip: String,
    domain: String,
    subdomain: String,
    cookie: String,
}

fn lookup_ip() -> Result<String> {
    let opendns = NameServerConfigGroup::from_ips_clear(
        &[
            IpAddr::V4(Ipv4Addr::new(208, 67, 222, 222)),
            IpAddr::V4(Ipv4Addr::new(208, 67, 220, 220)),
        ],
        53,
    );
    let resolver_config = ResolverConfig::from_parts(None, vec![], opendns);
    let resolver = Resolver::new(resolver_config, ResolverOpts::default())?;
    let resolver_result = resolver.lookup_ip("myip.opendns.com")?;
    let ipv4 = resolver_result.iter().next();

    match ipv4 {
        Some(x) => Ok(x.to_string()),
        None => Err(anyhow!("Public IP lookup failed.")),
    }
}

fn parse_cookie(response: &Response) -> Result<String> {
    match response.header("Set-Cookie") {
        Some(cookie) => {
            let auth_cookie: Vec<&str> = cookie.split(';').collect();
            Ok(auth_cookie[0].to_string())
        }
        None => Err(anyhow!("Failed to get cookies from hover.")),
    }
}

fn get_dns(domain: String, subdomain: String) -> Result<()> {
    let resp = ureq::post("https://www.hover.com/api/login")
        .set("Accept", "application/json")
        .send_json(json!({
          "username": env::var("HOVER_USERNAME")?,
          "password": env::var("HOVER_PASSWORD")?
        }));

    let state = State {
        ip: lookup_ip()?,
        cookie: parse_cookie(&resp)?,
        domain,
        subdomain,
    };

    let url = format!("https://www.hover.com/api/domains/{}/dns", state.domain);
    let domains: Overview = ureq::get(&url)
        .set("Cookie", &state.cookie)
        .call()
        .into_json_deserialize()?;

    domains.compare(&state);
    Ok(())
}

fn main() -> Result<()> {
    let args: Args = argh::from_env();

    match args.commands {
        Commands::Update(x) => {
            if let Err(e) = get_dns(x.domain, x.subdomain) {
                println!("{}", e)
            }
        }
        Commands::Ip(_) => println!("{}", lookup_ip()?),
    }

    Ok(())
}
