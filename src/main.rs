use std::env;

use anyhow::Result;
use argh::FromArgs;
use serde::Deserialize;
use ureq::json;

#[derive(FromArgs)]
#[argh(description = "One required flags: the domain to modify.")]
struct Args {
    #[argh(option, short = 's', description = "the domain to modify")]
    domain: String,
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
            if entry.name == "@" && entry.r#type == "A" && state.ip != entry.content {
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
    cookie: String,
}

fn main() -> Result<()> {
    let user = env::var("HOVER_USERNAME")?;
    let pass = env::var("HOVER_PASSWORD")?;
    let args: Args = argh::from_env();

    let ip = ureq::get("http://icanhazip.com").call().into_string()?;

    let resp = ureq::post("https://www.hover.com/api/login")
        .set("Accept", "application/json")
        .send_json(json!({
          "username": user,
          "password": pass
        }));

    let auth_cookie: Vec<&str> = resp
        .header("Set-Cookie")
        .expect("Cookie value")
        .split(";")
        .collect();

    let state = State {
        ip: ip.trim().to_string(),
        domain: args.domain,
        cookie: auth_cookie[0].to_string(),
    };

    let url = format!("https://www.hover.com/api/domains/{}/dns", state.domain);
    let domains: Overview = ureq::get(&url)
        .set("Cookie", &state.cookie)
        .call()
        .into_json_deserialize()?;

    domains.compare(&state);

    Ok(())
}
