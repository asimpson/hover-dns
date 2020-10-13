use std::env;

use anyhow::Result;
use argh::FromArgs;
use serde::Deserialize;
use ureq::json;

#[derive(FromArgs)]
#[argh(description = "Specify domain to check")]
struct Args {
    #[argh(option, short = 's', description = "domain to check")]
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

fn get_existing_a_record(cookie: &str, domain: &str) -> Result<String> {
    let url = format!("https://www.hover.com/api/domains/{}/dns", domain);
    let anet = ureq::get(&url).set("Cookie", cookie).call();

    let info = anet.into_json_deserialize::<Overview>()?;
    let name = &info.domains[0].domain_name;
    return Ok(name.to_string());
}

fn main() -> Result<()> {
    let user = env::var("HOVER_USERNAME")?;
    let pass = env::var("HOVER_PASSWORD")?;
    let args: Args = argh::from_env();

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

    let a_record = get_existing_a_record(auth_cookie[0], &args.domain)?;

    println!("{:?}", a_record);

    Ok(())
}
