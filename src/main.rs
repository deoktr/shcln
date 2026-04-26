/*
 * Copyright 2025 Deoktr
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use std::env;
use std::error::Error;
use std::fmt;
use std::fs::{copy, remove_file, File};
use std::io::{prelude::*, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, OnceLock};

use clap::Parser;
use regex::Regex;

static MATCH_LIST: LazyLock<[Regex; 139]> = LazyLock::new(|| {
    [
        // targeted matches
        Regex::new(r#"echo (?:-e)?*["']?(.*)["']? *\| *sudo.*-S"#).unwrap(),
        Regex::new(r#"echo (?:-e)?*["']?(.*)["']? *\| *sudo.* passwd .*"#).unwrap(),
        Regex::new(r#"sudo.*-S.*<<< *(.*)"#).unwrap(),
        Regex::new(r#"docker.*--password-stdin"#).unwrap(),
        Regex::new(r"(?i)(?:aws_access_key_id|aws_secret_access_key)=([0-9a-zA-Z/+]{20,40})").unwrap(),
        Regex::new(r#"(?i:authorization):(?:.*)(?i:basic).(.*)("|'|\x60|\$\()"#).unwrap(),
        Regex::new(r"curl.*(?:-u|--user)(?:[ =])([^ ]*)").unwrap(),
        Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"(ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"ghr_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"glpat-[0-9a-zA-Z-_]{20}").unwrap(),
        Regex::new(r#"(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        Regex::new(r#""key-[0-9a-zA-Z]{32}""#).unwrap(), // MailGun API Key
        Regex::new(r"(?i)[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
        Regex::new(r"(SG.[0-9A-Za-z\-_]{15,30}\.[0-9A-Za-z\-_]{15,30})").unwrap(),
        Regex::new(r"(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})").unwrap(),
        Regex::new(r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{30,32})").unwrap(),
        Regex::new(r"https://hooks.slack.com/services/([A-Za-z0-9+/]{44,46})").unwrap(),
        Regex::new(r"(SK[0-9a-fA-F]{32})").unwrap(),
        // FIXME: wrongly detect ssh
        // Regex::new(r"(([A-Za-z]*:(?://)?)([-;:&=\+\$,\w]+)@[A-Za-z0-9.-]+(:[0-9]+)?|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:/[\+~%/.\w\-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?").unwrap(),
        Regex::new(r#"(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        Regex::new(r"https://outlook.office.com/webhook/([0-9a-f-]{36})/@").unwrap(),
        Regex::new(r"oy2[a-z0-9]{43}").unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{35,44})[''"]"#).unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{18,25})[''"]"#).unwrap(),
        Regex::new(r"wget(?:.*)--(?:ftp-|http-)?(?:password|user)[ =]([^ ]*)").unwrap(),
        Regex::new(r#"(?i)linkedin(.{0,20})?(?-i)[''"]([0-9a-zA-Z]{12,16})[''"]"#).unwrap(),
        Regex::new(r"(EAACEdEose0cBA[0-9A-Za-z]+)").unwrap(),
        Regex::new(r#"(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:\[s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|"|\n|\r|\s|\x60|;]|$)"#).unwrap(),
        Regex::new(r"diskutil.*passphrase ([[:alpha:][:punct:]]{1,200}).*").unwrap(),
        Regex::new(r#"AWS_ACCESS_KEY_ID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AWS_SECRET_ACCESS_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GITHUB_TOKEN=["']?([0-9a-zA-Z*_/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GITLAB_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"HEROKU_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VAULT_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CONSUL_HTTP_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VERCEL_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CLOUDFLARE_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"NEWRELIC_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"README_API_KEY=["']?([0-9a-zA-Z*/+]{0,100})["']?"#).unwrap(),
        Regex::new(r#"CARGO_REGISTRY_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AWS_ACCESS_KEY_ID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AWS_SECRET_ACCESS_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AMAZON_AWS_ACCESS_KEY_ID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AMAZON_AWS_SECRET_ACCESS_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"ALGOLIA_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AZURE_CLIENT_ID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AZURE_CLIENT_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AZURE_USERNAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"AZURE_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"MSI_ENDPOINT=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"MSI_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"binance_api=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"binance_secret=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"BITTREX_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"BITTREX_API_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CF_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CF_USERNAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CODECLIMATE_REPO_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"COVERALLS_REPO_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CIRCLE_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"DIGITALOCEAN_ACCESS_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"DOCKER_EMAIL=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"DOCKER_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"DOCKER_USERNAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"DOCKERHUB_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"ITC_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FACEBOOK_APP_ID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FACEBOOK_APP_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FACEBOOK_ACCESS_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FIREBASE_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FIREBASE_API_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"FOSSA_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GH_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GITHUB_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GH_ENTERPRISE_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GITHUB_ENTERPRISE_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_DEPLOY_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_DEPLOY_USER=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GOOGLE_APPLICATION_CREDENTIALS=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GOOGLE_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_DEPLOY_USER=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_DEPLOY_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"GITLAB_USER_LOGIN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_JOB_JWT=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_JOB_JWT_V2=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CI_JOB_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"HEROKU_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"HEROKU_API_USER=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"MAILGUN_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"MCLI_PRIVATE_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"MCLI_PUBLIC_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"NGROK_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"NGROK_AUTH_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"NPM_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"NPM_AUTH_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OKTA_CLIENT_ORGURL=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OKTA_CLIENT_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OKTA_OAUTH2_CLIENTSECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OKTA_OAUTH2_CLIENTID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OKTA_AUTHN_GROUPID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OS_USERNAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"OS_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"PERCY_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"POSTGRES_PASSWORD=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SAUCE_ACCESS_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SAUCE_USERNAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SENTRY_AUTH_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SLACK_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"square_access_token=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"square_oauth_secret=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"STRIPE_API_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"STRIPE_DEVICE_NAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SURGE_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"SURGE_LOGIN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TWILIO_ACCOUNT_SID=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TWILIO_AUTH_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CONSUMER_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"CONSUMER_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TRAVIS_SUDO=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TRAVIS_OS_NAME=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TRAVIS_SECURE_ENV_VARS=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"TELEGRAM_BOT_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VAULT_TOKEN=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VAULT_CLIENT_KEY=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VULTR_ACCESS=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        Regex::new(r#"VULTR_SECRET=["']?([0-9a-zA-Z*/+]{1,100})["']?"#).unwrap(),
        // non-targeted matches
        Regex::new(r" --?[0-9a-zA-Z_-]*pass(?:word)? *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*token[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*auth[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*key(?: +|=)([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*jwt[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*secret[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r"echo +(.*) *>.*(?:secret|pass|key|token|jwt)").unwrap(), // secret file creation
        // TODO: remove quotes from match group, note that rust regex doesn't
        // support look-around, and we need a single group, also cannot name
        // capture group
        Regex::new(r#"KEY[0-9a-zA-Z_-]*=('[^']+'|"[^"]+"|[^ ]+)"#).unwrap(),
        Regex::new(r#"SECRET[0-9a-zA-Z_-]*=('[^']+'|"[^"]+"|[^ ]+)"#).unwrap(),
        Regex::new(r#"TOKEN[0-9a-zA-Z_-]*=('[^']+'|"[^"]+"|[^ ]+)"#).unwrap(),
        Regex::new(r#"JWT[0-9a-zA-Z_-]*=('[^']+'|"[^"]+"|[^ ]+)"#).unwrap(),
    ]
});

static KEEP_TMP: OnceLock<bool> = OnceLock::new();

#[derive(Debug)]
struct ShclnError {
    message: String,
}

impl Error for ShclnError {}

impl fmt::Display for ShclnError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // write!(f, "{}", self.message)
        // red colored log
        write!(f, "\x1b[0;31m{}\x1b[0m", self.message)
    }
}

macro_rules! shcln_err {
    ($message:tt) => {
        return Err(ShclnError {
            message: format!($message),
        })
    };
}

/// Remove sensitive entries from shell histories.
#[derive(Parser)]
#[command(version)]
struct Cli {
    /// User home directory [default: read HOME env]
    #[arg(long)]
    home: Option<PathBuf>,

    /// Bash history file relative to home
    #[arg(long, default_value = ".bash_history")]
    bash_history: String,

    /// Zsh history file relative to home
    #[arg(long, default_value = ".zsh_history")]
    zsh_history: String,

    /// Keep temp backup file
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    keep_tmp: bool,
}

fn main() {
    let args = Cli::parse();

    KEEP_TMP.get_or_init(|| args.keep_tmp);

    let home_path = args.home.unwrap_or_else(|| {
        PathBuf::from(
            env::var("HOME").expect("home flag not specified and HOME env var not defined"),
        )
    });

    println!("cleaning home: {}", home_path.display());

    clean_home(&home_path, args.bash_history, args.zsh_history);
}

fn clean_home(home_path: &PathBuf, bash_history: String, zsh_history: String) {
    clean_shell(&home_path.join(bash_history), "bash", clean_bash_history);
    clean_shell(&home_path.join(zsh_history), "zsh", clean_zsh_history);
}

fn clean_shell(base_path: &Path, label: &str, cleaner: fn(&str, &str) -> Result<u32, ShclnError>) {
    if !base_path.exists() {
        return;
    }

    let history_path = base_path.display().to_string();
    let tmp_path = base_path.with_extension("bak").display().to_string();

    let removed = match cleaner(&history_path, &tmp_path) {
        Ok(removed) => removed,
        Err(err) => return println!("{}", err),
    };

    println!(
        "removed {} {} from {} history ({})",
        removed,
        if removed <= 1 { "entry" } else { "entries" },
        label,
        history_path,
    );
}

/// Clean a shell history file.
fn clean_bash_history(history_path: &str, tmp_path: &str) -> Result<u32, ShclnError> {
    match copy(history_path, tmp_path) {
        Ok(_) => (),
        Err(error) => shcln_err!("Failed to copy '{history_path}' to '{tmp_path}': {error}"),
    };

    let history_file = match File::create(history_path) {
        Ok(file) => file,
        Err(error) => shcln_err!("Failed to open '{history_path}': {error}"),
    };
    let tmp_file = match File::open(tmp_path) {
        Ok(file) => file,
        Err(error) => shcln_err!("Failed to create '{tmp_path}': {error}"),
    };

    let mut writer = BufWriter::new(history_file);
    let mut reader = BufReader::new(tmp_file);

    let mut removed: u32 = 0;
    let mut line = String::new();

    loop {
        match reader.read_line(&mut line) {
            Ok(b) => {
                if b == 0 {
                    break;
                }
            }
            Err(ref error) if error.kind() == std::io::ErrorKind::InvalidData => {
                // ignore invalid UTF-8 errors
                println!(
                    "{}",
                    ShclnError {
                        message: format!("Failed to read line from '{tmp_path}': {error}")
                    }
                );
                continue;
            }
            Err(error) => shcln_err!("Failed to read line from '{tmp_path}': {error}"),
        }

        if line.trim_end().len() == 0 {
            continue;
        }

        if !rm_line(&line.trim_end()) {
            match writer.write(line.as_bytes()) {
                Ok(_) => (),
                Err(error) => shcln_err!("Failed to write line to '{history_path}': {error}"),
            };
        } else {
            removed += 1;
        }
        line.clear();
    }

    match writer.flush() {
        Ok(_) => (),
        Err(error) => shcln_err!("Failed to flush '{history_path}': {error}"),
    };

    if !KEEP_TMP.get().unwrap() {
        match remove_file(tmp_path) {
            Ok(_) => (),
            Err(error) => shcln_err!("Failed to remove temp file '{tmp_path}': {error}"),
        };
    }

    Ok(removed)
}

/// Clean a zsh history file.
///
/// Zsh stores entries one per line, optionally prefixed with extended history
/// metadata (`: <timestamp>:<elapsed>;<command>`), and metafies non-printable
/// bytes with `0x83` as described at
/// <https://www.zsh.org/mla/users/2011/msg00154.html>. Multi-line commands are
/// stored with each inner newline escaped as `\\\n`.
fn clean_zsh_history(history_path: &str, tmp_path: &str) -> Result<u32, ShclnError> {
    match copy(history_path, tmp_path) {
        Ok(_) => (),
        Err(error) => shcln_err!("Failed to copy '{history_path}' to '{tmp_path}': {error}"),
    };

    let history_file = match File::create(history_path) {
        Ok(file) => file,
        Err(error) => shcln_err!("Failed to open '{history_path}': {error}"),
    };
    let tmp_file = match File::open(tmp_path) {
        Ok(file) => file,
        Err(error) => shcln_err!("Failed to create '{tmp_path}': {error}"),
    };

    let mut writer = BufWriter::new(history_file);
    let mut reader = BufReader::new(tmp_file);

    let mut removed: u32 = 0;
    let mut entry: Vec<u8> = Vec::new();
    let mut buf: Vec<u8> = Vec::new();

    loop {
        buf.clear();
        let n = match reader.read_until(b'\n', &mut buf) {
            Ok(n) => n,
            Err(error) => shcln_err!("Failed to read line from '{tmp_path}': {error}"),
        };

        if n == 0 {
            if !entry.is_empty() {
                flush_zsh_entry(&entry, &mut writer, &mut removed, history_path)?;
                entry.clear();
            }
            break;
        }

        entry.extend_from_slice(&buf);

        let continues =
            entry.len() >= 2 && entry[entry.len() - 1] == b'\n' && entry[entry.len() - 2] == b'\\';

        if !continues {
            flush_zsh_entry(&entry, &mut writer, &mut removed, history_path)?;
            entry.clear();
        }
    }

    match writer.flush() {
        Ok(_) => (),
        Err(error) => shcln_err!("Failed to flush '{history_path}': {error}"),
    };

    if !KEEP_TMP.get().unwrap() {
        match remove_file(tmp_path) {
            Ok(_) => (),
            Err(error) => shcln_err!("Failed to remove temp file '{tmp_path}': {error}"),
        };
    }

    Ok(removed)
}

fn flush_zsh_entry(
    entry: &[u8],
    writer: &mut BufWriter<File>,
    removed: &mut u32,
    history_path: &str,
) -> Result<(), ShclnError> {
    let content_end = if entry.ends_with(b"\n") {
        entry.len() - 1
    } else {
        entry.len()
    };
    if content_end == 0 {
        return Ok(());
    }

    let decoded = zsh_demetafy(&entry[..content_end]);
    let cmd = strip_zsh_prefix(&decoded);
    let logical = cmd.replace("\\\n", "\n");

    let matched = logical.lines().any(rm_line);
    if matched {
        *removed += 1;
    } else {
        match writer.write_all(entry) {
            Ok(_) => (),
            Err(error) => shcln_err!("Failed to write line to '{history_path}': {error}"),
        };
    }
    Ok(())
}

/// Decode zsh metafield encoding: a `0x83` byte escapes the next byte, which is
/// XOR'd with `0x20` to recover the original.
fn zsh_demetafy(bytes: &[u8]) -> String {
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x83 && i + 1 < bytes.len() {
            out.push(bytes[i + 1] ^ 0x20);
            i += 2;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Strip the `: <timestamp>:<elapsed>;` prefix used by zsh extended history.
fn strip_zsh_prefix(line: &str) -> &str {
    let Some(rest) = line.strip_prefix(": ") else {
        return line;
    };
    let bytes = rest.as_bytes();
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        i += 1;
    }
    if i == 0 || i >= bytes.len() || bytes[i] != b':' {
        return line;
    }
    let mut j = i + 1;
    while j < bytes.len() && bytes[j].is_ascii_digit() {
        j += 1;
    }
    if j == i + 1 || j >= bytes.len() || bytes[j] != b';' {
        return line;
    }
    &rest[j + 1..]
}

/// Whether or not to remove the line from the history file.
fn rm_line(line: &str) -> bool {
    for re in MATCH_LIST.iter() {
        if re.is_match(line) {
            // debug logs
            // println!("matched: {}\nwith: {}", line, re);

            // TODO: hash the secret before logging
            // get the secret value
            // let caps = re.captures(line).unwrap();
            // let secret = caps.get(1).unwrap();
            // println!("secret: {}", secret.as_str());

            println!("removed: {}", line.trim_end());

            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rm_line_match_aws() {
        // no match
        assert!(!rm_line("export RAND_VAR=foobar123"));
        assert!(!rm_line("RAND_VAR=foobar123 aws foo bar"));
        assert!(!rm_line("RAND_VAR='foobar123' aws foo bar"));
        assert!(!rm_line("RAND_VAR=\"foobar123\" aws foo bar"));
        assert!(!rm_line("RAND_VAR=foobar123"));
        assert!(!rm_line("RAND_VAR='foobar123'"));
        assert!(!rm_line("RAND_VAR=\"foobar123\""));

        // match
        assert!(rm_line("export AWS_ACCESS_KEY_ID=foobar123"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=foobar123 aws foo bar"));
        assert!(rm_line("AWS_ACCESS_KEY_ID='foobar123' aws foo bar"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=\"foobar123\" aws foo bar"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=foobar123"));
        assert!(rm_line("AWS_ACCESS_KEY_ID='foobar123'"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=\"foobar123\""));
    }

    #[test]
    fn test_rm_line_match_basic() {
        // no match
        assert!(!rm_line(""));
        assert!(!rm_line("abc"));
        assert!(!rm_line("123"));
        assert!(!rm_line("cmd -with 2 --flags 'abc' --var $USER"));
        assert!(!rm_line("export RAND_VAR=foobar123"));
        assert!(!rm_line("RAND_VAR=foobar123 aws foo bar"));
        assert!(!rm_line("RAND_VAR=foobar123"));
        assert!(!rm_line("RAND_VAR='foobar123'"));
        assert!(!rm_line("RAND_VAR=\"foobar123\""));

        // match
        assert!(rm_line("export AWS_ACCESS_KEY_ID=foobar123"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=foobar123 aws foo bar"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=foobar123"));
        assert!(rm_line("AWS_ACCESS_KEY_ID='foobar123'"));
        assert!(rm_line("AWS_ACCESS_KEY_ID=\"foobar123\""));
    }

    #[test]
    fn test_rm_line_sudo() {
        // no match
        assert!(!rm_line("echo 'foo' | sudo xargs echo"));
        assert!(!rm_line("sudo passwd root"));
        assert!(!rm_line("sudo passwd john"));

        // match
        assert!(rm_line("echo abcdefg123! | sudo -S foo"));
        assert!(rm_line("echo   abcdefg123!   |   sudo  -S   foo  --help"));
        assert!(rm_line("echo 'abcdefg123!' | sudo -S foo"));
        assert!(rm_line("echo 'abcdefg123 !' | sudo -S foo"));
        assert!(rm_line("echo \"abcdefg123!\" | sudo -S foo"));
        assert!(rm_line("sudo -S <<< password command"));
        assert!(rm_line("sudo  -S  <<<  password  command"));
        assert!(rm_line("sudo -S <<< 'password' foo"));
        assert!(rm_line("sudo -S <<< 'password bar' foo"));
        assert!(rm_line("sudo -S <<< \"password\" foo"));
        assert!(rm_line("echo -e 'foo\\nfoo\\n' | sudo passwd root"));
    }

    #[test]
    fn test_rm_line() {
        // no match
        assert!(!rm_line("ls -alhF --group-directories-first /tmp"));
        assert!(!rm_line("mkdir -p /tmp/foo/bar/baz"));
        assert!(!rm_line("cmd -p"));
        assert!(!rm_line("ssh-keyscan"));
        assert!(!rm_line("ssh-keygen"));
        assert!(!rm_line("ssh-keygen -f server.key"));
        assert!(!rm_line("sudo cryptsetup luksAddKey /dev/sda1 /tmp/foo"));
        assert!(!rm_line(
            "sudo cryptsetup open /dev/sda1 --key-file /tmp/foo"
        ));
        assert!(!rm_line("sudo chmod 400 /tmp/foo.key"));
        assert!(!rm_line("git commit -m \"key\""));
        assert!(!rm_line("cat yubikey.rules"));
        assert!(!rm_line("cat /etc/passwd"));
        assert!(!rm_line("echo $SECRET_TOKEN_KEY"));
        assert!(!rm_line("aws sso login --profile my-profile"));
        assert!(!rm_line("grep password foo.txt"));
        assert!(!rm_line("mkpasswd"));
        assert!(!rm_line("ssh foo@10.0.0.1"));
        assert!(!rm_line("ssh foo@localhost"));
        assert!(!rm_line("ssh user@localhost"));

        // match
        assert!(rm_line("export SECRET=abc"));
        // assert!(rm_line("cmd -p 'abc'"));
        assert!(rm_line("cmd --password 'abcdefg123!'"));
        assert!(rm_line("cmd --auth-token 'abcdefg123!'"));
        assert!(rm_line("echo 'abcdefg123!' | xargs myprogram -pass --"));
        assert!(rm_line("echo 'abcdefg123!' > pass"));
        assert!(rm_line("prog --password 'foo' && ssh-keyscan"));
        assert!(rm_line("ykman --scp-password abc"));
        assert!(rm_line(
            "echo \"foobar\" | docker login example.com -u user --password-stdin"
        ));
        assert!(rm_line("curl -u 'admin:foobar123!' http://example.com/"));
        assert!(rm_line(
            "curl -H \"Authorization: Basic foobar123\" http://example.com/"
        ));
    }

    #[test]
    fn test_strip_zsh_prefix() {
        assert_eq!(strip_zsh_prefix(": 1700000000:0;ls -al"), "ls -al");
        assert_eq!(
            strip_zsh_prefix(": 1700000000:15;export FOO=bar"),
            "export FOO=bar"
        );

        // no prefix: passthrough
        assert_eq!(strip_zsh_prefix("ls -al"), "ls -al");

        // malformed: passthrough
        assert_eq!(strip_zsh_prefix(": nope"), ": nope");
        assert_eq!(strip_zsh_prefix(": 123:abc"), ": 123:abc");
        assert_eq!(strip_zsh_prefix(": 123"), ": 123");
    }

    #[test]
    fn test_zsh_demetafy() {
        // plain ASCII is untouched
        assert_eq!(zsh_demetafy(b"hello world"), "hello world");

        // 0x83 escapes the next byte, which is XOR'd with 0x20. e.g. a tab
        // (0x09) is stored as 0x83 0x29 (0x09 ^ 0x20)
        assert_eq!(zsh_demetafy(&[b'a', 0x83, 0x29, b'b']), "a\tb");

        // a null byte is stored as 0x83 0x20
        assert_eq!(zsh_demetafy(&[0x83, 0x20]), "\0");
    }
}
