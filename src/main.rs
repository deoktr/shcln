use std::env;
use std::fs::{copy, remove_file, File};
use std::io::{prelude::*, BufReader, BufWriter};
use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

const BASH_HISTORY_FILE_PATH: &str = ".bash_history";

static MATCH_LIST: LazyLock<[Regex; 52]> = LazyLock::new(|| {
    [
        // low quality matches
        Regex::new(r" --?[0-9a-zA-Z_-]*pass(?:word)? *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*token[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*auth[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*key(?: +|=)([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*jwt[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r" --?[0-9a-zA-Z_-]*secret[0-9a-zA-Z_-]* *=?([^ ]+)").unwrap(),
        Regex::new(r">.*(?:secret|pass|token|jwt)").unwrap(),
        // medium quality matches
        Regex::new(r#"KEY[0-9a-zA-Z_-]*=["']?([^ ]+)["']?"#).unwrap(),
        Regex::new(r#"SECRET[0-9a-zA-Z_-]*=["']?([^ ]+)["']?"#).unwrap(),
        Regex::new(r#"JWT[0-9a-zA-Z_-]*=["']?([^ ]+)["']?"#).unwrap(),
        Regex::new(r#"TOKEN[0-9a-zA-Z_-]*=["']?([^ ]+)["']?"#).unwrap(),
        // high quality matches
        Regex::new(r#"echo (?:-e)?*["']?(.*)["']? *\| *sudo.*-S"#).unwrap(),
        Regex::new(r#"sudo.*-S.*<<< *(.*)"#).unwrap(),
        Regex::new(r#"AWS_ACCESS_KEY_ID=["']?([0-9a-zA-Z*/+]{0,100})["']?"#).unwrap(),
        Regex::new(r"AWS_SECRET_ACCESS_KEY=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"(?i)(aws_access_key_id|aws_secret_access_key)=([0-9a-zA-Z/+]{20,40})").unwrap(),
        Regex::new(r#"(?i:authorization):(?:.*)(?i:Basic).(.*)("|'|\x60|\$\()"#).unwrap(),
        Regex::new(r"curl.*(?:-u|--user)(?:[ =])([^ ]*)").unwrap(),
        Regex::new(r#"GITHUB_TOKEN=["']?([0-9a-zA-Z*_/+]{0,100})["']?"#).unwrap(),
        Regex::new(r"ghp_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"gho_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"(ghu|ghs)_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"ghr_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"GITLAB_TOKEN=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"glpat-[0-9a-zA-Z-_]{20}").unwrap(),
        Regex::new(r#"(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        Regex::new(r"HEROKU_API_KEY=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"VAULT_TOKEN=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"CONSUL_HTTP_TOKEN=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"VERCEL_TOKEN=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"CLOUDFLARE_API_KEY=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"NEWRELIC_API_KEY=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r#""key-[0-9a-zA-Z]{32}""#).unwrap(), // MailGun API Key
        Regex::new(r"(?i)[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
        Regex::new(r"SG.[0-9A-Za-z\-_]{15,30}\.[0-9A-Za-z\-_]{15,30}").unwrap(),
        Regex::new(r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}").unwrap(),
        Regex::new(r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{30,32})").unwrap(),
        Regex::new(r"https://hooks.slack.com/services/([A-Za-z0-9+/]{44,46})").unwrap(),
        Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
        Regex::new(r"(([A-Za-z]*:(?://)?)([-;:&=\+\$,\w]+)@[A-Za-z0-9.-]+(:[0-9]+)?|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:/[\+~%/.\w\-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?").unwrap(),
        Regex::new(r#"(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        Regex::new(r"https://outlook.office.com/webhook/([0-9a-f-]{36})/@").unwrap(),
        Regex::new(r"oy2[a-z0-9]{43}").unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{35,44})[''"]"#).unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{18,25})[''"]"#).unwrap(),
        Regex::new(r"wget(?:.*)--(?:ftp-|http-)?(?:password|user)[ =]([^ ]*)").unwrap(),
        Regex::new(r#"(?i)linkedin(.{0,20})?(?-i)[''"]([0-9a-zA-Z]{12,16})[''"]"#).unwrap(),
        Regex::new(r"EAACEdEose0cBA[0-9A-Za-z]+").unwrap(),
        Regex::new(r#"(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:\[s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|"|\n|\r|\s|\x60|;]|$)"#).unwrap(),
        Regex::new(r"README_API_KEY=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"CARGO_REGISTRY_TOKEN=([0-9a-zA-Z*/+]{0,100})").unwrap(),
        Regex::new(r"diskutil.*passphrase ([[:alpha:][:punct:]]{0,200}).*").unwrap(),
    ]
});

static KEEP_TMP: bool = true;

fn main() {
    let home_path = env::var("HOME").unwrap();

    let base_path = Path::new(&home_path).join(BASH_HISTORY_FILE_PATH);
    let history_path = base_path.display().to_string();
    let tmp_path = base_path.with_extension("bak").display().to_string();

    let removed = clean_history(&history_path, &tmp_path).unwrap();

    println!(
        "removed {} {} from bash history ({})",
        removed,
        if removed <= 1 { "entry" } else { "entries" },
        history_path,
    );
}

/// Clean a shell history file.
fn clean_history(history_path: &str, tmp_path: &str) -> Result<u32, std::io::Error> {
    copy(history_path, tmp_path)?;

    let history_file = File::create(history_path)?;
    let tmp_file = File::open(tmp_path)?;

    let mut writer = BufWriter::new(history_file);
    let mut reader = BufReader::new(tmp_file);

    let mut removed: u32 = 0;
    let mut line = String::new();
    while reader.read_line(&mut line)? > 0 {
        if !rm_line(&line) {
            writer.write(line.as_bytes())?;
        } else {
            println!("removed: {}", line.trim_end());
            removed += 1;
        }
        line.clear();
    }
    writer.flush()?;

    if !KEEP_TMP {
        remove_file(tmp_path)?;
    }

    Ok(removed)
}

/// Weither or not to remove the line from the history file.
fn rm_line(line: &str) -> bool {
    for re in MATCH_LIST.iter() {
        if re.is_match(line) {
            // debug logs
            // println!("matched: {}\nwith: {}", line, re);

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
        // assert!(rm_line("echo -e 'foo\\nfoo\\n' | sudo passwd root"));
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

        // match
        assert!(rm_line("export SECRET=abc"));
        // assert!(rm_line("cmd -p 'abc'"));
        assert!(rm_line("cmd --password 'abcdefg123!'"));
        assert!(rm_line("cmd --auth-token 'abcdefg123!'"));
        assert!(rm_line("echo 'abcdefg123!' | xargs myprogram -pass --"));
        assert!(rm_line("echo 'abcdefg123!' > pass"));
        assert!(rm_line("prog --password 'foo' && ssh-keyscan"));
        assert!(rm_line("ykman --scp-password abc"));
    }
}
