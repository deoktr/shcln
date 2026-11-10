use std::sync::{LazyLock, OnceLock};

use regex::bytes::{Regex, RegexBuilder};

use crate::pattern_data::{
    PATTERN_COUNT, PATTERN_IDS, PATTERN_NAMES, PATTERN_PROVIDERS, PATTERN_SOURCES,
};
use crate::prefilter::Prefilter;

/// Human-readable metadata for a secret scanning rule.
#[derive(Clone, Copy, Debug)]
pub struct Pattern {
    pub provider: &'static str,
    pub name: &'static str,
    pub id: &'static str,
}

/// Lazily compiled regexes. A pattern is only compiled the first time its
/// prefilter keywords occur in a history line.
static PATTERN_CACHE: LazyLock<Vec<OnceLock<Regex>>> =
    LazyLock::new(|| (0..PATTERN_COUNT).map(|_| OnceLock::new()).collect());

static PREFILTER: LazyLock<Prefilter> = LazyLock::new(Prefilter::new);

/// Compile a pattern. Some rules combine several large expressions, so raise
/// the compiled size limit above the regex crate's deliberately conservative
/// default.
fn rx(pattern: &str) -> Regex {
    RegexBuilder::new(pattern)
        .unicode(false)
        .size_limit(64 * 1024 * 1024)
        .build()
        .unwrap()
}

/// Return the first pattern that matches the line, if any.
pub fn match_line(line: &str) -> Option<Pattern> {
    let matched = PREFILTER.find_match(line.as_bytes(), |idx| {
        let cell = &PATTERN_CACHE[idx];
        let re = cell.get_or_init(|| rx(PATTERN_SOURCES[idx]));
        re.is_match(line.as_bytes())
    })?;
    Some(Pattern {
        provider: PATTERN_PROVIDERS[matched],
        name: PATTERN_NAMES[matched],
        id: PATTERN_IDS[matched],
    })
}

/// Whether or not to remove the line from the history file.
#[allow(dead_code)]
pub fn rm_line(line: &str) -> bool {
    match_line(line).is_some()
}

#[cfg(test)]
fn compiled_patterns() -> &'static [Regex] {
    static COMPILED: LazyLock<Vec<Regex>> =
        LazyLock::new(|| PATTERN_SOURCES.iter().map(|s| rx(s)).collect());
    &COMPILED
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(line: &str) -> bool {
        compiled_patterns()
            .iter()
            .any(|re| re.is_match(line.as_bytes()))
    }

    #[test]
    fn all_patterns_compile() {
        assert_eq!(PATTERN_COUNT, PATTERN_SOURCES.len());
        assert_eq!(compiled_patterns().len(), PATTERN_COUNT);
    }

    #[test]
    fn match_line_returns_pattern_metadata() {
        let token = format!("ops_eyJ{}", "a".repeat(260));
        let pattern = match_line(&token).expect("token should match a pattern");
        assert_eq!(pattern.provider, "1Password");
        assert_eq!(pattern.name, "1Password Service Account Token");
        assert_eq!(pattern.id, "1password_service_account_token");
        assert!(match_line("ls -la").is_none());
    }

    #[test]
    fn representative_secrets_match() {
        let samples = [
            "AKIAIOSFODNN7EXAMPLE",
            "ASIAIOSFODNN7EXAMPLE",
            "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "gho_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghu_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghs_abcdefghijklmnopqrstuvwxyz0123456789",
            "ghr_abcdefghijklmnopqrstuvwxyz0123456789",
            "github_pat_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
            "glpat-abcdefghijklmnopqrst",
            "glpat-abcdefghijklmnopqrstuvwxyz0.12abcdefg",
            "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            "sk_live_1234567890abcdefghijklmn",
            "rk_live_1234567890abcdefghijklmn",
            "sk-proj-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567T3BlbkFJabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567",
            "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789AA",
            "hf_abcdefghijklmnopqrstuvwxyzabcdefgh",
            "api_org_abcdefghijklmnopqrstuvwxyzabcdefgh",
            "gsk_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
            "r8_abcdefghijklmnopqrstuvwxyz0123456789a",
            "pplx-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
            "xai-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmn",
            "sk-or-v1-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
            "pypi-AgEIcHlwaS5vcmcCJabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            "hvs.abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            "ops_eyJabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            "aio_abcdefghijklmnopqrstuvwxyz12",
            "p8e-abcdefghijklmnopqrstuvwxyz012345",
            "patabcdefghijklmn.abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "LTAIabcdefghijklmnopqrst",
            "ATBBabcdefghijklmnopqrstuvwx",
            "bkua_abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "CCIPAT_abcdefghijklmnopqrstuv_abcdef0123456789abcdef0123456789abcdef01",
            "CLOJARS_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01",
            "cfut_abcdefghijklmnopqrstuvwxyz0123456789abcd01234567",
            "cfk_abcdefghijklmnopqrstuvwxyz0123456789abcd01234567",
            "CFPAT-abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "dapiabcdef0123456789abcdef0123456789",
            "dop_v1_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "dp.pt.abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "duffel_live_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "dt0c01.abcdefghijklmnopqrstuvwx.abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz01234567",
            "EZAKabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
            "EZTKabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqr",
            "EAAabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
            "figp_abcdefghijklmnopqrstuvwxyz0123456789abcdef",
            "FLWSECK-abcdefghijklmnopqrstuvwxyz012345-X",
            "fio-u-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghij",
            "na1.abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ+/abcdefghijklmnop",
            "HRKU-AAabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
            "pat-na1-abcdefgh-1234-5678-9012-abcdefghijkl",
            "AKCpabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
            "cmVmdabcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvw",
            "lin_api_abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "live_abcdef0123456789abcdef0123456789abc",
            "MAILGUN_API_KEY=key-abcdef0123456789abcdef0123456789",
            "sk.abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            "abcdef_abcdefghijklmnopqrstuvwxyz012_mmk",
            "MERAKI_API_KEY=abcdef0123456789abcdef0123456789abcdef01",
            "MESSAGEBIRD_API_KEY=abcdefghijklmnopqrstuvwxy",
            "NRAK-abcdefghijklmnopqrstuvwxyz0",
            "NRIQ-abcdefghijklmnopqrstuvwxy",
            "ntn_12345678901abcdefghijklmnopqrstuvwxyz012345678",
            "secret_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "oy2abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "API-ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "pnu_abcdefghijklmnopqrstuvwxyz0123456789",
            "pul-abcdef0123456789abcdef0123456789abcdef01",
            "rdme_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
            "shpat_abcdef0123456789abcdef0123456789",
            "shpca_abcdef0123456789abcdef0123456789",
            "shppa_abcdef0123456789abcdef0123456789",
            "shpss_abcdef0123456789abcdef0123456789",
            "SG.abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123",
            "sntryu_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "shippo_live_abcdef0123456789abcdef0123456789abcdef01",
            "xapp-1-A0123456789-1234567890-abcdefghijklmnopqrstuvwxyz0123456789",
            "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx",
            "ACabcdef0123456789abcdef0123456789",
            "SKabcdef0123456789abcdef0123456789",
            "tfp_abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
            "wandb_v1_abcdefghijklmnopqrstuvwxyz0_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklm",
            "tskey-api-abcdefghijklmnopqrstuvwxyz-abcdefghijklmnopqrstuvwxyz",
            "123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghi",
            "abc1Q~abcdefghijklmnopqrstuvwxyz012345",
            "AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx==",
            "Endpoint=https://example.azconfig.io;Id=abc;Secret=abcdefghijklmnopqrstuvwxyz0123456789",
            "HostName=example.azure-devices.net;DeviceId=device;SharedAccessKey=abcdefghijklmnopqrstuvwxyz0123456789",
            "mongodb://user:password@localhost:27017/mydb",
            "postgres://user:password@localhost:5432/mydb",
            "-----BEGIN RSA PRIVATE KEY-----",
            "sbp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "sb_secret_abcdefghijklmnopqrstuvwxyz",
            "glc_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
            "glsa_abcdefghijklmnopqrstuvwxyz012345_abcdef01",
            "pcsk_abcde_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0",
            "pscale_tkn_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "pscale_oauth_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "pscale_pw_abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "PMAK-abcdef0123456789abcdef01-abcdef0123456789abcdef0123456789ab",
            "re_abcdefgh_abcdefghijkmnopqrstuvwxy",
            "rootly_abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "rubygems_abcdef0123456789abcdef0123456789abcdef0123456789",
            "sgp_abcdef0123456789abcdef0123456789abcdef01",
            "sq0atp-abcdefghijklmnopqrstuv",
            "AQVNabcdefghijklmnopqrstuvwxyz012345678",
            "VERCEL_TOKEN=abcdefghijklmnopqrstuvwxyz012345",
            "WORKOS_API_KEY=sk_abcdefghijklmnopqrstuvwxyz012345",
        ];

        let missing: Vec<_> = samples
            .iter()
            .copied()
            .filter(|sample| !matches(sample))
            .collect();
        assert!(
            missing.is_empty(),
            "no pattern matched samples: {missing:#?}"
        );
    }

    #[test]
    fn prefilter_never_skips_a_matching_pattern() {
        assert_eq!(PREFILTER.pattern_count(), PATTERN_SOURCES.len());

        let samples = [
            "ls -la",
            "cargo build --release",
            "export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789",
            "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE",
            "curl -H 'Authorization: Bearer abcdefghijklmnopqrstuvwxyz' https://example.com",
            "psql postgres://user:password@localhost:5432/db",
            "-----BEGIN RSA PRIVATE KEY-----",
            "xoxb-123456789012-123456789012-abcdefghijklmnopqrstuvwx",
            "sk_live_1234567890abcdefghijklmn",
            "hf_abcdefghijklmnopqrstuvwxyzabcdefgh",
            "pcsk_abcde_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789",
            "dapiabcdef0123456789abcdef0123456789",
            "dp.pt.abcdefghijklmnopqrstuvwxyz0123456789abcdefg",
            "https://hooks.slack.com/services/T00000000/B00000000/abcdefghijklmnopqrstuvwx",
            "sbp_abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "AIzaabcdefghijklmnopqrstuvwxyz0123456",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
            "glpat-abcdefghijklmnopqrst",
            "github_pat_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuv",
        ];

        for sample in samples {
            let candidates = PREFILTER.candidate_indices(sample.as_bytes());
            for (idx, re) in compiled_patterns().iter().enumerate() {
                if re.is_match(sample.as_bytes()) {
                    assert!(
                        candidates.contains(&idx),
                        "prefilter skipped pattern {idx} for {sample:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn rm_line_matches_expected() {
        let lines = [
            "export AWS_ACCESS_KEY_ID=foobar123",
            "AWS_ACCESS_KEY_ID=foobar123 aws foo bar",
            "AWS_ACCESS_KEY_ID='foobar123' aws foo bar",
            "AWS_ACCESS_KEY_ID=\"foobar123\" aws foo bar",
            "AWS_ACCESS_KEY_ID=foobar123",
            "AWS_ACCESS_KEY_ID='foobar123'",
            "AWS_ACCESS_KEY_ID=\"foobar123\"",
            "echo abcdefg123! | sudo -S foo",
            "echo   abcdefg123!   |   sudo  -S   foo  --help",
            "echo 'abcdefg123!' | sudo -S foo",
            "echo 'abcdefg123 !' | sudo -S foo",
            "echo \"abcdefg123!\" | sudo -S foo",
            "sudo -S <<< password command",
            "sudo  -S  <<<  password  command",
            "sudo -S <<< 'password' foo",
            "sudo -S <<< 'password bar' foo",
            "sudo -S <<< \"password\" foo",
            "echo -e 'foo\\nfoo\\n' | sudo passwd root",
            "echo \"foobar\" | docker login example.com -u user --password-stdin",
            "curl -u 'admin:foobar123!' http://example.com/",
            "curl -H \"Authorization: Basic foobar123\" http://example.com/",
            "AKIAIOSFODNN7EXAMPLE",
            "aws sts get-session-token ASIAIOSFODNN7EXAMPLE",
            "sk_live_1234567890abcdefghijkl",
            "sk-abcdefghij0123456789T3BlbkFJabcdefghij0123456789",
            "hf_abcdefghijklmnopqrstuvwxyzabcdefgh",
            "api_org_abcdefghijklmnopqrstuvwxyzabcdefgh",
            "gsk_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop",
            "r8_abcdefghijklmnopqrstuvwxyz0123456789a",
            "pplx-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl",
            "xai-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefgh",
            "sk-or-v1-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
            "sk-abcdef0123456789abcdef0123456789",
            "mistral-abcdefghijklmnopqrst",
            "fw_abcdefghijklmnopqrstuvwxyz012345",
            "jina_abcdefghijklmnopqrstuvwx",
            "pa-abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "pcsk_abcdefghijklmnopqrstuvwxyz0123456789",
            "nvapi-abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "lsv2_pt_abcdefghijklmnopqrstuvwx",
            "csk-abcdefghijklmnopqrstuvwxyz0123456789abcd",
            "sk_abcdefghijklmnopqrstuvwxyz012345",
            "ABSKaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
            "github_pat_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "npm_abcdefghijklmnopqrstuvwxyz0123456789",
            "pypi-AgEIcHlwaS5vcmcCJaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hvs.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "curl https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnop",
            "echo \"-----BEGIN OPENSSH PRIVATE KEY-----\"",
            "cat <<'EOF' -----BEGIN RSA PRIVATE KEY----- EOF",
            "cat -----BEGIN DSA PRIVATE KEY-----",
            "cat -----BEGIN EC PRIVATE KEY-----",
            "cat -----BEGIN PRIVATE KEY-----",
            "cat -----BEGIN ENCRYPTED PRIVATE KEY-----",
            "cat -----BEGIN PGP PRIVATE KEY BLOCK-----",
            "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==;EndpointSuffix=core.windows.net",
            "mongosh \"mongodb://user:password@localhost:27017/mydb?authSource=admin\"",
            "mongodb://user:password@localhost:27017/mydb",
            "mongodb+srv://user:password@cluster0.mongodb.net/mydb",
            "mysql://user:password@localhost:3306/mydb",
            "mysql://root:p%40ss@127.0.0.1:3306/mydb",
            "mysql+pymysql://user:password@localhost:3306/mydb",
            "jdbc:mysql://user:password@localhost:3306/mydb",
            "jdbc:mysql://localhost:3306/mydb?user=root&password=secret",
            "mysql://localhost:3306/mydb?user=root&password=secret",
            "postgres://user:password@localhost:5432/mydb",
            "postgresql://user:password@localhost:5432/mydb",
            "postgresql+psycopg2://user:password@localhost:5432/mydb",
            "jdbc:postgresql://user:password@localhost:5432/mydb",
            "Server=localhost;Database=mydb;Uid=user;Pwd=secret;",
            "Password=secret;Data Source=localhost;Database=mydb;",
            "Host=localhost;Database=mydb;Username=user;Password=secret;",
            "host=localhost port=5432 dbname=mydb user=foo password=secret",
        ];

        let missing: Vec<_> = lines
            .iter()
            .copied()
            .filter(|line| !rm_line(line))
            .collect();
        assert!(
            missing.is_empty(),
            "expected rm_line to match: {missing:#?}"
        );
    }

    #[test]
    fn rm_line_rejects_unexpected() {
        let lines = [
            "export RAND_VAR=foobar123",
            "RAND_VAR=foobar123 aws foo bar",
            "RAND_VAR='foobar123' aws foo bar",
            "RAND_VAR=\"foobar123\" aws foo bar",
            "RAND_VAR=foobar123",
            "RAND_VAR='foobar123'",
            "RAND_VAR=\"foobar123\"",
            "",
            "abc",
            "123",
            "cmd -with 2 --flags 'abc' --var $USER",
            "echo 'foo' | sudo xargs echo",
            "sudo passwd root",
            "sudo passwd john",
            "ls -alhF --group-directories-first /tmp",
            "mkdir -p /tmp/foo/bar/baz",
            "cmd -p",
            "ssh-keyscan",
            "ssh-keygen",
            "ssh-keygen -f server.key",
            "sudo cryptsetup luksAddKey /dev/sda1 /tmp/foo",
            "sudo cryptsetup open /dev/sda1 --key-file /tmp/foo",
            "sudo chmod 400 /tmp/foo.key",
            "git commit -m \"key\"",
            "cat yubikey.rules",
            "cat /etc/passwd",
            "echo $SECRET_TOKEN_KEY",
            "aws sso login --profile my-profile",
            "grep password foo.txt",
            "mkpasswd",
            "ssh foo@10.0.0.1",
            "ssh foo@localhost",
            "ssh user@localhost",
            "export SECRET=abc",
            "cmd --password 'abcdefg123!'",
            "cmd --auth-token 'abcdefg123!'",
            "echo 'abcdefg123!' | xargs myprogram -pass --",
            "echo 'abcdefg123!' > pass",
            "prog --password 'foo' && ssh-keyscan",
            "ykman --scp-password abc",
            "ssh://git@github.com",
            "git clone https://github.com/user/repo",
            "curl https://example.com:8080/path",
            "curl -H \"Content-Type: application/json\" https://example.com",
            "cat -----BEGIN CERTIFICATE-----",
            "cat -----BEGIN PUBLIC KEY-----",
            "cat -----BEGIN PGP PUBLIC KEY BLOCK-----",
            "mongodb://localhost:27017/mydb",
            "mongodb+srv://cluster0.mongodb.net/mydb",
            "mysql://localhost:3306/mydb",
            "jdbc:mysql://localhost:3306/mydb",
            "jdbc:mysql://localhost:3306/mydb?useSSL=false",
            "postgres://localhost:5432/mydb",
            "postgresql://localhost:5432/mydb",
            "Server=localhost;Database=mydb;Uid=user;",
            "pip install pypi-metadata-exporter",
            "AKIA123",
            "sk-ant-not-a-real-key",
            "hf_short",
            "gsk_short",
            "sk-or-not-a-key",
            "pk_test_1234567890abcdefghijkl",
            "export OPENAI_API_KEY",
        ];

        let matched: Vec<_> = lines.iter().copied().filter(|line| rm_line(line)).collect();
        assert!(
            matched.is_empty(),
            "expected rm_line not to match: {matched:#?}"
        );
    }
}
