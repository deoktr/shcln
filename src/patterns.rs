use std::sync::LazyLock;

use regex::Regex;

static MATCH_LIST: LazyLock<[Regex; 176]> = LazyLock::new(|| {
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
        Regex::new(r"\b(github_pat_[0-9a-zA-Z_]{22,})\b").unwrap(),
        Regex::new(r"ghr_[0-9a-zA-Z]{36}").unwrap(),
        Regex::new(r"glpat-[0-9a-zA-Z-_]{20}").unwrap(),
        Regex::new(r#"(?i)(?:heroku)(?:[0-9a-z\-_\t .]{0,20})(?:[\s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        // MailGun API Key
        Regex::new(r#""key-[0-9a-zA-Z]{32}""#).unwrap(),
        Regex::new(r"(?i)[0-9a-f]{32}-us[0-9]{1,2}").unwrap(),
        Regex::new(r"(SG.[0-9A-Za-z\-_]{15,30}\.[0-9A-Za-z\-_]{15,30})").unwrap(),
        Regex::new(r"(SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43})").unwrap(),
        Regex::new(r"(xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{30,32})").unwrap(),
        Regex::new(r"https://hooks.slack.com/services/([A-Za-z0-9+/]{44,46})").unwrap(),
        Regex::new(r"(SK[0-9a-fA-F]{32})").unwrap(),
        // AWS access key id (AKIA/ASIA/...), also catches temporary keys
        Regex::new(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b").unwrap(),
        // Stripe secret, publishable and restricted keys
        Regex::new(r"\b((?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{16,})\b").unwrap(),
        // OpenAI API key (legacy)
        Regex::new(r"\b(sk-[0-9a-zA-Z]{20}T3BlbkFJ[0-9a-zA-Z]{20})\b").unwrap(),
        // OpenAI API key (project / service account / admin scoped)
        Regex::new(r"\b(sk-(?:proj|svcacct|admin)-[0-9a-zA-Z\-_]{16,})\b").unwrap(),
        // Anthropic API key
        Regex::new(r"\b(sk-ant-(?:api|sid|admin)[0-9]{2}-[0-9a-zA-Z\-_]{16,})\b").unwrap(),
        Regex::new(r"\b(npm_[0-9a-zA-Z]{36})\b").unwrap(),
        Regex::new(r"\b(pypi-[0-9a-zA-Z\-_]{50,})\b").unwrap(),
        // HashiCorp Vault token
        Regex::new(r"\b(hv[bsp]\.[0-9a-zA-Z\-_]{20,})\b").unwrap(),
        // FIXME: wrongly detect ssh
        // Regex::new(r"(([A-Za-z]*:(?://)?)([-;:&=\+\$,\w]+)@[A-Za-z0-9.-]+(:[0-9]+)?|(?:www.|[-;:&=\+\$,\w]+@)[A-Za-z0-9.-]+)((?:/[\+~%/.\w\-_]*)?\??(?:[-\+=&;%@.\w_]*)#?(?:[\w]*))?").unwrap(),
        Regex::new(r#"(?i)\b(AIza[0-9A-Za-z\\-_]{35})(?:['|"|\n|\r|\s|\x60]|$)"#).unwrap(),
        // Hugging Face access token and organization token
        Regex::new(r"\b(hf_[a-z]{34})\b").unwrap(),
        Regex::new(r"\b(api_org_[a-z]{34})\b").unwrap(),
        // Groq
        Regex::new(r"\b(gsk_[0-9a-zA-Z]{48})\b").unwrap(),
        // Replicate
        Regex::new(r"\b(r8_[0-9a-zA-Z]{40})\b").unwrap(),
        // Perplexity
        Regex::new(r"\b(pplx-[0-9a-zA-Z]{48})\b").unwrap(),
        // xAI / Grok
        Regex::new(r"\b(xai-[0-9a-zA-Z]{40,})\b").unwrap(),
        // OpenRouter
        Regex::new(r"\b(sk-or-v1-[0-9a-zA-Z]{40,})\b").unwrap(),
        // DeepSeek (bare sk- prefix followed by hex)
        Regex::new(r"\b(sk-[0-9a-f]{32,})\b").unwrap(),
        // Mistral
        Regex::new(r"(?i)\b(mistral-[0-9a-zA-Z]{16,})\b").unwrap(),
        // Fireworks AI
        Regex::new(r"\b(fw_[0-9a-zA-Z]{30,})\b").unwrap(),
        // Jina AI
        Regex::new(r"\b(jina_[0-9a-zA-Z]{20,})\b").unwrap(),
        // Voyage AI
        Regex::new(r"\b(pa-[0-9a-zA-Z]{32,})\b").unwrap(),
        // Pinecone
        Regex::new(r"\b(pcsk_[0-9a-zA-Z]{30,})\b").unwrap(),
        // NVIDIA NGC (build.nvidia.com)
        Regex::new(r"\b(nvapi-[0-9a-zA-Z]{30,})\b").unwrap(),
        // LangSmith (LangChain)
        Regex::new(r"\b(lsv2_[0-9a-zA-Z_-]{20,})\b").unwrap(),
        // Cerebras
        Regex::new(r"\b(csk-[0-9a-zA-Z]{30,})\b").unwrap(),
        // ElevenLabs
        Regex::new(r"\b(sk_[0-9a-zA-Z]{24,})\b").unwrap(),
        // Amazon Bedrock (long-lived and short-lived API keys)
        Regex::new(r"\b(ABSK[A-Za-z0-9+/=]{40,})\b").unwrap(),
        Regex::new(r"bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t").unwrap(),
        Regex::new(r"https://outlook.office.com/webhook/([0-9a-f-]{36})/@").unwrap(),
        Regex::new(r"oy2[a-z0-9]{43}").unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{35,44})[''"]"#).unwrap(),
        Regex::new(r#"(?i)twitter(.{0,20})?[''"]([0-9a-z]{18,25})[''"]"#).unwrap(),
        Regex::new(r"wget(?:.*)--(?:ftp-|http-)?(?:password|user)[ =]([^ ]*)").unwrap(),
        Regex::new(r#"(?i)linkedin(.{0,20})?(?-i)[''"]([0-9a-zA-Z]{12,16})[''"]"#).unwrap(),
        Regex::new(r"(EAACEdEose0cBA[0-9A-Za-z]+)").unwrap(),
        Regex::new(r#"(?i)(?:datadog)(?:[0-9a-z\-_\t .]{0,20})(?:\[s|']|[\s|"]){0,3}(?:=|>|:=|\|\|:|<=|=>|:)(?:'|"|\s|=|\x60){0,5}([a-z0-9]{40})(?:['|"|\n|\r|\s|\x60|;]|$)"#).unwrap(),
        Regex::new(r"diskutil.*passphrase ([[:alpha:][:punct:]]{1,200}).*").unwrap(),
        // Discord webhook url
        Regex::new(r"(discord(?:app)?\.com/api/webhooks/[0-9]{17,}/[0-9A-Za-z_-]+)").unwrap(),
        // private key pasted inline: OpenSSH native, PEM (RSA/DSA/EC),
        // PKCS#8, encrypted, and PGP armored private key blocks
        Regex::new(r"(?i)(-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----)").unwrap(),
        // Azure storage account connection string key
        Regex::new(r"(AccountKey=[A-Za-z0-9+/]{40,}={0,2})").unwrap(),
        // MongoDB connection string with credentials
        Regex::new(r#"(?i)\bmongodb(?:\+[a-z0-9]+)?://[^'"`<>/:\s@]+:[^'"`<>/@\s]+@[^?'"`\s]+"#).unwrap(),
        // MySQL connection string with credentials (also matches JDBC and SQLAlchemy URIs)
        Regex::new(r#"(?i)\bmysql(?:\+[a-z0-9]+)?://[^'"`<>/:\s@]+:[^'"`<>/@\s]+@[^?'"`\s]+"#).unwrap(),
        // PostgreSQL connection string with credentials (also matches JDBC and SQLAlchemy URIs)
        Regex::new(r#"(?i)\bpostgres(?:ql)?(?:\+[a-z0-9]+)?://[^'"`<>/:\s@]+:[^'"`<>/@\s]+@[^?'"`\s]+"#).unwrap(),
        // key/value connection strings for MySQL and PostgreSQL with credentials
        Regex::new(r"(?i)(?:\b(?:server|host|data source)\s*=[^;\s]+.*\b(?:pwd|password)\s*=[^;\s]+|\b(?:pwd|password)\s*=[^;\s]+.*\b(?:server|host|data source)\s*=[^;\s]+)").unwrap(),
        // database connection URI with credentials in query parameters
        Regex::new(r"(?i)\b(?:mysql|postgres(?:ql)?)(?:\+[a-z0-9]+)?://[^\s?]+\?[^\s]*(?:pwd|password)=[^&\s]+").unwrap(),
        // JDBC connection string with credentials in query parameters
        Regex::new(r"(?i)\bjdbc:[a-z]+://[^\s?]+\?[^\s]*(?:pwd|password)=[^&\s]+").unwrap(),
        // env vars
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

/// Whether or not to remove the line from the history file.
pub fn rm_line(line: &str) -> bool {
    for re in MATCH_LIST.iter() {
        if re.is_match(line) {
            // debug logs
            // println!("matched: {}\nwith: {}", line, re);

            // TODO: hash the secret before logging
            // get the secret value
            // let caps = re.captures(line).unwrap();
            // let secret = caps.get(1).unwrap();
            // println!("secret: {}", secret.as_str());

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
    fn test_rm_line_specific_credentials() {
        // no match
        assert!(!rm_line("ssh://git@github.com"));
        assert!(!rm_line("git clone https://github.com/user/repo"));
        assert!(!rm_line("curl https://example.com:8080/path"));
        assert!(!rm_line(
            "curl -H \"Content-Type: application/json\" https://example.com"
        ));
        assert!(!rm_line("cat -----BEGIN CERTIFICATE-----"));
        assert!(!rm_line("cat -----BEGIN PUBLIC KEY-----"));
        assert!(!rm_line("cat -----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert!(!rm_line("mongodb://localhost:27017/mydb"));
        assert!(!rm_line("mongodb+srv://cluster0.mongodb.net/mydb"));
        assert!(!rm_line("mysql://localhost:3306/mydb"));
        assert!(!rm_line("jdbc:mysql://localhost:3306/mydb"));
        assert!(!rm_line("jdbc:mysql://localhost:3306/mydb?useSSL=false"));
        assert!(!rm_line("postgres://localhost:5432/mydb"));
        assert!(!rm_line("postgresql://localhost:5432/mydb"));
        assert!(!rm_line("Server=localhost;Database=mydb;Uid=user;"));
        assert!(!rm_line("pip install pypi-metadata-exporter"));
        assert!(!rm_line("AKIA123"));
        assert!(!rm_line("sk-ant-not-a-real-key"));
        assert!(!rm_line("hf_short"));
        assert!(!rm_line("gsk_short"));
        assert!(!rm_line("sk-or-not-a-key"));
        assert!(!rm_line("export OPENAI_API_KEY"));

        // match
        assert!(rm_line("AKIAIOSFODNN7EXAMPLE"));
        assert!(rm_line("aws sts get-session-token ASIAIOSFODNN7EXAMPLE"));
        assert!(rm_line("sk_live_1234567890abcdefghijkl"));
        assert!(rm_line("pk_test_1234567890abcdefghijkl"));
        assert!(rm_line(
            "sk-abcdefghij0123456789T3BlbkFJabcdefghij0123456789"
        ));
        assert!(rm_line("sk-proj-abcdefghijklmnop"));
        assert!(rm_line("sk-svcacct-abcdefghijklmnop"));
        assert!(rm_line("sk-admin-abcdefghijklmnop"));
        assert!(rm_line("sk-ant-api03-abcdefghijklmnop"));
        assert!(rm_line("sk-ant-admin01-abcdefghijklmnop"));
        assert!(rm_line("hf_abcdefghijklmnopqrstuvwxyzabcdefgh"));
        assert!(rm_line("api_org_abcdefghijklmnopqrstuvwxyzabcdefgh"));
        assert!(rm_line(
            "gsk_abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"
        ));
        assert!(rm_line("r8_abcdefghijklmnopqrstuvwxyz0123456789abcd"));
        assert!(rm_line(
            "pplx-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijkl"
        ));
        assert!(rm_line(
            "xai-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789abcdefgh"
        ));
        assert!(rm_line(
            "sk-or-v1-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        ));
        assert!(rm_line("sk-abcdef0123456789abcdef0123456789"));
        assert!(rm_line("mistral-abcdefghijklmnopqrst"));
        assert!(rm_line("fw_abcdefghijklmnopqrstuvwxyz012345"));
        assert!(rm_line("jina_abcdefghijklmnopqrstuvwx"));
        assert!(rm_line("pa-abcdefghijklmnopqrstuvwxyz0123456789abcd"));
        assert!(rm_line("pcsk_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(rm_line("nvapi-abcdefghijklmnopqrstuvwxyz0123456789abcd"));
        assert!(rm_line("lsv2_pt_abcdefghijklmnopqrstuvwx"));
        assert!(rm_line("csk-abcdefghijklmnopqrstuvwxyz0123456789abcd"));
        assert!(rm_line("sk_abcdefghijklmnopqrstuvwxyz012345"));
        assert!(rm_line(
            "ABSKABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx"
        ));
        assert!(rm_line("bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t"));
        assert!(rm_line("github_pat_abcdefghijklmnopqrstuv"));
        assert!(rm_line("npm_abcdefghijklmnopqrstuvwxyz0123456789"));
        assert!(rm_line(
            "pypi-012345678901234567890123456789012345678901234567890123456789"
        ));
        assert!(rm_line("hvs.abcdefghijklmnopqrstuvwx"));
        assert!(rm_line(
            "curl https://discord.com/api/webhooks/123456789012345678/abcdefghijklmnop"
        ));
        assert!(rm_line("echo \"-----BEGIN OPENSSH PRIVATE KEY-----\""));
        assert!(rm_line("cat <<'EOF' -----BEGIN RSA PRIVATE KEY----- EOF"));
        assert!(rm_line("cat -----BEGIN DSA PRIVATE KEY-----"));
        assert!(rm_line("cat -----BEGIN EC PRIVATE KEY-----"));
        assert!(rm_line("cat -----BEGIN PRIVATE KEY-----"));
        assert!(rm_line("cat -----BEGIN ENCRYPTED PRIVATE KEY-----"));
        assert!(rm_line("cat -----BEGIN PGP PRIVATE KEY BLOCK-----"));
        assert!(rm_line(
            "DefaultEndpointsProtocol=https;AccountName=x;AccountKey=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP==;EndpointSuffix=core.windows.net"
        ));
        assert!(rm_line(
            "mongosh \"mongodb://user:password@localhost:27017/mydb?authSource=admin\""
        ));
        assert!(rm_line("mongodb://user:password@localhost:27017/mydb"));
        assert!(rm_line(
            "mongodb+srv://user:password@cluster0.mongodb.net/mydb"
        ));
        assert!(rm_line("mysql://user:password@localhost:3306/mydb"));
        assert!(rm_line("mysql://root:p%40ss@127.0.0.1:3306/mydb"));
        assert!(rm_line("mysql+pymysql://user:password@localhost:3306/mydb"));
        assert!(rm_line("jdbc:mysql://user:password@localhost:3306/mydb"));
        assert!(rm_line(
            "jdbc:mysql://localhost:3306/mydb?user=root&password=secret"
        ));
        assert!(rm_line(
            "mysql://localhost:3306/mydb?user=root&password=secret"
        ));
        assert!(rm_line("postgres://user:password@localhost:5432/mydb"));
        assert!(rm_line("postgresql://user:password@localhost:5432/mydb"));
        assert!(rm_line(
            "postgresql+psycopg2://user:password@localhost:5432/mydb"
        ));
        assert!(rm_line(
            "jdbc:postgresql://user:password@localhost:5432/mydb"
        ));
        assert!(rm_line(
            "Server=localhost;Database=mydb;Uid=user;Pwd=secret;"
        ));
        assert!(rm_line(
            "Password=secret;Data Source=localhost;Database=mydb;"
        ));
        assert!(rm_line(
            "Host=localhost;Database=mydb;Username=user;Password=secret;"
        ));
        assert!(rm_line(
            "host=localhost port=5432 dbname=mydb user=foo password=secret"
        ));
    }
}
