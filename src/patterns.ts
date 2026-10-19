export interface SecretPattern {
  readonly label: string;
  readonly pattern: RegExp;
  // Absent means enabled by default. Patterns with `defaultEnabled: false`
  // stay in the catalog but are only active when listed in config `enable`.
  readonly defaultEnabled?: boolean;
}

// Ordered so more specific prefixes come before generic ones to prevent
// a generic pattern from consuming a match that a specific one would
// label more accurately.

export const PATTERNS: ReadonlyArray<SecretPattern> = [
  // -- GitLab token family --
  { label: "gitlab_pat", pattern: /glpat-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_pipeline_trigger", pattern: /glptt-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_deploy_token", pattern: /gldt-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_ci_job_token", pattern: /glcbt-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_runner_token", pattern: /glrt-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_service_account", pattern: /glsoat-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_feed_token", pattern: /glft-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_incoming_mail", pattern: /glimt-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_oauth_secret", pattern: /gloas-[A-Za-z0-9\-_]{20,}/g },
  { label: "gitlab_agent_token", pattern: /glagent-[A-Za-z0-9\-_]{20,}/g },
  // -- GitHub token family --
  { label: "github_pat", pattern: /ghp_[A-Za-z0-9]{36,}/g },
  { label: "github_oauth", pattern: /gho_[A-Za-z0-9]{36,}/g },
  { label: "github_app_token", pattern: /ghu_[A-Za-z0-9]{36,}/g },
  { label: "github_app_install", pattern: /ghs_[A-Za-z0-9]{36,}/g },
  { label: "github_fine_grained", pattern: /github_pat_[A-Za-z0-9_]{22,}/g },
  // -- AWS --
  { label: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/g },
  {
    label: "aws_secret_key",
    pattern:
      /(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY|SecretAccessKey)[=:\s"']+([A-Za-z0-9/+=]{40})/g,
  },
  // -- AI providers (anthropic before openai to avoid prefix collision) --
  { label: "anthropic_key", pattern: /sk-ant-[A-Za-z0-9\-_]{20,}/g },
  { label: "openai_project_key", pattern: /sk-proj-[A-Za-z0-9\-_]{20,}/g },
  { label: "openai_key", pattern: /sk-(?!ant-)(?!proj-)[A-Za-z0-9]{20,}/g },
  { label: "cohere_key", pattern: /co-[A-Za-z0-9]{30,}/g },
  { label: "huggingface_token", pattern: /hf_[A-Za-z0-9]{30,}/g },
  // -- Google Cloud --
  { label: "google_api_key", pattern: /AIza[0-9A-Za-z\-_]{35}/g },
  { label: "google_oauth_secret", pattern: /GOCSPX-[A-Za-z0-9\-_]{28}/g },
  { label: "gcloud_access_token", pattern: /ya29\.[A-Za-z0-9\-_]{50,}/g },
  { label: "google_refresh_token", pattern: /1\/\/[A-Za-z0-9\-_]{40,}/g },
  // -- Cloud infrastructure --
  { label: "digitalocean_pat", pattern: /dop_v1_[a-f0-9]{64}/g },
  { label: "digitalocean_oauth", pattern: /doo_v1_[a-f0-9]{64}/g },
  { label: "hashicorp_vault", pattern: /hvs\.[A-Za-z0-9]{24,}/g },
  {
    label: "heroku_api_key",
    pattern:
      /(?:HEROKU_API_KEY|heroku_api_key)[=:\s"']+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/g,
  },
  { label: "vercel_token", pattern: /vercel_[A-Za-z0-9]{24,}/g },
  // -- SaaS --
  { label: "slack_token", pattern: /xox[bpors]-[A-Za-z0-9-]{10,}/g },
  {
    label: "slack_webhook",
    pattern: /hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/g,
  },
  { label: "twilio_api_key", pattern: /SK[a-f0-9]{32}/g },
  { label: "sendgrid_key", pattern: /SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{22,}/g },
  { label: "postman_key", pattern: /PMAK-[A-Za-z0-9-]{50,}/g },
  { label: "datadog_api_key", pattern: /dd[a-z]{1,2}_[A-Za-z0-9]{32,40}/g },
  // -- Payments --
  { label: "stripe_secret", pattern: /sk_(?:test|live)_[A-Za-z0-9]{10,}/g },
  { label: "stripe_restricted", pattern: /rk_(?:test|live)_[A-Za-z0-9]{10,}/g },
  { label: "stripe_webhook", pattern: /whsec_[A-Za-z0-9]{32,}/g },
  { label: "square_access_token", pattern: /sq0atp-[A-Za-z0-9\-_]{22,}/g },
  { label: "square_oauth", pattern: /sq0csp-[A-Za-z0-9\-_]{43}/g },
  // -- Package registries --
  { label: "npm_token", pattern: /npm_[A-Za-z0-9]{36,}/g },
  { label: "pypi_token", pattern: /pypi-[A-Za-z0-9\-_]{50,}/g },
  { label: "rubygems_key", pattern: /rubygems_[A-Za-z0-9]{48}/g },
  // -- Auth tokens --
  { label: "jwt", pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { label: "bearer_token", pattern: /Bearer\s+[A-Za-z0-9\-._~+/]+=*/g },
  { label: "basic_auth", pattern: /Basic\s+[A-Za-z0-9+/]{10,}={0,2}/g },
  {
    label: "private_key",
    pattern:
      /-----BEGIN\s+(?:RSA\s+|EC\s+|ED25519\s+|DSA\s+)?PRIVATE\s+KEY-----[\s\S]*?-----END\s+(?:RSA\s+|EC\s+|ED25519\s+|DSA\s+)?PRIVATE\s+KEY-----/g,
  },
  // -- Database URLs --
  {
    label: "database_url",
    pattern: /(?:postgres|postgresql|mysql|mongodb|mongodb\+srv|redis):\/\/[^:\s]+:[^@\s]+@[^\s]+/g,
  },
  // -- Observability --
  { label: "sentry_dsn", pattern: /https:\/\/[a-f0-9]{32}@[^\s/]+\.ingest\.sentry\.io\/[0-9]+/g },
  { label: "grafana_api_key", pattern: /glc_[A-Za-z0-9\-_]{32,}/g },
  { label: "doppler_token", pattern: /dp\.st\.[A-Za-z0-9_-]{40,}/g },
  // -- Azure / Microsoft --
  {
    label: "azure_connection_string",
    pattern:
      /DefaultEndpointsProtocol=https?;AccountName=[^;\s]+;AccountKey=[A-Za-z0-9+/]{86}==[^\s"']*/g,
  },
  { label: "azure_storage_key", pattern: /AccountKey=([A-Za-z0-9+/]{86}==)/g },
  { label: "azure_sas_token", pattern: /[?&]sig=([A-Za-z0-9%+/=]{40,})/g },
  // -- Shopify --
  { label: "shopify_access_token", pattern: /shpat_[a-fA-F0-9]{20,}/g },
  { label: "shopify_custom_app", pattern: /shpca_[a-fA-F0-9]{20,}/g },
  { label: "shopify_private_app", pattern: /shppa_[a-fA-F0-9]{20,}/g },
  { label: "shopify_shared_secret", pattern: /shpss_[a-fA-F0-9]{20,}/g },
  // -- Additional SaaS --
  { label: "mailgun_api_key", pattern: /key-[a-z0-9]{30,}/g },
  { label: "mailchimp_api_key", pattern: /[a-f0-9]{32}-us\d{1,2}/g },
  { label: "linear_api_key", pattern: /lin_api_[A-Za-z0-9]{40,}/g },
  {
    label: "terraform_cloud_token",
    pattern: /[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9\-_]{60,}/g,
  },
  { label: "pulumi_token", pattern: /pul-[a-f0-9]{40}/g },
  { label: "docker_pat", pattern: /dckr_pat_[A-Za-z0-9\-_]{24,}/g },
  { label: "age_secret_key", pattern: /AGE-SECRET-KEY-1[A-Za-z0-9]{58}/g },
  // -- SSH public keys --
  { label: "ssh_public_key", pattern: /ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{60,}={0,2}/g },
  {
    label: "ssh_ecdsa_key",
    pattern: /ecdsa-sha2-nistp(?:256|384|521)\s+[A-Za-z0-9+/]{60,}={0,2}/g,
  },
  // -- PII --
  // Off by default: email addresses are everywhere in ordinary file reads
  // (configs, catalogs, vendored code) and redacting them breaks workflows.
  {
    label: "email",
    defaultEnabled: false,
    pattern: /(?<![:/])[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
  },
  {
    label: "credit_card",
    pattern:
      /\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6(?:011|5[0-9]{2}))[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{3,4}\b/g,
  },
  { label: "us_ssn", pattern: /\b\d{3}-\d{2}-\d{4}\b/g },
  { label: "phone_us", pattern: /\+1[-.\s]?\(?[2-9]\d{2}\)?[-.\s]?[2-9]\d{2}[-.\s]?\d{4}/g },
  // -- Generic env var secrets (last -- most generic) --
  {
    label: "env_secret",
    pattern:
      /(?:PASSWORD|PASSWD|SECRET|API_KEY|PRIVATE_KEY|ACCESS_KEY|AUTH_TOKEN|ENCRYPTION_KEY|SIGNING_KEY|DB_PASSWORD|DATABASE_PASSWORD)\s*[=:]\s*["']?([^\s"']{8,})["']?/gi,
  },
];
