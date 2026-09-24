import { describe, expect, it } from "vitest";
import { detectSecrets } from "./detector.js";

describe("detectSecrets", () => {
  it("detects a JWT token", () => {
    const jwt =
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
    const results = detectSecrets(`token: ${jwt}`);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^jwt_/);
    expect(results[0].value).toBe(jwt);
  });

  it("detects a GitLab PAT", () => {
    const pat = "glpat-xyzABCDEFGH12345678901234";
    const results = detectSecrets(pat);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^gitlab_pat_/);
  });

  it("detects a GitLab pipeline trigger token", () => {
    const token = "glptt-abcdefghijklmnopqrstuvwx";
    const results = detectSecrets(token);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^gitlab_pipeline_trigger_/);
  });

  it("detects a GitHub PAT", () => {
    const pat = "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234";
    const results = detectSecrets(pat);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^github_pat_/);
  });

  it("detects a gcloud access token", () => {
    const token = "ya29.a0ARrdaM8abc123def456ghi789jkl012mno345pqr678stu901vwx234yz";
    const results = detectSecrets(token);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^gcloud_access_token_/);
  });

  it("detects an AWS access key", () => {
    const results = detectSecrets("key: AKIAIOSFODNN7EXAMPLE");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^aws_access_key_/);
  });

  it("detects an AWS secret key with context", () => {
    const results = detectSecrets("AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^aws_secret_key_/);
    expect(results[0].value).toBe("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY");
  });

  it("does not false-positive on random UUIDs", () => {
    const results = detectSecrets("id: 550e8400-e29b-41d4-a716-446655440000");

    const herokuMatch = results.find((r) => r.label.startsWith("heroku"));
    expect(herokuMatch).toBeUndefined();
  });

  it("detects multiple secrets in one text", () => {
    const text = [
      "glpat-xyzABCDEFGH12345678901234",
      "ghp_1234567890abcdefghijklmnopqrstuvwxyz1234",
    ].join(" and ");

    const results = detectSecrets(text);

    expect(results.length).toBeGreaterThanOrEqual(2);
  });

  it("detects a database connection string", () => {
    const results = detectSecrets("postgres://admin:s3cretP4ss@db.example.com:5432/mydb");

    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].label).toMatch(/^database_url_/);
  });

  it("detects a private key block", () => {
    const key =
      "-----BEGIN RSA PRIVATE KEY-----\nMIIBogIBAAJBANLJhPHhITqQbPklG3ibCVxwGMRfp/v4XqhfdQHdcVfHap6NQ5Wo\nk/4xIA+ui35/MmNartNuC+BdMhz+dl2qNh0CAwEAAQ==\n-----END RSA PRIVATE KEY-----";
    const results = detectSecrets(key);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^private_key_/);
  });

  it("ignores strings shorter than minimum length", () => {
    const results = detectSecrets("sk-abc");

    expect(results).toHaveLength(0);
  });

  // -- Azure / Microsoft --
  it("detects an Azure storage key", () => {
    const key =
      "AccountKey=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwx==";
    const results = detectSecrets(key);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^azure_storage_key_/);
  });

  it("detects an Azure SAS token", () => {
    const url =
      "https://myaccount.blob.core.windows.net/c?sv=2021-06-08&sig=dGhpcyBpcyBhIGZha2Ugc2lnbmF0dXJlIHZhbHVl%2BTest%3D%3D";
    const results = detectSecrets(url);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^azure_sas_token_/);
  });

  // -- Shopify --
  it("detects a Shopify access token", () => {
    // Split to avoid GitHub push protection flagging the literal
    const token = ["shpat", "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"].join("_");
    const results = detectSecrets(token);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^shopify_access_token_/);
  });

  // -- Additional SaaS --
  it("detects a Mailgun API key", () => {
    const results = detectSecrets("key-3ax6xnjp29jd6fds4gc373sgvjxteol0");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^mailgun_api_key_/);
  });

  it("detects a Mailchimp API key", () => {
    // Split to avoid GitHub push protection flagging the literal
    const key = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" + "-us12";
    const results = detectSecrets(key);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^mailchimp_api_key_/);
  });

  it("detects a Docker PAT", () => {
    const results = detectSecrets("dckr_pat_a1b2c3d4e5f6a7b8c9d0e1f2");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^docker_pat_/);
  });

  it("detects a Terraform Cloud token", () => {
    const token =
      "a1B2c3D4e5F6g7.atlasv1.a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a1b2c3d4e5f6a7b8c9d0e1f2";
    const results = detectSecrets(token);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^terraform_cloud_token_/);
  });

  // -- SSH public keys --
  it("detects an SSH ed25519 public key", () => {
    const key =
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyDataHereForTestingPurposesOnlyNotARealKey";
    const results = detectSecrets(key);

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^ssh_public_key_/);
  });

  // -- PII --
  it("detects an email address", () => {
    const results = detectSecrets("contact john.doe@example.com for info");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^email_/);
  });

  it("detects a credit card number", () => {
    const results = detectSecrets("card: 4111 1111 1111 1111");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^credit_card_/);
  });

  it("detects a credit card without separators", () => {
    const results = detectSecrets("card: 4111111111111111");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^credit_card_/);
  });

  // -- Regression: credit_card false positive on long digit runs --
  it("does not detect the SolarEdge float32-max sentinel as a credit card", () => {
    const results = detectSecrets(
      "export_control_site_limit: -340282346638528859811704183484516925440",
    );

    const creditCardMatch = results.find((r) => r.label.startsWith("credit_card"));
    expect(creditCardMatch).toBeUndefined();
  });

  it("does not detect non-Luhn digit windows as credit cards", () => {
    const results = detectSecrets("3402823466385288");
    const creditCardMatch = results.find((r) => r.label.startsWith("credit_card"));
    expect(creditCardMatch).toBeUndefined();
  });

  it("still detects Luhn-valid card-shaped numbers even when isolated", () => {
    // 418348451692544 is a Luhn-valid 15-digit window of the SolarEdge
    // sentinel; it is indistinguishable from a real card and must remain
    // detectable when isolated.
    const results = detectSecrets("418348451692544");
    const creditCardMatch = results.find((r) => r.label.startsWith("credit_card"));
    expect(creditCardMatch).toBeDefined();
  });

  it("detects a US SSN", () => {
    const results = detectSecrets("ssn is 123-45-6789");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^us_ssn_/);
  });

  it("detects a US phone number", () => {
    const results = detectSecrets("call +1-555-867-5309");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^phone_us_/);
  });

  // -- Generic env var secrets --
  it("detects a PASSWORD env var", () => {
    const results = detectSecrets("PASSWORD=SuperSecretPassword123");

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^env_secret_/);
  });

  it("detects a quoted SECRET env var", () => {
    const results = detectSecrets('SECRET="my-secret-value-here"');

    expect(results).toHaveLength(1);
    expect(results[0].label).toMatch(/^env_secret_/);
  });

  it("does not match env vars with short values", () => {
    const results = detectSecrets("PASSWORD=short");

    expect(results).toHaveLength(0);
  });
});
