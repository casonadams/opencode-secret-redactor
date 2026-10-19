# opencode-secret-redactor

An [OpenCode](https://opencode.ai) plugin that prevents secrets from leaking
into LLM context. Secrets detected in tool output are replaced with
`🔒label🔓` tokens before the model sees them, then transparently
restored when a tool needs the real value for execution.

> **V2 note:** this build targets the OpenCode **2.x** plugin API
> (`@opencode/plugin`). OpenCode 2 replaced the V1 plugin contract
> (`"Plugin export is not a function"` on V1 packages — see
> [opencode #31575](https://github.com/anomalyco/opencode/issues/31575)),
> so the V1 plugin is a full rewrite, not a rename. For OpenCode 2.0 and
> newer use this package; it is published on npm as
> **`opencode-secret-redactor-fixed`**.

## Detected secret types

AWS keys, GitHub/GitLab tokens, OpenAI/Anthropic keys, Google Cloud
credentials, Stripe keys, Slack tokens, JWTs, private keys, database
connection strings, and many more. See
[`src/patterns.ts`](src/patterns.ts) for the full list.

## Setup

Add the plugin to `opencode.json(c)` using the V2 `plugins` list:

```json
{
  "plugins": ["opencode-secret-redactor-fixed"]
}
```

A single local file is not a valid plugin entry in V2; point the config at a
**directory** or drop the plugin under `.opencode/plugins/`. From a checkout of
this repository:

```json
{
  "plugins": ["/absolute/path/to/opencode-secret-redactor"]
}
```

The plugin hooks into execution automatically -- no configuration is required
to start.


## Configuration

Everything is optional. Without any config file the plugin scans with the
default pattern set, ignoring values that look like placeholders.

### Config files

Read in this order; later layers win:

1. `secret-redactor.json` in your opencode config directory
   (`~/.config/opencode`, or `$OPENCODE_CONFIG_DIR` if set)
2. `.opencode/secret-redactor.json` in the current project directory
3. The file pointed to by `$SECRET_REDACTOR_CONFIG` -- when set, it
   **replaces** layers 1 and 2, which keeps tests and one-off runs hermetic
4. The environment lists `$SECRET_REDACTOR_ENABLE` and
   `$SECRET_REDACTOR_DISABLE` (comma-separated pattern labels)

Every layer uses the same schema:

```json
{
  "enable": ["email"],
  "disable": ["jwt"],
  "minLength": 12,
  "extraPatterns": [
    { "label": "acme_token", "pattern": "acme_[a-f0-9]{32}", "flags": "g" }
  ]
}
```

- `enable` / `disable`: pattern labels from [`src/patterns.ts`](src/patterns.ts).
  `disable` wins when a label appears in both. Labels only matter for patterns
  that are off by default (such as `email`) or to drop an over-eager pattern.
- `minLength`: shortest value worth redacting (default `8`).
- `extraPatterns`: your own regular expressions, appended to the built-in set.
  A pattern that fails to compile is skipped with a warning.

Malformed JSON and wrong-typed fields are ignored with a warning rather than
failing the plugin.

### Off-by-default patterns

PII patterns ship disabled, because redacting them costs more than it saves.
The current one is `email`; enable it explicitly:

```json
{ "enable": ["email"] }
```

### Placeholders are never secrets

Values that are references to a secret rather than the secret itself are
skipped: `$PASS`, `${DB_PASSWORD}`, `{some_pass}`, `{{vault_password}}`,
`%DEPLOY_TOKEN%`, `<<ACCESS_KEY>>`, `$(PASS)`, `__SECRET__`,
`${{ secrets.FOO }}`. The check matches the **whole** value, so a real secret
that merely contains `$` or braces (a bcrypt hash, for example) is still
redacted.

### Programmatic use

The package also exports `loadConfig`, `resolveConfig`, `configure`,
`getConfig`, `detectSecrets`, and `isPlaceholder`, so secrets can be scanned
outside opencode:

```js
const { loadConfig, configure, detectSecrets } = require("opencode-secret-redactor-fixed");

configure(loadConfig());
const hits = detectSecrets(fs.readFileSync("settings.yml", "utf8"));
```

## How it works

The plugin is a V2 definition (`{ id, setup }`) that registers hooks on the
domains that own each operation:

1. `session.hook("prompt")` redacts secrets in the user prompt before it is
   persisted, so a secret typed into the chat never reaches the transcript or
   the model as plaintext.
2. `session.hook("context")`, together with `"compaction"`, `"generate"`, and
   `"title"`, redacts every model-visible string in an assembled request —
   message text, reasoning, tool-call inputs, tool results, and system
   instructions — immediately before dispatch. Persisted history is not
   modified; only the outgoing request is.
3. `tool.hook("execute.after")` redacts the output of `shell`, `read`, `grep`,
   and `webfetch` before it enters context, storing each value in an in-memory
   vault.
4. `tool.hook("execute.before")` restores real values in `shell`, `write`, and
   `edit` arguments, so a command or file write built from a placeholder runs
   against the real secret.

OpenCode 2 renamed the shell tool from `bash` to `shell`; the default tool
scopes account for that.

## Migration to V2

- The default export is now an OpenCode 2 plugin definition
  (`Plugin.define({ id, setup })`), registered through the V2 hook domains
  instead of a map of `"tool.execute.*"` string keys.
- The V1 `chat.message` hook became `session.hook("prompt")`; the
  `experimental.chat.messages.transform` hook became
  `session.hook("context")` (with `compaction`, `generate`, and `title`
  registered for the auxiliary request kinds).
- The plugin no longer imports `@opencode/plugin` at runtime: it uses the
  package only for types, so the built module is self-contained.
- TUI toasts were dropped. V2 server plugins have no toast API; toasts belong
  to CLI plugins under `@opencode/plugin/tui`, which receive no server-side
  redaction events.

## License

[MIT](LICENSE)

