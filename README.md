# opencode-secret-redactor

An [OpenCode](https://opencode.ai) plugin that prevents secrets from leaking
into LLM context. Secrets detected in tool output are replaced with
`🔒label🔓` tokens before the model sees them, then transparently
restored when a tool needs the real value for execution.

## Detected secret types

AWS keys, GitHub/GitLab tokens, OpenAI/Anthropic keys, Google Cloud
credentials, Stripe keys, Slack tokens, JWTs, private keys, database
connection strings, and many more. See
[`src/patterns.ts`](src/patterns.ts) for the full list.

## Setup

The same package works with OpenCode 2 and OpenCode 1 (1.18.29 or newer).

### OpenCode 2

Add the plugin to your `opencode.json(c)`:

```json
{
  "plugins": ["opencode-secret-redactor@0.6.0"]
}
```

The terminal UI loads the package's `./tui` entry automatically and shows a
toast whenever something is redacted. When the CLI connects to a remote
server, add the TUI plugin to `cli.json` as well:

```json
{
  "plugins": ["opencode-secret-redactor"]
}
```

### OpenCode 1

```json
{
  "plugin": ["opencode-secret-redactor@0.6.0"]
}
```

For OpenCode 1 releases older than 1.18.29, stay on
`opencode-secret-redactor@0.5.1`.

No further configuration is required.

## How it works

1. **After** `bash`/`shell`, `read`, `grep`, or `webfetch` tool output, the
   plugin scans for secrets using pattern matching and stores any matches in
   an in-memory vault.
2. The output sent to the LLM contains only redacted placeholders. User
   prompts and the message history of every model request (including
   compaction and title generation on OpenCode 2) are scrubbed as well.
3. **Before** `bash`/`shell`, `write`, `edit`, or patch tool execution,
   placeholders in the tool arguments are replaced with the original values
   so commands run correctly.

The vault lives only in memory and is never written to disk.

## License

[MIT](LICENSE)
