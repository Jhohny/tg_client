# Contributing to tg_client

Thanks for taking the time to contribute! This document covers the practical bits.

## Setup

```sh
git clone https://github.com/Jhohny/tg_client.git
cd tg_client
bundle install
bundle exec rspec
```

Ruby ≥ 3.2 is required (see `.ruby-version` for the version actively developed against).

## Running the test suite

```sh
bundle exec rspec
```

The suite is **unit-only** — no live calls to Telegram. There are 118+ specs covering the TL parser, AES-IGE, RSA_PAD, the transport framing, session persistence, the RPC dispatcher (with a `FakeTransport` double), the DH handshake helpers, `#authenticate`, `#get_dialogs`, and `#get_history`.

End-to-end validation against the real production DCs goes through `examples/smoke.rb` — see the README for env vars.

## Commit style

We use [Conventional Commits](https://www.conventionalcommits.org/):

* `feat:` — new feature or capability
* `fix:` — bug fix
* `chore:` — tooling, vendoring, dependency bumps
* `docs:` — documentation only
* `test:` — test-only changes
* `refactor:` — restructure without behavior change

Keep each commit independently buildable — `bundle exec rspec` must pass at every commit on the branch.

## Ruby style

* `# frozen_string_literal: true` at the top of every `.rb` file.
* Keyword arguments for any method with more than one argument.
* `Data.define` for immutable value objects (Ruby 3.2+); `Struct.new(..., keyword_init: true)` only when mutation is required.
* `attr_reader` over hand-written getters.
* `private_constant` for module-internal constants.
* Binary-safe strings — use `String#b` (or `.b` literals) for byte buffers; never concat a UTF-8 string with binary.
* `pack`/`unpack1` with explicit directives (`Q<`, `L<`, `l<`, `a16`, `C`, etc.).
* `StringIO` for stream serialization.
* No monkey-patching of core classes.
* No `rescue Exception` — use `rescue StandardError` or specific subclasses.
* Errors subclass `TgClient::Error`; never raise `RuntimeError` or a bare string.
* `SecureRandom.bytes` for nonces and padding (not `Random#bytes`).

## Updating the bundled TL schema

The Telegram schema lives under `lib/tg_client/schema/`:

* `api.tl` and `mtproto.tl` are sourced from [tdlib master](https://github.com/tdlib/td/tree/master/td/generate/scheme).
* `public_keys.pem` holds the production and test-DC RSA public keys from tdlib's `PublicRsaKeySharedMain.cpp`.

When bumping the schema:

1. Pull the latest `telegram_api.tl` and `mtproto_api.tl` from tdlib.
2. **Re-apply the local edits to `mtproto.tl`**: uncomment `rpc_result`, `msg_container`, `message`, and `ping`, and switch the `result`/`body` fields from `string` to `Object` (tdlib comments these out because its generator handles them specially; we need them in the registry).
3. Update `TgClient::SCHEMA_LAYER` in `lib/tg_client/version.rb` to the new layer number (check `td/telegram/Version.h` in tdlib for `MTPROTO_LAYER`).
4. Run the suite and the smoke script to confirm nothing regressed.
5. Land it as a single `chore: bump TL schema to layer N` commit.

## Reporting issues

* For security issues, please **do not** open a public issue — email `jhonathan.amezcua@gmail.com` directly.
* For bugs or feature ideas, open an issue at <https://github.com/Jhohny/tg_client/issues>. Include the Ruby version, the gem version, and a minimal reproduction if possible.

## Pull requests

1. Fork and create a topic branch.
2. Make small, focused commits with clear messages.
3. Add or update specs for any behavior change.
4. Ensure `bundle exec rspec` is green.
5. Open the PR against `main` with a short description of what changed and why.
