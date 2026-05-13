# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] — 2026-05-12

Initial release.

### Added

- `TgClient::Client.new(api_id, api_hash, session_file:, dc_id:, test:, logger:)` —
  constructor; no network until `#authenticate` is called.
- `#authenticate(phone:, code_provider:)` — runs the full MTProto 2.0 DH
  handshake (`req_pq_multi` → `req_DH_params` → `set_client_DH_params`) on
  the first run, persists the session, and returns `:resumed` on subsequent
  runs without prompting. Re-handshakes on `PHONE_MIGRATE_N`. Raises
  `TgClient::PasswordRequired` when the account has 2FA enabled.
- `#get_dialogs(limit:)` — fetches dialogs and refreshes the internal
  `access_hash` cache for users and channels.
- `#get_history(chat_id:, date_from:, limit:)` — returns an array of plain
  Ruby hashes `{id:, date: Time, from_id:, from_name:, text:}`. Resolves
  `InputPeer` from the bot-style `chat_id` sign convention
  (`> 0` → user, `> -1_000_000_000_000` → basic group,
  `≤ -1_000_000_000_000` → channel/supergroup).
- TL schema parser, serializer, and deserializer (`TgClient::TL`) handling
  flag bitmaps, conditional params, boxed/bare vectors, bare types, and
  the `string` length-prefix + 4-byte padding encoding. `int128` / `int256`
  are treated as raw bytes.
- Crypto primitives (`TgClient::Crypto`): AES-256-IGE, RSA_PAD,
  MTProto 2.0 `msg_key` + `aes_key`/`iv` derivation, `auth_key_id`,
  Pollard's rho `factor_pq`, and RSA public-key fingerprinting.
- TCP Full transport (`TgClient::Transport`) with CRC32 framing,
  send/recv sequence counters, and DC address tables (production + test).
- Session persistence (`TgClient::Session`) — atomic JSON-with-base64
  writes at mode 0600.
- Vendored Telegram TL schema at layer 225 (sourced from tdlib master)
  and the production + test-DC RSA public keys.

### Documentation

- README with public API reference, chat_id sign convention table, and
  smoke-test instructions.
- `examples/smoke.rb` for end-to-end validation against Telegram's
  production servers.

[Unreleased]: https://github.com/Jhohny/tg_client/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Jhohny/tg_client/releases/tag/v0.1.0
