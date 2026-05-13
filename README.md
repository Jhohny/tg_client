# tg_client

A minimal Ruby MTProto 2.0 client for **reading Telegram chat history**.

Two public methods, plain Ruby hashes out, session persistence so you only authenticate once.

```ruby
require "tg_client"

client = TgClient::Client.new(api_id, api_hash, session_file: "~/.tg_session")
client.authenticate(phone: "+521234567890")   # prompts for code on first run only

messages = client.get_history(
  chat_id:   -1001234567890,        # supergroup; see "Chat IDs" below
  date_from: Date.today - 1,
  limit:     200
)
# => [{ id:, date:, from_id:, from_name:, text: }, ...]
```

## Install

Add to your Gemfile:

```ruby
gem "tg_client", path: "."   # while developing locally
```

Or build and install:

```
gem build tg_client.gemspec && gem install tg_client-0.1.0.gem
```

Requires Ruby ≥ 3.2.

## Credentials

You need an `api_id` and `api_hash` from <https://my.telegram.org>. Each phone number can only register one pair.

## API

### `Client.new(api_id, api_hash, session_file:, dc_id:, test:, logger:)`

Constructs a client. No network until `authenticate`.

* `session_file` — path (with `~` expansion) where the post-handshake auth key is persisted. Default `"~/.tg_session"`.
* `dc_id` — DC to start the handshake on. Default 2 (most accounts live there; the gem follows `PHONE_MIGRATE_N` automatically).
* `test` — use Telegram's test DCs instead of production.
* `logger` — a `Logger`. Default silent (`Logger.new(IO::NULL)`).

### `#authenticate(phone:, code_provider: nil)`

* If `session_file` exists, restores it and returns `:resumed` without any prompts.
* Otherwise runs the DH handshake, calls `auth.sendCode`, prompts for the verification code, calls `auth.signIn`, saves the session, and returns `:authenticated`.
* `code_provider` overrides the `$stdin` prompt — useful for tests / non-interactive scripts.
* Raises `TgClient::PasswordRequired` if the account has 2FA enabled (cloud passwords are intentionally not supported).

### `#get_dialogs(limit: 100)`

Returns the raw `messages.dialogs` response and fills the internal peer cache with `access_hash` values for users and channels. Call this once before `get_history` on a peer you haven't seen.

### `#get_history(chat_id:, date_from:, limit: 100)`

Returns an array of plain hashes:

```ruby
[
  { id: 12345, date: Time, from_id: 100, from_name: "Ada Lovelace", text: "hello" },
  ...
]
```

`date_from` may be a `Date`, `Time`, or `Integer` (unix timestamp); only messages older than this are returned (Telegram's `offset_date` semantics).

## Chat IDs

The `chat_id` argument follows the bot-style convention:

| value                                 | resolves to              |
| ------------------------------------- | ------------------------ |
| `chat_id > 0`                         | user (DM)                |
| `-(1..999_999_999_999)`               | basic group              |
| `chat_id ≤ -1_000_000_000_000`        | channel / supergroup     |

Users and channels need an `access_hash` — call `get_dialogs` first to populate the cache.

## Smoke test

```
TG_API_ID=12345 TG_API_HASH=abc TG_PHONE=+1... TG_CHAT=-100... ruby examples/smoke.rb
```

See `examples/smoke.rb`.

## What this doesn't do

* No 2FA / cloud password support (raises `PasswordRequired` instead).
* No sending messages.
* No streaming updates.
* No file uploads/downloads.
* No CDN DC handling.

## License

MIT.
