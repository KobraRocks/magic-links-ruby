# Magic Links

Magic Links is a Ruby stdlib-only helper for creating and verifying cryptographically signed "magic link" tokens. It is framework-agnostic and works in Rails, Sinatra, Hanami, Rack, or plain Ruby.

- **Deterministic signing** via HMAC-SHA256 with key rotation support.
- **Replay protection** using one-time `jti` tracking.
- **Context binding** for user-agent/IP fingerprints.
- **Redirect vetting** with optional origin allow list.
- **No external runtime dependencies**.

Read `SPEC.md` for the full security model and expected behavior.

## Getting Started

```ruby
require 'magic_links'

MagicLinks.configure do |c|
  c.issuer = 'my-app'
  c.allowed_audiences = %w[login email_change]
  c.origin_whitelist = ['https://example.com']
  c.clock_skew = 30
  c.default_ttl = 15 * 60
  c.active_kid = 'k1'
  c.keys = {
    'k1' => ENV.fetch('MLINK_K1'),
    'k0' => ENV.fetch('MLINK_K0', '0' * 32) # retired key kept for validation
  }
  c.store = MagicLinks::MemoryStore.new # swap for a production store (see below)
  c.hash_user_agent = true
  c.hash_ip = false
end
```

- `issuer` must uniquely identify the application accepting the links.
- `keys` is a hash keyed by `kid`, containing binary strings ≥32 bytes.
- `active_kid` controls which key is used for new tokens; older keys remain valid for verification.
- `store` implements the replay protection contract and defaults to a mutex-backed in-memory store.

## Issuing and Verifying

```ruby
issued = MagicLinks.issue(
  aud: 'login',
  sub: user.id,
  ttl: 10 * 60,
  redir: '/app',
  ctx: { user_agent: request.user_agent, ip: request.remote_ip }
)

url = MagicLinks.url(base: login_magic_url, token: issued)
Mailer.magic_link(user.email, url).deliver_later
```

Later, when handling the callback:

```ruby
verified = MagicLinks.verify!(
  params[:ml],
  request_context: { user_agent: request.user_agent, ip: request.remote_ip },
  expected_aud: 'login'
)

sign_in(User.find(verified.sub))
redirect_to(verified.redir || root_path)
```

All verification failures raise a subclass of `MagicLinks::Error`. You can rescue broadly and map to HTTP 401/400 depending on `err.class`.

## Rack Middleware Helper

For Rack-compatible apps you can opt into the bundled middleware. It **does not** add a runtime dependency on Rack; the helper only activates if `Rack::Request` is available.

```ruby
# config.ru
data_store = MyMagicLinkStore.new
MagicLinks.configure do |c|
  # ...
  c.store = data_store
end

use MagicLinks::RackMiddleware, param: 'ml', expected_aud: 'login', on_error: lambda { |env, err|
  env['rack.errors'].puts("magic link failed: #{err.class}: #{err.message}")
}
```

When a token is present the middleware verifies it, stores the result in `env['magic_links.token']`, and allows the request to continue. Failures are captured in `env['magic_links.error']` and control returns to downstream middleware/handlers.

## Telemetry Hook

```ruby
MagicLinks.on_event do |event, data|
  # event is :issued, :verified, or :error
  # data includes :aud, :jti, and optionally :err_class / :err_message
  Metrics.increment("magic_links.#{event}", tags: data)
end
```

Multiple handlers can be registered; errors inside handlers are swallowed so they cannot break issuance/verification.

## Production Store Adapters

`MagicLinks::MemoryStore` is perfect for tests and single-process servers, but production deployments typically need a shared store. Implement `MagicLinks::Store` with two methods: `mark_used!(jti:, exp:)` (atomic first-write wins) and optional `used?(jti:)`/`sweep!` helpers.

### SQLite (SQL Example)

```ruby
# Table DDL (SQLite)
# CREATE TABLE magic_link_tokens (
#   jti TEXT PRIMARY KEY,
#   exp INTEGER NOT NULL
# );

require 'sqlite3'

class SqliteStore < MagicLinks::Store
  def initialize(path = ENV.fetch('MLINK_DB_PATH', 'magic_links.sqlite3'))
    @db = SQLite3::Database.new(path)
    @db.busy_timeout = 5000
  end

  def mark_used!(jti:, exp:)
    @db.execute('INSERT OR IGNORE INTO magic_link_tokens (jti, exp) VALUES (?, ?)', [jti, exp])
    @db.changes.positive?
  end

  def sweep!
    @db.execute('DELETE FROM magic_link_tokens WHERE exp < ?', [Time.now.to_i])
  end
end
```

`INSERT OR IGNORE` makes the first caller succeed and subsequent replays fail without raising. Swap in any other SQLite client if you prefer; the gem itself does not depend on it.

### Redis Example

```ruby
require 'redis'

class RedisStore < MagicLinks::Store
  def initialize(client = Redis.new)
    @client = client
  end

  def mark_used!(jti:, exp:)
    ttl = [exp - Time.now.to_i, 0].max
    @client.set("mlink:jti:#{jti}", 1, nx: true, ex: ttl) ? true : false
  end

  def used?(jti:)
    @client.exists?("mlink:jti:#{jti}")
  end
end
```

The key pattern `mlink:jti:<jti>` is short-lived; TTL is derived from the token expiration. Consider running periodic cleanup for metrics if you need better observability.

## Testing

The repository includes a `Minitest` suite (`ruby -Itest test/test_magic_links.rb`) covering signing, time window enforcement, replay protection, redirect validation, key rotation, context binding, and malformed tokens.

## License

MIT. See `LICENSE` for details.
