# Magic Links Gem — Technical Specification (stdlib-only)

## 0) Goals & non-goals

**Goals**

* Generate cryptographically signed, URL-safe “magic link” tokens.
* Validate tokens server-side with strong replay protection and key rotation.
* Provide a small, portable API that works in Rails, Sinatra, Hanami, Rack, or custom apps.
* Zero external dependencies (Ruby stdlib only).

**Non-goals**

* Not a full email sender.
* Not a user/session system—this gem proves the link; your app decides what to do next.

---

## 1) Security model & threat assumptions

* **Confidentiality of token**: Token is transported via email. Assume the mail channel can be phished/forwarded; the token is **bearer** unless additional context binding is enabled.
* **Integrity**: Enforced via HMAC-SHA256 (OpenSSL stdlib).
* **Replay**: Prevented with one-time use (`jti`) + store. Expiration (`exp`) and optional “not before” (`nbf`) enforced.
* **Key compromise**: Mitigated via **key rotation** (`kid`) and short TTL.
* **Network adversaries**: Token is signed (integrity) but not encrypted (no secrets inside payload).
* **Phishing**: Mitigated by audience/action scoping, optional context binding (user-agent/IP hash), and **origin pinning** in verification.

---

## 2) Token design

### 2.1 Format (compact, JWT-like but simpler)

`<base64url(header)>.<base64url(payload)>.<base64url(signature)>`

* **header (JSON)**:

  * `alg`: `"HS256"`
  * `typ`: `"MLINK"`
  * `v`: `1`
  * `kid`: string key id (for rotation)

* **payload (JSON)** (UTF-8, no secrets):

  * `iss`: issuer (e.g., `"your-app-name"` or origin)
  * `aud`: audience string (e.g., `"login"`, `"email_change"`)
  * `sub`: subject (user id, email hash, etc.)
  * `exp`: expiration (unix seconds)
  * `iat`: issued at (unix seconds)
  * `nbf`: (optional) not-before (unix seconds)
  * `jti`: unique id (nonce) for one-time use
  * `redir`: (optional) relative path or allowlisted absolute URL for post-success redirect
  * `ctx`: (optional) context binding object (see §6.2)
  * `meta`: (optional) arbitrary small JSON (UI copy, A/B bucket, etc.)

* **signature**:

  * `HMAC-SHA256(secret_for_kid, "#{b64(header)}.#{b64(payload)}")`

* **Encoding**: URL-safe Base64 (no padding), using `Base64.urlsafe_encode64(data, padding: false)`.

### 2.2 Key requirements

* Key is at least **32 bytes** from `SecureRandom.bytes(32)`.
* Multiple keys held in memory keyed by `kid`. Exactly one **active** key for issuing; all keys valid for verifying until retired.

---

## 3) Link transport

* Embed token in a query param, default `ml`:

  ```
  https://example.com/magic?ml=<token>
  ```
* The gem must **not** auto-append UTM or PII.
* Optional **fragment** is not used (fragments aren’t sent to servers).

---

## 4) Public API (high-level)

```ruby
module MagicLinks
  # Configuration (process-wide)
  MagicLinks.configure do |c|
    c.issuer = "my-app"                          # required
    c.allowed_audiences = %w[login email_change] # optional allowlist
    c.origin_whitelist = ["https://example.com"] # for redir vetting
    c.clock_skew = 30                             # seconds
    c.default_ttl = 15 * 60                       # seconds
    c.active_kid = "k1"                           # required
    c.keys = { "k1" => ENV["MLINK_K1"].b, "k0" => ENV["MLINK_K0"].b } # String=>binary
    c.store = MagicLinks::MemoryStore.new        # implements Store interface
    c.hash_user_agent = true                      # optionally bind context
    c.hash_ip = false                             # see §6.2 caveats
  end

  # Issue a token and, optionally, a full URL
  def self.issue(aud:, sub:, ttl: nil, redir: nil, meta: nil, ctx: nil) -> IssuedToken
  end

  # Verify token string and mark as used (one-time)
  def self.verify!(token_string, request_context: nil, expected_aud: nil) -> VerifiedToken
  end

  # Build a URL given a token (helper)
  def self.url(base:, token:, param: "ml") -> String
  end

  # Errors
  class Error < StandardError; end
  class Expired < Error; end
  class NotYetValid < Error; end
  class InvalidSignature < Error; end
  class InvalidAudience < Error; end
  class InvalidIssuer < Error; end
  class UsedToken < Error; end
  class InvalidRedirect < Error; end
  class Malformed < Error; end
end
```

**Return types**

```ruby
IssuedToken = Struct.new(:token, :jti, :exp, :kid, :aud, :sub, keyword_init: true)
VerifiedToken = Struct.new(:aud, :sub, :jti, :exp, :iat, :redir, :meta, :raw_payload, keyword_init: true)
```

---

## 5) Storage & replay prevention

### 5.1 Store interface (no external deps)

```ruby
module MagicLinks
  class Store
    # Atomically mark jti as used until exp. Return true if newly marked, false if already used.
    def mark_used!(jti:, exp:) -> bool; raise NotImplementedError; end
    # Optional: was it seen? (non-atomic read helper)
    def used?(jti:) -> bool; raise NotImplementedError; end
    # Optional: cleanup or compaction hook
    def sweep!; end
  end
end
```

### 5.2 Reference in-memory store (for dev/test)

* Implemented with `Hash` + `Mutex`.
* Purges on `sweep!` of expired entries.
* Not suitable for multi-process deployments.

### 5.3 Production stores

* Ship **adapters** as modules that users can copy—**no runtime deps**:

  * **SQL example**: shows table DDL and Ruby adapter using `pg`/`mysql2` if available, but **adapter not required** by gem.
  * **Redis example**: shows key pattern `mlink:jti:<jti>` with `SETNX` + `EXPIRE`.

*(We include adapters as documentation/snippets; the gem’s core requires only the `Store` interface.)*

---

## 6) Verification rules

### 6.1 Hard checks (fail closed)

1. **Well-formed** token (3 parts, JSON decodes).
2. **`alg`** is `"HS256"`, **`typ`** `"MLINK"`, **`v`** `1`.
3. **Signature** matches for **any configured key** (`kid` must exist).
4. **`iss`** equals configured `issuer`.
5. **`aud`** is in `allowed_audiences` (if set) and/or matches `expected_aud` argument.
6. **Time**:

   * `exp` in future (allow `clock_skew`).
   * `nbf` in past (allow `clock_skew`).
   * `iat` not too far in future (bound by `clock_skew`).
7. **Replay**: `store.mark_used!(jti, exp)` must return true (first use).
8. **Redirect**:

   * `redir` empty ⇒ fine.
   * If present: must be **relative path** OR absolute URL with host in `origin_whitelist`. Reject otherwise.

### 6.2 Optional context binding (phishing/replay mitigation)

* If `hash_user_agent`: include a short hash in payload `ctx.ua = sha256(truncated_user_agent)`.
* If `hash_ip`: include `ctx.ip = ip_cidr(ip, /24 for IPv4, /64 for IPv6)` to resist NAT churn.
* On verify, recompute from `request_context` and require equality. **Caveat**: behind proxies/load balancers, ensure you trust the source of IP/UA.

*(Use OpenSSL::Digest::SHA256, hex or base64url.)*

---

## 7) Issuance algorithm (pseudocode)

```ruby
def issue(aud:, sub:, ttl: nil, redir: nil, meta: nil, ctx: nil)
  now = Time.now.to_i
  exp = now + (ttl || config.default_ttl)
  jti = SecureRandom.hex(16) # 128-bit

  payload = {
    "iss" => config.issuer,
    "aud" => aud,
    "sub" => sub,
    "iat" => now,
    "exp" => exp,
    "jti" => jti
  }
  payload["nbf"] = ctx[:nbf] if ctx&.key?(:nbf)
  payload["redir"] = redir if redir
  payload["meta"] = meta if meta

  if config.hash_user_agent && ctx&.dig(:user_agent)
    payload["ctx"] ||= {}
    payload["ctx"]["ua"] = sha256_8(ctx[:user_agent]) # 8 bytes urlsafe b64
  end
  if config.hash_ip && ctx&.dig(:ip)
    payload["ctx"] ||= {}
    payload["ctx"]["ip"] = cidr_hash(ctx[:ip])
  end

  header = { "alg" => "HS256", "typ" => "MLINK", "v" => 1, "kid" => config.active_kid }
  token = sign_compact(header, payload, config.keys[config.active_kid])
  IssuedToken.new(token:, jti:, exp:, kid: config.active_kid, aud:, sub:)
end
```

---

## 8) Verification algorithm (pseudocode)

```ruby
def verify!(token_str, request_context: nil, expected_aud: nil)
  header, payload, sig = parse_compact(token_str)
  key = config.keys[header["kid"]] or raise InvalidSignature
  verify_signature!(header, payload, sig, key)

  now = Time.now.to_i
  skew = config.clock_skew
  raise Expired      if payload["exp"] <= now - skew
  raise NotYetValid  if payload["nbf"] && payload["nbf"] > now + skew
  raise Malformed    if payload["iat"] && payload["iat"] > now + skew
  raise InvalidIssuer  unless payload["iss"] == config.issuer
  if expected_aud
    raise InvalidAudience unless payload["aud"] == expected_aud
  elsif config.allowed_audiences&.any?
    raise InvalidAudience unless config.allowed_audiences.include?(payload["aud"])
  end

  # Context binding checks
  if (ctx = payload["ctx"])
    if ctx["ua"] && request_context&.dig(:user_agent)
      raise InvalidSignature unless ctx["ua"] == sha256_8(request_context[:user_agent])
    end
    if ctx["ip"] && request_context&.dig(:ip)
      raise InvalidSignature unless ctx["ip"] == cidr_hash(request_context[:ip])
    end
  end

  # One-time use
  used = config.store.mark_used!(jti: payload["jti"], exp: payload["exp"])
  raise UsedToken unless used

  # Redirect vetting
  redir = vet_redirect(payload["redir"])

  VerifiedToken.new(
    aud: payload["aud"], sub: payload["sub"], jti: payload["jti"],
    exp: payload["exp"], iat: payload["iat"], redir:, meta: payload["meta"],
    raw_payload: payload
  )
end
```

**Implementation details**

* **Constant-time compare**: implement `secure_compare(a, b)` that runs in constant time over the longest string.
* **JSON**: use `JSON.generate`/`JSON.parse` with `symbolize_names: false`.
* **Base64**: `Base64.urlsafe_encode64(..., padding: false)` and `Base64.urlsafe_decode64`.
* **Signature**: `OpenSSL::HMAC.digest("SHA256", key, signing_input)`.

---

## 9) Key rotation

* Config holds a hash `{kid => key_bytes}` and `active_kid`.
* **Issuing** uses `active_kid`. **Verifying** accepts any known `kid`.
* To rotate:

  1. Add new key with new `kid`. Set `active_kid` to it.
  2. Keep old keys for at least the max TTL.
  3. After grace period, remove old keys.

---

## 10) Redirect handling & open-redirect safety

* If `redir` is present in payload:

  * **Preferred**: only allow **relative** paths (`/dashboard`).
  * If absolute URL is allowed, require the scheme+host to match **exactly** an entry in `origin_whitelist`.
  * Normalize and reject mixed-scheme, unicode trickery (use `URI.parse`, enforce `https`, punycode via `addrinfo` not needed—keep to a strict host match list).

---

## 11) Example integrations (non-mandatory)

### 11.1 Rails controller (issue)

```ruby
issued = MagicLinks.issue(
  aud: "login",
  sub: user.id,
  ttl: 10 * 60,
  redir: "/app",
  ctx: { user_agent: request.user_agent, ip: request.remote_ip }
)
url  = MagicLinks.url(base: login_magic_url, token: issued.token)
# send email with url
```

### 11.2 Rails controller (consume)

```ruby
def magic
  token = params[:ml].to_s
  verified = MagicLinks.verify!(
    token,
    request_context: { user_agent: request.user_agent, ip: request.remote_ip },
    expected_aud: "login"
  )
  sign_in(User.find(verified.sub)) # your app’s auth
  redirect_to(verified.redir || root_path)
rescue MagicLinks::Error => e
  render status: :unauthorized, plain: "Invalid or expired link"
end
```

### 11.3 Rack middleware (optional helper)

Provide an optional helper class inside the gem that **users must wire manually**; no rack dependency is enforced—only documented.

---

## 12) Configuration surface

```ruby
MagicLinks.configure do |c|
  c.issuer = "my-app"
  c.allowed_audiences = %w[login email_change]
  c.origin_whitelist = ["https://example.com"]
  c.clock_skew = 30
  c.default_ttl = 900
  c.active_kid = "k1"
  c.keys = { "k1" => SecureRandom.bytes(32) }
  c.store = MagicLinks::MemoryStore.new
  c.hash_user_agent = true
  c.hash_ip = false
end
```

---

## 13) Error taxonomy & telemetry

* **Typed errors** (see §4) to drive HTTP 401 vs 400 logic.
* Expose a small hook to allow logging/metrics without deps:

  ```ruby
  MagicLinks.on_event do |event, data|
    # event: :issued, :verified, :error
    # data: { aud:, jti:, err_class:, err_message: ... }
  end
  ```

---

## 14) Testing strategy (stdlib only)

* Use Ruby’s bundled testing (`Test::Unit` or `Minitest` as available) to avoid external gems.
* Unit tests for:

  * Signature verification (happy path & tampering).
  * Time window logic (exp/nbf/iat + skew).
  * Replay protection (second use fails).
  * Redirect vetting and allowlist.
  * Key rotation (old `kid` still verifies).
  * Context binding (UA/IP).
  * Malformed tokens (base64/JSON/parts).

---

## 15) Performance notes

* Tokens are small (a few hundred bytes), CPU is dominated by one HMAC per verify.
* Memory store uses O(N) entries where N ≈ number of outstanding issued tokens until expiration.
* For high-QPS, recommend Redis adapter pattern (doc snippet) using `SETNX` + `EXPIRE`.

---

## 16) File layout

```
magic_links/
  lib/
    magic_links.rb               # loader + configure
    magic_links/config.rb
    magic_links/codec.rb         # base64url, json helpers
    magic_links/signature.rb     # hmac, secure_compare
    magic_links/issuer.rb        # issue()
    magic_links/verifier.rb      # verify!()
    magic_links/store.rb         # interface
    magic_links/store/memory.rb  # reference implementation
    magic_links/util.rb          # time helpers, redirect vetting, ctx hashing
  test/
    test_magic_links.rb          # stdlib tests
  README.md
  LICENSE
```

---

## 17) Backwards/forwards compatibility

* `v: 1` in header to allow future token evolutions.
* Strict `alg` check (`HS256`) to avoid alg-none downgrade.
* New fields must be **ignored by older verifiers** unless security-critical.

---

## 18) Deployment guidance & ops

* Keep keys in env/secret store; rotate quarterly or on incident.
* Set TTLs short (5–15 min for login).
* Enforce HTTPS everywhere; HSTS on your domains.
* In email templates, show **intended domain** and **expiry** to help users spot phishing.

---

## 19) Appendix: precise helper behaviors

* **secure_compare(a, b)**: XOR/accumulator over bytes of equalized length; returns false if lengths differ, but still processes to constant time based on the longer length.
* **sha256_8(s)**: `Base64.urlsafe_encode64(Digest::SHA256.digest(s))[0,11].tr('=', '')` (~8 bytes entropy, URL-safe).
* **cidr_hash(ip)**: Normalize to IPv4 `/24` or IPv6 `/64` string (e.g., `203.0.113.5/24`, `2001:db8::/64`), then `sha256_8` of that string.
* **vet_redirect(redir)**:

  * If `nil` → `nil`
  * If startswith `/` → return as is.
  * Else parse with `URI.parse`; require `https` + host in `origin_whitelist`; return normalized `to_s`; else raise `InvalidRedirect`.



