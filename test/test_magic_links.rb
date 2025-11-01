# frozen_string_literal: true

require 'minitest/autorun'
require_relative '../lib/magic_links'

class MagicLinksTest < Minitest::Test
  def setup
    MagicLinks.reset!
    MagicLinks.configure do |c|
      c.issuer = 'test-app'
      c.allowed_audiences = %w[login email_change]
      c.origin_whitelist = ['https://example.com']
      c.clock_skew = 30
      c.default_ttl = 120
      c.active_kid = 'k1'
      c.keys = { 'k1' => 'a' * 32, 'k0' => 'b' * 32 }
      c.store = MagicLinks::MemoryStore.new
      c.hash_user_agent = true
      c.hash_ip = true
    end
    @context = { user_agent: 'TestUA/1.0', ip: '203.0.113.5' }
  end

  def test_issue_and_verify_happy_path
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context, redir: '/home', meta: { 'foo' => 'bar' })
    verified = MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')

    assert_equal 'login', verified.aud
    assert_equal 'user-123', verified.sub
    assert_equal issued.jti, verified.jti
    assert_equal '/home', verified.redir
    assert_equal({ 'foo' => 'bar' }, verified.meta)
  end

  def test_signature_tampering_detected
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    parts = issued.token.split('.')
    payload = MagicLinks::Codec.decode_segment(parts[1])
    payload['sub'] = 'attacker'
    tampered_payload = MagicLinks::Codec.encode_segment(payload)
    tampered = [parts[0], tampered_payload, parts[2]].join('.')

    assert_raises(MagicLinks::InvalidSignature) do
      MagicLinks.verify!(tampered, request_context: @context, expected_aud: 'login')
    end
  end

  def test_expired_token_raises
    issued = freeze_time(Time.at(1_700_000_000)) do
      MagicLinks.issue(aud: 'login', sub: 'user-123', ttl: 10, ctx: @context)
    end

    assert_raises(MagicLinks::Expired) do
      freeze_time(Time.at(1_700_000_000 + 10 + MagicLinks.config.clock_skew + 1)) do
        MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')
      end
    end
  end

  def test_not_yet_valid_token_raises
    issued = freeze_time(Time.at(1_700_000_000)) do
      MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context.merge(nbf: 1_700_000_120))
    end

    assert_raises(MagicLinks::NotYetValid) do
      freeze_time(Time.at(1_700_000_060)) do
        MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')
      end
    end
  end

  def test_replay_protection
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')

    assert_raises(MagicLinks::UsedToken) do
      MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')
    end
  end

  def test_redirect_vetting_allows_relative_and_whitelisted
    issued_relative = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context, redir: '/dashboard')
    verified_relative = MagicLinks.verify!(issued_relative.token, request_context: @context, expected_aud: 'login')
    assert_equal '/dashboard', verified_relative.redir

    issued_absolute = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context, redir: 'https://example.com/app')
    verified_absolute = MagicLinks.verify!(issued_absolute.token, request_context: @context, expected_aud: 'login')
    assert_equal 'https://example.com/app', verified_absolute.redir
  end

  def test_redirect_vetting_blocks_unlisted_hosts
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context, redir: 'https://evil.com/app')
    assert_raises(MagicLinks::InvalidRedirect) do
      MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')
    end
  end

  def test_key_rotation_accepts_old_tokens
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    MagicLinks.config.keys['k2'] = 'c' * 32
    MagicLinks.config.active_kid = 'k2'

    verified = MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'login')
    assert_equal 'user-123', verified.sub
  end

  def test_context_binding_detects_mismatch
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)

    assert_raises(MagicLinks::InvalidSignature) do
      MagicLinks.verify!(issued.token, request_context: @context.merge(user_agent: 'OtherUA'), expected_aud: 'login')
    end

    assert_raises(MagicLinks::InvalidSignature) do
      MagicLinks.verify!(issued.token, request_context: @context.merge(ip: '198.51.100.42'), expected_aud: 'login')
    end
  end

  def test_malformed_tokens
    assert_raises(MagicLinks::Malformed) do
      MagicLinks.verify!('bad-token', request_context: @context, expected_aud: 'login')
    end

    parts = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context).token.split('.')
    bad_signature = [parts[0], parts[1], '!!!'].join('.')

    assert_raises(MagicLinks::Malformed) do
      MagicLinks.verify!(bad_signature, request_context: @context, expected_aud: 'login')
    end
  end

  def test_expected_audience_enforced
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    assert_raises(MagicLinks::InvalidAudience) do
      MagicLinks.verify!(issued.token, request_context: @context, expected_aud: 'email_change')
    end
  end

  def test_future_issued_at_rejected
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    header_segment, payload_segment = issued.token.split('.')[0, 2]
    header = MagicLinks::Codec.decode_segment(header_segment)
    payload = MagicLinks::Codec.decode_segment(payload_segment)
    payload['iat'] = payload['iat'] + 10_000

    key = MagicLinks.config.keys[header['kid']]
    forged = MagicLinks::Signature.sign_compact(header, payload, key)

    assert_raises(MagicLinks::Malformed) do
      MagicLinks.verify!(forged, request_context: @context, expected_aud: 'login')
    end
  end

  def test_url_helper_appends_param
    issued = MagicLinks.issue(aud: 'login', sub: 'user-123', ctx: @context)
    url = MagicLinks.url(base: 'https://example.com/magic', token: issued)
    assert_includes url, 'ml='
    assert url.end_with?(issued.token)
  end

  private

  def freeze_time(frozen_time)
    Time.stub :now, frozen_time do
      yield
    end
  end
end
