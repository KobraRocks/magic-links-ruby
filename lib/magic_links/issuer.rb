# frozen_string_literal: true

module MagicLinks
  class Issuer
    def initialize(config)
      @config = config
    end

    def issue(aud:, sub:, ttl: nil, redir: nil, meta: nil, ctx: nil)
      raise MagicLinks::Error, 'audience must be provided' if blank?(aud)
      raise MagicLinks::Error, 'subject must be provided' if blank?(sub)

      now = Util.now
      ttl_seconds = ttl || config.default_ttl
      unless ttl_seconds.is_a?(Numeric) && ttl_seconds.positive?
        raise MagicLinks::Error, 'ttl must be positive number'
      end

      exp = now + ttl_seconds.to_i
      jti = SecureRandom.hex(16)

      payload = {
        'iss' => config.issuer,
        'aud' => aud,
        'sub' => sub,
        'iat' => now,
        'exp' => exp,
        'jti' => jti
      }

      if ctx&.key?(:nbf)
        payload['nbf'] = ctx[:nbf].to_i
      end

      payload['redir'] = redir if redir
      payload['meta'] = meta if meta

      apply_context(ctx, payload)

      header = {
        'alg' => 'HS256',
        'typ' => 'MLINK',
        'v' => 1,
        'kid' => config.active_kid
      }

      key = config.keys.fetch(config.active_kid)
      token = Signature.sign_compact(header, payload, key)

      IssuedToken.new(token: token, jti: jti, exp: exp, kid: config.active_kid, aud: aud, sub: sub)
    end

    private

    attr_reader :config

    def apply_context(ctx, payload)
      return unless ctx

      context = {}
      if config.hash_user_agent && ctx[:user_agent]
        context['ua'] = Util.sha256_8(ctx[:user_agent])
      end
      if config.hash_ip && ctx[:ip]
        context['ip'] = Util.cidr_hash(ctx[:ip])
      end

      payload['ctx'] = context unless context.empty?
    end

    def blank?(value)
      value.respond_to?(:empty?) ? value.empty? : !value
    end
  end
end
