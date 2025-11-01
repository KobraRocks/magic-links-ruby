# frozen_string_literal: true

module MagicLinks
  class Verifier
    def initialize(config, request_context: nil, expected_aud: nil)
      @config = config
      @request_context = request_context || {}
      @expected_aud = expected_aud
    end

    def verify!(token_string)
      header, payload, signature_bytes, header_segment, payload_segment = Codec.parse_compact(token_string)

      validate_header!(header)
      key = resolve_key(header['kid'])
      unless Signature.valid_signature?(header_segment, payload_segment, signature_bytes, key)
        raise MagicLinks::InvalidSignature, 'signature mismatch'
      end

      validate_payload!(payload)
      enforce_audience!(payload)
      enforce_context!(payload)

      unless config.store.mark_used!(jti: payload['jti'], exp: payload['exp'])
        raise MagicLinks::UsedToken, 'token has already been used'
      end

      redir = Util.vet_redirect(payload['redir'], origin_whitelist: config.origin_whitelist)

      MagicLinks::VerifiedToken.new(
        aud: payload['aud'],
        sub: payload['sub'],
        jti: payload['jti'],
        exp: payload['exp'],
        iat: payload['iat'],
        redir: redir,
        meta: payload['meta'],
        raw_payload: payload
      )
    end

    private

    attr_reader :config, :request_context, :expected_aud

    def validate_header!(header)
      unless header.is_a?(Hash)
        raise MagicLinks::Malformed, 'header must be a JSON object'
      end

      unless header['alg'] == 'HS256'
        raise MagicLinks::InvalidSignature, 'unsupported alg'
      end

      unless header['typ'] == 'MLINK' && header['v'] == 1
        raise MagicLinks::Malformed, 'invalid typ or version'
      end

      raise MagicLinks::InvalidSignature, 'kid missing' unless header['kid']
    end

    def validate_payload!(payload)
      unless payload.is_a?(Hash)
        raise MagicLinks::Malformed, 'payload must be a JSON object'
      end

      %w[iss aud sub exp iat jti].each do |required|
        raise MagicLinks::Malformed, "payload missing #{required}" unless payload.key?(required)
      end

      unless payload['iss'] == config.issuer
        raise MagicLinks::InvalidIssuer, 'issuer mismatch'
      end

      now = Util.now
      skew = config.clock_skew.to_i
      exp = integer_attribute(payload['exp'], 'exp')
      raise MagicLinks::Expired, 'token expired' if exp <= now - skew

      nbf_value = nil
      if payload.key?('nbf')
        nbf_value = integer_attribute(payload['nbf'], 'nbf')
        raise MagicLinks::NotYetValid, 'token not valid yet' if nbf_value > now + skew
      end

      iat = integer_attribute(payload['iat'], 'iat')
      raise MagicLinks::Malformed, 'issued-at in future' if iat > now + skew

      payload['exp'] = exp
      payload['iat'] = iat
      payload['nbf'] = nbf_value if nbf_value
    end

    def enforce_audience!(payload)
      aud = payload['aud']
      if expected_aud
        raise MagicLinks::InvalidAudience, 'audience mismatch' unless aud == expected_aud
      elsif config.allowed_audiences&.any?
        unless config.allowed_audiences.include?(aud)
          raise MagicLinks::InvalidAudience, 'audience not allowed'
        end
      end
    end

    def enforce_context!(payload)
      ctx = payload['ctx']
      return unless ctx

      unless ctx.is_a?(Hash)
        raise MagicLinks::InvalidSignature, 'context malformed'
      end

      if ctx.key?('ua')
        ua = request_context[:user_agent] or raise MagicLinks::InvalidSignature, 'user agent required'
        expected = Util.sha256_8(ua)
        raise MagicLinks::InvalidSignature, 'user agent mismatch' unless Signature.secure_compare(expected, ctx['ua'])
      end

      if ctx.key?('ip')
        ip = request_context[:ip] or raise MagicLinks::InvalidSignature, 'ip required'
        expected = Util.cidr_hash(ip)
        raise MagicLinks::InvalidSignature, 'ip mismatch' unless Signature.secure_compare(expected, ctx['ip'])
      end
    end

    def resolve_key(kid)
      key = config.keys[kid]
      raise MagicLinks::InvalidSignature, 'unknown key id' unless key
      key
    end

    def integer_attribute(value, name)
      Integer(value)
    rescue ArgumentError, TypeError
      raise MagicLinks::Malformed, "payload #{name} must be integer"
    end
  end
end
