# frozen_string_literal: true

module MagicLinks
  module Codec
    module_function

    def base64url_encode(data)
      ::Base64.urlsafe_encode64(data, padding: false)
    end

    def base64url_decode(data)
      ::Base64.urlsafe_decode64(data)
    rescue ArgumentError => e
      raise MagicLinks::Malformed, "invalid base64: #{e.message}"
    end

    def encode_json(obj)
      ::JSON.generate(obj)
    end

    def decode_json(str)
      ::JSON.parse(str)
    rescue JSON::ParserError => e
      raise MagicLinks::Malformed, "invalid json: #{e.message}"
    end

    def encode_segment(obj)
      base64url_encode(encode_json(obj))
    end

    def decode_segment(segment)
      decode_json(base64url_decode(segment))
    end

    def parse_compact(token)
      parts = token.to_s.split('.')
      raise MagicLinks::Malformed, 'token must have three parts' unless parts.length == 3

      header = decode_segment(parts[0])
      payload = decode_segment(parts[1])
      signature = base64url_decode(parts[2])
      [header, payload, signature, parts[0], parts[1]]
    end

  end
end
