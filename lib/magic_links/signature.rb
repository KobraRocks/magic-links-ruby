# frozen_string_literal: true

module MagicLinks
  module Signature
    module_function

    def sign_compact(header, payload, key)
      header_segment = Codec.encode_segment(header)
      payload_segment = Codec.encode_segment(payload)
      signing_input = "#{header_segment}.#{payload_segment}"
      signature_segment = Codec.base64url_encode(compute_hmac(key, signing_input))
      [header_segment, payload_segment, signature_segment].join('.')
    end

    def valid_signature?(header_segment, payload_segment, signature_bytes, key)
      signing_input = "#{header_segment}.#{payload_segment}"
      expected = compute_hmac(key, signing_input)
      secure_compare(expected, signature_bytes)
    end

    def compute_hmac(key, data)
      ::OpenSSL::HMAC.digest('SHA256', key, data)
    end

    def secure_compare(a, b)
      a_bytes = a.to_s.b
      b_bytes = b.to_s.b
      max_length = [a_bytes.bytesize, b_bytes.bytesize].max
      result = a_bytes.bytesize ^ b_bytes.bytesize

      max_length.times do |i|
        a_byte = i < a_bytes.bytesize ? a_bytes.getbyte(i) : 0
        b_byte = i < b_bytes.bytesize ? b_bytes.getbyte(i) : 0
        result |= a_byte ^ b_byte
      end

      result.zero?
    end
  end
end
