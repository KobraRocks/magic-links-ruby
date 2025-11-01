# frozen_string_literal: true

require 'uri'
require 'ipaddr'
require 'digest'

module MagicLinks
  module Util
    module_function

    def now
      Time.now.to_i
    end

    def sha256_8(input)
      digest = ::OpenSSL::Digest::SHA256.digest(input.to_s)
      ::Base64.urlsafe_encode64(digest, padding: false)[0, 11].delete('=')
    end

    def cidr_hash(ip)
      normalized = normalize_ip(ip)
      sha256_8(normalized)
    end

    def normalize_ip(ip)
      addr = IPAddr.new(ip)
      mask = addr.ipv4? ? 24 : 64
      network = addr.mask(mask)
      "#{network}/#{mask}"
    rescue IPAddr::InvalidAddressError => e
      raise MagicLinks::Error, "invalid ip: #{e.message}"
    end

    def vet_redirect(redir, origin_whitelist: [])
      return if redir.nil?
      return redir if redir.start_with?('/')

      uri = URI.parse(redir)
      unless uri.is_a?(URI::HTTPS)
        raise MagicLinks::InvalidRedirect, 'redirect must use https scheme'
      end

      allowed = Array(origin_whitelist).any? do |origin|
        parsed = parse_origin(origin)
        parsed && parsed.scheme == uri.scheme && parsed.host == uri.host && parsed.port == uri.port
      end

      raise MagicLinks::InvalidRedirect, 'redirect host not allowed' unless allowed

      uri.to_s
    rescue URI::InvalidURIError => e
      raise MagicLinks::InvalidRedirect, "invalid redirect: #{e.message}"
    end

    def parse_origin(origin)
      URI.parse(origin)
    rescue URI::InvalidURIError
      nil
    end
    private_class_method :parse_origin
  end
end
