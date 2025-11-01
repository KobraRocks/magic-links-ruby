# frozen_string_literal: true

require 'json'
require 'base64'
require 'openssl'
require 'securerandom'
require 'time'

require_relative 'magic_links/version'
require_relative 'magic_links/config'
require_relative 'magic_links/codec'
require_relative 'magic_links/signature'
require_relative 'magic_links/util'
require_relative 'magic_links/store'
require_relative 'magic_links/store/memory'
require_relative 'magic_links/issuer'
require_relative 'magic_links/verifier'
require_relative 'magic_links/rack_middleware'

module MagicLinks
  Error = Class.new(StandardError)
  Expired = Class.new(Error)
  NotYetValid = Class.new(Error)
  InvalidSignature = Class.new(Error)
  InvalidAudience = Class.new(Error)
  InvalidIssuer = Class.new(Error)
  UsedToken = Class.new(Error)
  InvalidRedirect = Class.new(Error)
  Malformed = Class.new(Error)

  IssuedToken = Struct.new(:token, :jti, :exp, :kid, :aud, :sub, keyword_init: true)
  VerifiedToken = Struct.new(:aud, :sub, :jti, :exp, :iat, :redir, :meta, :raw_payload, keyword_init: true)

  class << self
    def config
      @config ||= MagicLinks::Config.new
    end

    def configure
      yield config
      config.validate!
    end

    def reset!
      @config = MagicLinks::Config.new
      @event_handlers = []
    end

    def on_event(&block)
      event_handlers << block if block
    end

    def emit_event(event, data = {})
      event_handlers.each do |handler|
        handler.call(event, data)
      rescue StandardError
        # ignore handler errors to avoid breaking flow
      end
    end

    def issue(**kwargs)
      config.validate!
      token = Issuer.new(config).issue(**kwargs)
      emit_event(:issued, aud: token.aud, jti: token.jti)
      token
    rescue Error => e
      emit_event(:error, aud: kwargs[:aud], jti: nil, err_class: e.class.name, err_message: e.message)
      raise
    end

    def verify!(token_string, request_context: nil, expected_aud: nil)
      config.validate!
      verifier = Verifier.new(config, request_context: request_context, expected_aud: expected_aud)
      result = verifier.verify!(token_string)
      emit_event(:verified, aud: result.aud, jti: result.jti)
      result
    rescue Error => e
      emit_event(:error, aud: expected_aud, jti: nil, err_class: e.class.name, err_message: e.message)
      raise
    end

    def url(base:, token:, param: 'ml')
      token_str = token.respond_to?(:token) ? token.token : token.to_s
      query_delim = base.include?('?') ? '&' : '?'
      "#{base}#{query_delim}#{param}=#{token_str}"
    end

    private

    def event_handlers
      @event_handlers ||= []
    end
  end
end
