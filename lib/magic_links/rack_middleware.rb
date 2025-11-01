# frozen_string_literal: true

require 'cgi'

module MagicLinks
  class RackMiddleware
    def initialize(app, param: 'ml', expected_aud: nil, on_error: nil)
      @app = app
      @param = param
      @expected_aud = expected_aud
      @on_error = on_error
    end

    def call(env)
      token = extract_token(env)
      return app.call(env) unless token

      context = {
        user_agent: env['HTTP_USER_AGENT'],
        ip: env['REMOTE_ADDR']
      }

      verified = MagicLinks.verify!(token, request_context: context, expected_aud: expected_aud)
      env['magic_links.token'] = verified
      app.call(env)
    rescue MagicLinks::Error => e
      env['magic_links.error'] = e
      on_error&.call(env, e)
      app.call(env)
    end

    private

    attr_reader :app, :param, :expected_aud, :on_error

    def extract_token(env)
      req = rack_request(env)
      raw = req.params[param]
      raw && !raw.empty? ? raw : nil
    rescue NameError
      # Rack not available; fall back to env parsing
      query = env['QUERY_STRING']
      return unless query && !query.empty?

      query.split('&').each do |pair|
        key, value = pair.split('=', 2)
        return CGI.unescape(value.to_s) if key == param
      end
      nil
    end

    def rack_request(env)
      raise NameError unless defined?(::Rack::Request)
      ::Rack::Request.new(env)
    end
  end
end
