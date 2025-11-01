# frozen_string_literal: true

module MagicLinks
  class Config
    attr_accessor :issuer, :allowed_audiences, :origin_whitelist,
                  :clock_skew, :default_ttl, :active_kid, :keys,
                  :store, :hash_user_agent, :hash_ip

    def initialize
      @issuer = nil
      @allowed_audiences = nil
      @origin_whitelist = []
      @clock_skew = 30
      @default_ttl = 15 * 60
      @active_kid = nil
      @keys = {}
      @store = MagicLinks::MemoryStore.new
      @hash_user_agent = false
      @hash_ip = false
    end

    def validate!
      raise MagicLinks::Error, 'issuer must be configured' if blank?(@issuer)

      unless @clock_skew.is_a?(Numeric) && @clock_skew >= 0
        raise MagicLinks::Error, 'clock_skew must be non-negative number'
      end

      unless @default_ttl.is_a?(Numeric) && @default_ttl.positive?
        raise MagicLinks::Error, 'default_ttl must be positive number'
      end

      raise MagicLinks::Error, 'active_kid must be configured' if blank?(@active_kid)

      unless @keys.is_a?(Hash) && @keys[@active_kid]
        raise MagicLinks::Error, 'keys must include active_kid key'
      end

      @keys.each do |kid, key|
        unless kid.is_a?(String)
          raise MagicLinks::Error, 'keys hash must use string key ids'
        end
        unless key.is_a?(String) && key.bytesize >= 32
          raise MagicLinks::Error, "key for #{kid.inspect} must be String >= 32 bytes"
        end
      end

      if @allowed_audiences && !@allowed_audiences.respond_to?(:include?)
        raise MagicLinks::Error, 'allowed_audiences must be enumerable'
      end

      unless @store && @store.respond_to?(:mark_used!)
        raise MagicLinks::Error, 'store must respond to mark_used!'
      end

      self
    end

    private

    def blank?(value)
      value.respond_to?(:empty?) ? value.empty? : !value
    end
  end
end
