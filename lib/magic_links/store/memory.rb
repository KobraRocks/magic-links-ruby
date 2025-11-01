# frozen_string_literal: true

require 'thread'

module MagicLinks

  class MemoryStore < Store
    def initialize
      @mutex = Mutex.new
      @entries = {}
    end

    def mark_used!(jti:, exp:)
      now = Time.now.to_i
      @mutex.synchronize do
        sweep_locked(now)
        entry = @entries[jti]
        return false if entry && entry >= now

        @entries[jti] = exp
        true
      end
    end

    def used?(jti:)
      now = Time.now.to_i
      @mutex.synchronize do
        sweep_locked(now)
        exp = @entries[jti]
        exp && exp >= now
      end
    end

    def sweep!
      now = Time.now.to_i
      @mutex.synchronize { sweep_locked(now) }
    end

    private

    def sweep_locked(now)
      @entries.delete_if { |_jti, exp| exp < now }
    end
  end
end
