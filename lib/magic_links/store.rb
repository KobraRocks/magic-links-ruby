# frozen_string_literal: true

module MagicLinks
  class Store
    def mark_used!(jti:, exp:)
      raise NotImplementedError
    end

    def used?(jti:)
      raise NotImplementedError
    end

    def sweep!
    end
  end
end
