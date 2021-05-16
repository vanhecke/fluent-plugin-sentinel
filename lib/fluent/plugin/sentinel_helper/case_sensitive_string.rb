# frozen_string_literal: true

module Fluent
  module Plugin
    module SentinelHelper
      # Microsoft's HTTP server violates the spec and is case-sensitive
      class CaseSensitiveString < String
        def downcase
          self
        end

        def capitalize
          self
        end

        def to_s
          self
        end
      end
    end
  end
end
