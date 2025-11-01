# frozen_string_literal: true

require_relative "lib/magic_links/version"

Gem::Specification.new do |spec|
  spec.name          = "magic-links"
  spec.version       = MagicLinks::VERSION
  spec.authors       = ["Magic Links Maintainers"]
  spec.email         = []

  spec.summary       = "Stateless tokens for passwordless magic link flows."
  spec.description   = "Pure Ruby implementation for issuing and verifying signed magic link tokens with replay protection and rack middleware helpers."
  spec.homepage      = "https://github.com/kobrarocks/magic-links"
  spec.license       = "MIT"

  spec.required_ruby_version = ">= 3.1"

  spec.files = Dir.glob("lib/**/*").select { |path| File.file?(path) }
  spec.files += Dir.glob("test/**/*").select { |path| File.file?(path) }
  spec.files += %w[README.md SPEC.md LICENSE]

  spec.metadata["source_code_uri"] = spec.homepage

  spec.require_paths = ["lib"]
end
