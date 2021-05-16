# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name          = 'fluent-plugin-sentinel'
  spec.version       = '0.1'
  spec.authors       = ['Joris Vanhecke']
  spec.email         = ['joris@jorisvanhecke.be']

  spec.summary       = 'Fluentd Plugin that helps load Syslog/CEF data into Azure Sentinel.'
  spec.homepage      = 'https://github.com/vanhecke/fluent-plugin-sentinel/'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.5.0')

  spec.metadata['allowed_push_host'] = "TODO: Set to 'http://mygemserver.com'"

  spec.metadata['homepage_uri'] = spec.homepage
  spec.metadata['source_code_uri'] = 'https://github.com/vanhecke/fluent-plugin-sentinel/'
  spec.metadata['changelog_uri'] = 'https://github.com/vanhecke/fluent-plugin-sentinel/'

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']
end
