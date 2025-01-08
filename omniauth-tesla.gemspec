# -*- encoding: utf-8 -*-
$LOAD_PATH.unshift File.expand_path('../lib', __FILE__)
require 'omniauth-tesla/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-tesla'
  spec.version       = Omniauth::Tesla::VERSION
  spec.authors       = ['Jamie Quint']
  spec.email         = ['jamiequint@gmail.com']
  spec.summary       = 'OmniAuth strategy for Tesla OAuth (authorization_code flow)'
  spec.description   = 'An OmniAuth strategy that supports Tesla’s Fleet API OAuth flow.'
  spec.homepage      = 'https://github.com/YourUserName/omniauth-tesla'
  spec.license       = 'MIT'

  spec.files         = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.require_paths = ['lib']

  # Adjust your runtime dependency version constraints as needed:
  spec.add_runtime_dependency 'omniauth-oauth2', '>= 1.5'

  # Common development dependencies (optional):
  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'rspec', '~> 3.0'

  # If you have a bin/ directory with executables, you can do:
  # spec.bindir        = 'exe'
  # spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
end
