# frozen_string_literal: true

require_relative "lib/tg_client/version"

Gem::Specification.new do |spec|
  spec.name        = "tg_client"
  spec.version     = TgClient::VERSION
  spec.authors     = ["Jhonathan Amezcua"]
  spec.email       = ["jhonathan.amezcua@gmail.com"]

  spec.summary     = "Minimal Telegram MTProto 2.0 client for reading chat history"
  spec.description = "Pure Ruby MTProto 2.0 client focused on a small public API: authenticate(phone:) and get_history(chat_id:, date_from:, limit:). Persists session to a local file."
  spec.homepage    = "https://github.com/jhonathan/tg_client"
  spec.license     = "MIT"

  spec.required_ruby_version = ">= 3.2"

  spec.files = Dir[
    "lib/**/*.rb",
    "lib/tg_client/schema/*",
    "README.md",
    "LICENSE*"
  ]
  spec.require_paths = ["lib"]

  # logger was removed from default gems in Ruby 4.0; we need it on $LOAD_PATH.
  spec.add_dependency "logger", "~> 1.6"

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.13"
end
