# frozen_string_literal: true

require "openssl"
require "securerandom"
require "socket"
require "stringio"
require "zlib"
require "json"
require "logger"
require "date"
require "time"

require_relative "tg_client/version"

# Top-level namespace and error hierarchy for the gem. Submodules are required
# from this file as they are implemented; see the require_relative lines at the
# bottom.
module TgClient
  # Base class for all errors raised by this gem. Catch this to handle anything
  # tg_client might raise.
  class Error < StandardError; end

  # Raised when the bundled TL schema fails to parse, or a method/type is
  # referenced that doesn't exist in the registry.
  class SchemaError < Error; end

  # Raised on framing errors, socket failures, or CRC32 mismatches.
  class TransportError < Error; end

  # Generic authentication failure (bad credentials, expired code, etc.).
  class AuthError < Error; end

  # Raised when auth.signIn returns SESSION_PASSWORD_NEEDED. This gem
  # intentionally does not implement the SRP cloud-password exchange.
  class PasswordRequired < AuthError
    def initialize(msg = "Account has 2FA enabled; tg_client does not support cloud passwords.")
      super
    end
  end

  # Raised when the server returns rpc_error. Carries the error code and the
  # raw error_message string from the API.
  class RPCError < Error
    attr_reader :code, :error_message

    def initialize(code, error_message)
      @code = code
      @error_message = error_message
      super("RPC error #{code}: #{error_message}")
    end
  end

  # Raised when the server returns a *_MIGRATE_N error indicating the account
  # lives on a different DC.
  class MigrateError < RPCError
    attr_reader :dc_id

    def initialize(code, error_message, dc_id)
      @dc_id = dc_id
      super(code, error_message)
    end
  end

  # Raised when the dispatcher exhausts its bad_server_salt retry budget.
  class BadServerSaltError < Error; end
end

require_relative "tg_client/tl_parser"
require_relative "tg_client/crypto"
