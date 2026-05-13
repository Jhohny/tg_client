# frozen_string_literal: true

module TgClient
  # Persists the post-handshake auth state to a JSON file with base64-encoded
  # binary fields. The session file lets subsequent runs skip the DH handshake
  # entirely and resume RPC immediately.
  #
  # File format (UTF-8 JSON):
  #
  #   {
  #     "dc_id":           Integer,
  #     "auth_key":        base64 of 256 bytes,
  #     "auth_key_id":     Integer (int64),
  #     "server_salt":     base64 of 8 bytes,
  #     "user_id":         Integer | null,
  #     "layer":           Integer
  #   }
  #
  # Writes are atomic (write to `path.tmp`, then rename) and the file is mode
  # 0600 so it's not world-readable.
  module Session
    REQUIRED_FIELDS = %w[dc_id auth_key auth_key_id server_salt layer].freeze
    private_constant :REQUIRED_FIELDS

    module_function

    # Load a session file. Returns a Hash with symbol keys and decoded binary
    # values, or nil if the file does not exist.
    def load(path)
      expanded = File.expand_path(path)
      return nil unless File.exist?(expanded)

      raw = JSON.parse(File.read(expanded))
      missing = REQUIRED_FIELDS - raw.keys
      raise Error, "session file #{path} is missing fields: #{missing.join(", ")}" unless missing.empty?

      {
        dc_id:       raw.fetch("dc_id"),
        auth_key:    decode64(raw.fetch("auth_key")),
        auth_key_id: raw.fetch("auth_key_id"),
        server_salt: decode64(raw.fetch("server_salt")),
        user_id:     raw["user_id"],
        layer:       raw.fetch("layer")
      }
    end

    # Persist a session hash. Atomic via tmp + rename. Sets mode 0600.
    def save(path, session)
      expanded = File.expand_path(path)
      tmp = "#{expanded}.tmp"

      payload = {
        "dc_id"       => session.fetch(:dc_id),
        "auth_key"    => encode64(session.fetch(:auth_key)),
        "auth_key_id" => session.fetch(:auth_key_id),
        "server_salt" => encode64(session.fetch(:server_salt)),
        "user_id"     => session[:user_id],
        "layer"       => session.fetch(:layer)
      }

      File.write(tmp, JSON.pretty_generate(payload))
      File.chmod(0o600, tmp)
      File.rename(tmp, expanded)
      nil
    end

    def encode64(bytes) = [bytes.b].pack("m0")
    def decode64(string) = string.unpack1("m0").b
  end
end
