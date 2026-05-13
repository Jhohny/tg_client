# frozen_string_literal: true

module TgClient
  # High-level MTProto client. Wraps a Transport with the MTProto 2.0 envelope
  # (auth_key_id, msg_key, AES-IGE-encrypted body) and dispatches RPC calls.
  #
  # Public surface:
  #
  #   client = TgClient::Client.new(api_id, api_hash, session_file: "~/.tg_session")
  #   client.authenticate(phone: "+521234567890")          # added in commit 9
  #   client.get_dialogs(limit: 100)                       # added in commit 10
  #   client.get_history(chat_id: -1001234567890, ...)     # added in commit 11
  #
  # Internals exposed for testing: #invoke (encrypted), #invoke_plain
  # (unencrypted, used by the DH handshake).
  class Client
    SCHEMA_DIR = File.expand_path("schema", __dir__)
    private_constant :SCHEMA_DIR

    attr_reader :api_id, :api_hash, :dc_id, :registry, :logger

    def initialize(api_id, api_hash, session_file: "~/.tg_session",
                   dc_id: 2, test: false, logger: nil, transport: nil)
      @api_id          = api_id
      @api_hash        = api_hash
      @session_file    = session_file
      @dc_id           = dc_id
      @test            = test
      @logger          = logger || Logger.new(IO::NULL)
      @transport_inst  = transport

      @registry        = TL::Parser.parse(File.join(SCHEMA_DIR, "api.tl"),
                                          File.join(SCHEMA_DIR, "mtproto.tl"))
      @serializer      = TL::Serializer.new(@registry)
      @deserializer    = TL::Deserializer.new(@registry)

      # Per-session state. Auth fields populated by the DH handshake or by a
      # session file load (commits 8 and 9).
      @auth_key            = nil  # 256 raw bytes
      @auth_key_id         = nil  # int64
      @server_salt         = 0    # int64
      @session_id          = SecureRandom.bytes(8).unpack1("q<")
      @msg_seqno_counter   = 0
      @last_msg_id         = 0
      @time_offset         = 0
      @initialized         = false
      @peer_cache          = { users: {}, channels: {} }
    end

    # Send an encrypted RPC call and wait for its rpc_result. Returns the
    # decoded result body (a hash with :_). Handles bad_server_salt retries,
    # rpc_error -> RPCError/MigrateError/PasswordRequired, and unwraps
    # msg_container.
    def invoke(method_name, **args)
      raise Error, "client has no auth_key yet (call #authenticate first)" if @auth_key.nil?

      body_bytes = @serializer.serialize_method(method_name.to_s, args)
      body_bytes = wrap_first_call(body_bytes) unless @initialized

      attempts = 0
      loop do
        attempts += 1
        raise BadServerSaltError, "exceeded salt retries" if attempts > 3

        req_msg_id = send_encrypted(body_bytes)
        begin
          result = wait_for_response(req_msg_id)
          @initialized = true
          return result
        rescue BadServerSaltError
          @logger.info { "retrying after bad_server_salt (attempt #{attempts})" }
        end
      end
    end

    # Send an unencrypted message (auth_key_id = 0). Used only during the DH
    # handshake. Returns the deserialized response body.
    def invoke_plain(method_name, **args)
      body_bytes = @serializer.serialize_method(method_name.to_s, args)
      send_plain(body_bytes)
      recv_plain
    end

    # Run the three-step MTProto 2.0 DH handshake against the currently
    # connected transport. Populates @auth_key, @auth_key_id, @server_salt.
    # See https://core.telegram.org/mtproto/auth_key.
    def do_dh_handshake
      nonce = SecureRandom.bytes(16)

      res_pq = invoke_plain("req_pq_multi", nonce: nonce)
      raise AuthError, "nonce mismatch in resPQ" unless res_pq[:nonce] == nonce
      server_nonce = res_pq[:server_nonce]
      pq_bytes     = res_pq[:pq]
      fingerprints = res_pq[:server_public_key_fingerprints]

      p_bytes, q_bytes = Crypto.factor_pq(pq_bytes)
      selected = Crypto.select_public_key(fingerprints)
      raise AuthError, "no matching RSA public key for #{fingerprints.inspect}" unless selected
      fp, rsa_key = selected

      new_nonce = SecureRandom.bytes(32)

      pq_inner_bytes = @serializer.serialize_object(
        _:            "p_q_inner_data_dc",
        pq:           pq_bytes,
        p:            p_bytes,
        q:            q_bytes,
        nonce:        nonce,
        server_nonce: server_nonce,
        new_nonce:    new_nonce,
        dc:           @dc_id
      )
      encrypted_pq = Crypto.rsa_pad_encrypt(rsa_key, pq_inner_bytes)

      server_dh = invoke_plain(
        "req_DH_params",
        nonce:                  nonce,
        server_nonce:           server_nonce,
        p:                      p_bytes,
        q:                      q_bytes,
        public_key_fingerprint: fp,
        encrypted_data:         encrypted_pq
      )
      raise AuthError, "unexpected DH response: #{server_dh[:_]}" unless server_dh[:_] == "server_DH_params_ok"
      raise AuthError, "nonce mismatch in server_DH_params_ok" unless server_dh[:nonce] == nonce
      raise AuthError, "server_nonce mismatch in server_DH_params_ok" unless server_dh[:server_nonce] == server_nonce

      tmp_key, tmp_iv = dh_kdf(new_nonce, server_nonce)
      decrypted = Crypto.aes_ige_decrypt(tmp_key, tmp_iv, server_dh[:encrypted_answer])

      inner_hash    = decrypted[0, 20]
      inner_payload = decrypted.byteslice(20..)
      server_dh_inner = @deserializer.deserialize(inner_payload)
      raise AuthError, "expected server_DH_inner_data, got #{server_dh_inner[:_]}" unless server_dh_inner[:_] == "server_DH_inner_data"

      reserialized = @serializer.serialize_object(server_dh_inner)
      raise AuthError, "server_DH_inner_data hash mismatch" unless Crypto.sha1(reserialized) == inner_hash
      raise AuthError, "nonce mismatch in server_DH_inner_data" unless server_dh_inner[:nonce] == nonce
      raise AuthError, "server_nonce mismatch in server_DH_inner_data" unless server_dh_inner[:server_nonce] == server_nonce

      g_int           = server_dh_inner[:g]
      dh_prime        = OpenSSL::BN.new(server_dh_inner[:dh_prime], 2)
      g_a             = OpenSSL::BN.new(server_dh_inner[:g_a],      2)
      @time_offset    = server_dh_inner[:server_time] - Time.now.to_i

      # Pick a random 2048-bit b. Validating 1 < g_a < dh_prime - 1 is
      # required by spec; we also keep the simpler check on g_b below.
      one = OpenSSL::BN.new(1)
      raise AuthError, "g_a out of range" if g_a <= one || g_a >= dh_prime - one
      b_bn  = OpenSSL::BN.new(SecureRandom.bytes(256), 2)
      g_bn  = OpenSSL::BN.new(g_int)
      g_b   = g_bn.mod_exp(b_bn, dh_prime)
      raise AuthError, "g_b out of range" if g_b <= one || g_b >= dh_prime - one

      auth_key = pad_bn_to(g_a.mod_exp(b_bn, dh_prime), 256)

      client_inner = @serializer.serialize_object(
        _:            "client_DH_inner_data",
        nonce:        nonce,
        server_nonce: server_nonce,
        retry_id:     0,
        g_b:          g_b.to_s(2)
      )
      data_with_hash = Crypto.sha1(client_inner) + client_inner
      pad_len = (16 - (data_with_hash.bytesize % 16)) % 16
      data_with_hash += SecureRandom.bytes(pad_len) if pad_len.positive?
      encrypted_data = Crypto.aes_ige_encrypt(tmp_key, tmp_iv, data_with_hash)

      dh_gen = invoke_plain(
        "set_client_DH_params",
        nonce:          nonce,
        server_nonce:   server_nonce,
        encrypted_data: encrypted_data
      )

      verify_dh_gen(dh_gen, new_nonce, server_nonce, auth_key, expected: "dh_gen_ok")

      @auth_key    = auth_key
      @auth_key_id = Crypto.auth_key_id(auth_key)
      @server_salt = compute_server_salt(new_nonce, server_nonce)
      @logger.info { "DH handshake complete: auth_key_id=#{@auth_key_id.to_s(16)} dc=#{@dc_id}" }
      nil
    end

    # DH key/iv derivation for the temporary AES used to encrypt the
    # client/server DH inner messages. Public for testing.
    def self.dh_kdf(new_nonce, server_nonce)
      sha_ns = Crypto.sha1(new_nonce + server_nonce)
      sha_sn = Crypto.sha1(server_nonce + new_nonce)
      sha_nn = Crypto.sha1(new_nonce + new_nonce)
      tmp_aes_key = sha_ns + sha_sn[0, 12]
      tmp_aes_iv  = sha_sn[12, 8] + sha_nn + new_nonce[0, 4]
      [tmp_aes_key, tmp_aes_iv]
    end

    # Compute the server salt: lower 8 bytes of XOR(new_nonce, server_nonce)
    # read as a little-endian int64.
    def self.compute_server_salt(new_nonce, server_nonce)
      a = new_nonce[0, 8].unpack1("q<")
      b = server_nonce[0, 8].unpack1("q<")
      a ^ b
    end

    # Left-pad a positive OpenSSL::BN's big-endian byte representation to a
    # fixed length with zero bytes. (auth_key must be exactly 256 bytes.)
    def self.pad_bn_to(bn, size)
      bytes = bn.to_s(2).b
      raise AuthError, "BN larger than #{size} bytes (#{bytes.bytesize})" if bytes.bytesize > size
      bytes.bytesize == size ? bytes : ("\x00".b * (size - bytes.bytesize)) + bytes
    end

    # ------------------------------------------------------------------------
    # Lazy transport accessor
    # ------------------------------------------------------------------------

    def transport
      @transport_inst ||= Transport.new(dc_id: @dc_id, test: @test, logger: @logger)
    end

    private

    # ------------------------------------------------------------------------
    # Unencrypted message I/O (handshake-only)
    # ------------------------------------------------------------------------

    def send_plain(body)
      msg_id = next_msg_id
      frame = [0].pack("q<") + [msg_id].pack("q<") + [body.bytesize].pack("l<") + body
      transport.send_frame(frame)
      msg_id
    end

    def recv_plain
      frame = transport.recv_frame
      auth_key_id = frame[0, 8].unpack1("q<")
      raise Error, "expected unencrypted frame, got auth_key_id=#{auth_key_id}" unless auth_key_id.zero?

      msg_len = frame[16, 4].unpack1("l<")
      body = frame[20, msg_len]
      @deserializer.deserialize(body)
    end

    # ------------------------------------------------------------------------
    # Encrypted message I/O
    # ------------------------------------------------------------------------

    def send_encrypted(body_bytes)
      msg_id = next_msg_id
      seq_no = next_seq_no(content: true)

      inner = [@server_salt].pack("q<") +
              [@session_id].pack("q<") +
              [msg_id].pack("q<") +
              [seq_no, body_bytes.bytesize].pack("l<l<") +
              body_bytes
      padded = pad_message(inner)

      mk = Crypto.msg_key(@auth_key, padded, direction: :client_to_server)
      aes_key, aes_iv = Crypto.derive_aes_key_iv(@auth_key, mk, direction: :client_to_server)
      encrypted = Crypto.aes_ige_encrypt(aes_key, aes_iv, padded)
      frame = [@auth_key_id].pack("q<") + mk + encrypted
      transport.send_frame(frame)

      @logger.debug { "sent encrypted msg_id=#{msg_id.to_s(16)} seq_no=#{seq_no} body_len=#{body_bytes.bytesize}" }
      msg_id
    end

    def recv_encrypted
      frame = transport.recv_frame
      mk = frame[8, 16]
      encrypted = frame.byteslice(24..)

      aes_key, aes_iv = Crypto.derive_aes_key_iv(@auth_key, mk, direction: :server_to_client)
      plaintext = Crypto.aes_ige_decrypt(aes_key, aes_iv, encrypted)

      expected_mk = Crypto.msg_key(@auth_key, plaintext, direction: :server_to_client)
      raise Error, "msg_key mismatch — possible tampering or wrong auth_key" unless mk == expected_mk

      # Envelope: salt(8) + session_id(8) + msg_id(8) + seq_no(4) + msg_len(4) + body
      msg_len = plaintext[28, 4].unpack1("l<")
      body_bytes = plaintext.byteslice(32, msg_len)
      @deserializer.deserialize(body_bytes)
    end

    # ------------------------------------------------------------------------
    # Response dispatch
    # ------------------------------------------------------------------------

    def wait_for_response(req_msg_id)
      loop do
        body = recv_encrypted
        result = dispatch_top_level(body, req_msg_id)
        return result unless result.equal?(NO_MATCH)
      end
    end

    NO_MATCH = Object.new.freeze
    private_constant :NO_MATCH

    def dispatch_top_level(body, req_msg_id)
      case body[:_]
      when "msg_container"
        body[:messages].each do |inner|
          inner_body = unwrap_gzip(inner[:body])
          result = dispatch_top_level(inner_body, req_msg_id)
          return result unless result.equal?(NO_MATCH)
        end
        NO_MATCH
      when "rpc_result"
        return NO_MATCH unless body[:req_msg_id] == req_msg_id
        unwrap_rpc_result(body[:result])
      when "bad_server_salt"
        @server_salt = body[:new_server_salt]
        raise BadServerSaltError
      when "bad_msg_notification"
        handle_bad_msg(body)
        NO_MATCH
      when "new_session_created"
        @server_salt = body[:server_salt]
        NO_MATCH
      when "pong", "msgs_ack", "future_salts", "msg_detailed_info", "msg_new_detailed_info"
        NO_MATCH
      else
        # An unsolicited update we don't recognize. Skip but log.
        @logger.debug { "skipping top-level body: #{body[:_]}" }
        NO_MATCH
      end
    end

    def unwrap_gzip(body)
      return body unless body.is_a?(Hash) && body[:_] == "gzip_packed"
      raw = Zlib::Inflate.inflate(body[:packed_data])
      @deserializer.deserialize(raw)
    end

    def unwrap_rpc_result(result)
      result = unwrap_gzip(result)
      if result.is_a?(Hash) && result[:_] == "rpc_error"
        raise_rpc_error(result)
      end
      result
    end

    def raise_rpc_error(err)
      code = err[:error_code] || err[:code]
      msg = err[:error_message].to_s

      if (m = msg.match(/\A(PHONE|USER|NETWORK|FILE|STATS)_MIGRATE_(\d+)\z/))
        raise MigrateError.new(code, msg, Integer(m[2]))
      elsif msg == "SESSION_PASSWORD_NEEDED"
        raise PasswordRequired
      else
        raise RPCError.new(code, msg)
      end
    end

    def handle_bad_msg(body)
      case body[:error_code]
      when 16, 17 # msg_id too low / too high → time desync
        # Re-anchor time. Server's msg_id high 32 bits is its current unix time.
        server_time = body[:bad_msg_id] >> 32
        @time_offset = server_time - Time.now.to_i
        @logger.warn { "bad_msg_notification code=#{body[:error_code]}, re-anchored time_offset=#{@time_offset}" }
      else
        @logger.warn { "bad_msg_notification code=#{body[:error_code]} ignored" }
      end
    end

    # ------------------------------------------------------------------------
    # invokeWithLayer + initConnection wrapper for the first call after auth
    # ------------------------------------------------------------------------

    def wrap_first_call(inner_body_bytes)
      # initConnection wraps a query in our device/lang metadata.
      init_conn = @serializer.serialize_method(
        "initConnection",
        api_id:           @api_id,
        device_model:     "Ruby",
        system_version:   RUBY_VERSION,
        app_version:      TgClient::VERSION,
        system_lang_code: "en",
        lang_pack:        "",
        lang_code:        "en",
        query:            nil # filled in below as raw bytes
      )

      # initConnection's last param is `query:!X` — a generic Object. Our
      # serializer would normally emit an Object via its hash form; but we
      # already have the serialized bytes. The trick: rebuild manually.
      init_conn_bytes = build_init_connection(inner_body_bytes)

      # invokeWithLayer { layer:int query:!X }
      invoke_layer_id = @registry.by_name("invokeWithLayer").id
      [invoke_layer_id, TgClient::SCHEMA_LAYER].pack("L<l<") + init_conn_bytes
    end

    def build_init_connection(query_bytes)
      init = @registry.by_name("initConnection")
      io = StringIO.new("".b)
      io.set_encoding(Encoding::BINARY)
      io.write([init.id].pack("L<"))
      # initConnection params (current schema):
      #   flags:#  api_id:int  device_model:string  system_version:string
      #   app_version:string  system_lang_code:string  lang_pack:string
      #   lang_code:string  proxy:flags.0?InputClientProxy
      #   params:flags.1?JSONValue  query:!X
      # We send no proxy / params -> flags = 0.
      io.write([0].pack("L<"))                              # flags
      io.write([@api_id].pack("l<"))                        # api_id
      write_tl_string(io, "Ruby")                           # device_model
      write_tl_string(io, RUBY_VERSION)                     # system_version
      write_tl_string(io, TgClient::VERSION)                # app_version
      write_tl_string(io, "en")                             # system_lang_code
      write_tl_string(io, "")                               # lang_pack
      write_tl_string(io, "en")                             # lang_code
      io.write(query_bytes)                                 # query — raw TL
      io.string
    end

    def write_tl_string(io, str)
      bytes = str.b
      len = bytes.bytesize
      if len < 254
        io.write([len].pack("C"))
        header = 1
      else
        io.write([254].pack("C"))
        io.write([len].pack("L<")[0, 3])
        header = 4
      end
      io.write(bytes)
      pad = (4 - ((header + len) % 4)) % 4
      io.write("\x00".b * pad) if pad.positive?
    end

    # ------------------------------------------------------------------------
    # Padding & ID generation
    # ------------------------------------------------------------------------

    def pad_message(inner)
      remainder = inner.bytesize % 16
      pad_needed = 16 - remainder
      pad_needed += 16 if pad_needed < 12
      inner + SecureRandom.bytes(pad_needed)
    end

    def next_msg_id
      now = Time.now.to_f + @time_offset
      secs = now.floor
      frac = now - secs
      candidate = (secs << 32) | (((frac * (1 << 32)).to_i) & 0xfffffffc)
      candidate = @last_msg_id + 4 if candidate <= @last_msg_id
      @last_msg_id = candidate
    end

    def next_seq_no(content:)
      if content
        s = (@msg_seqno_counter * 2) + 1
        @msg_seqno_counter += 1
        s
      else
        @msg_seqno_counter * 2
      end
    end

    # Instance-level shims for the helpers exposed as module methods on the
    # class. (Module methods on the class keep the helpers easy to spec
    # without instantiating the Client.)
    def dh_kdf(new_nonce, server_nonce) = self.class.dh_kdf(new_nonce, server_nonce)
    def compute_server_salt(new_nonce, server_nonce) = self.class.compute_server_salt(new_nonce, server_nonce)
    def pad_bn_to(bn, size) = self.class.pad_bn_to(bn, size)

    def verify_dh_gen(dh_gen, new_nonce, server_nonce, auth_key, expected:)
      case dh_gen[:_]
      when "dh_gen_ok"
        return if expected == "dh_gen_ok" && new_nonce_hash(new_nonce, 1, auth_key) == dh_gen[:new_nonce_hash1]
      when "dh_gen_retry"
        raise AuthError, "DH handshake requires retry (new_nonce_hash2)"
      when "dh_gen_fail"
        raise AuthError, "DH handshake failed (new_nonce_hash3)"
      end
      raise AuthError, "DH handshake verification failed: #{dh_gen[:_]}"
    end

    def new_nonce_hash(new_nonce, marker, auth_key)
      aux = Crypto.sha1(auth_key)[0, 8]
      Crypto.sha1(new_nonce + [marker].pack("C") + aux)[-16, 16]
    end
  end
end
