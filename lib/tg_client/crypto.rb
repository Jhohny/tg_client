# frozen_string_literal: true

module TgClient
  # Cryptographic primitives for MTProto 2.0.
  #
  # Includes:
  #   * AES-256-IGE block-chaining mode (built on top of OpenSSL's AES-256-ECB
  #     with padding disabled, because OpenSSL does not expose IGE directly)
  #   * RSA_PAD — the current Telegram RSA padding scheme, used to encrypt
  #     p_q_inner_data during the DH handshake
  #   * msg_key + AES key/IV derivation per MTProto 2.0
  #   * auth_key_id derivation
  #   * Pollard's rho factorization of the 64-bit pq value
  #   * RSA public key fingerprint computation (TL-serialize n,e then SHA1)
  module Crypto
    AUTH_KEY_BYTES   = 256
    RSA_KEY_BYTES    = 256
    RSA_PAD_DATA_LEN = 192

    module_function

    # ------------------------------------------------------------------------
    # SHA helpers
    # ------------------------------------------------------------------------

    def sha1(data)   = OpenSSL::Digest::SHA1.digest(data.b)
    def sha256(data) = OpenSSL::Digest::SHA256.digest(data.b)

    def xor_bytes(a, b)
      raise ArgumentError, "xor_bytes: length mismatch #{a.bytesize} vs #{b.bytesize}" unless a.bytesize == b.bytesize
      a.bytes.zip(b.bytes).map { |x, y| x ^ y }.pack("C*")
    end

    # ------------------------------------------------------------------------
    # AES-256-IGE
    # ------------------------------------------------------------------------

    # Encrypt `plaintext` (multiple of 16 bytes) under AES-256-IGE with the
    # given 32-byte key and 32-byte iv (iv = iv1 || iv2, each 16 bytes).
    def aes_ige_encrypt(key, iv, plaintext)
      check_ige_inputs!(key, iv, plaintext)
      cipher = OpenSSL::Cipher.new("AES-256-ECB").tap do |c|
        c.encrypt
        c.padding = 0
        c.key = key
      end

      prev_c = iv[0, 16]
      prev_p = iv[16, 16]
      ciphertext = "".b

      slice_blocks(plaintext).each do |p_block|
        encrypted = cipher.update(xor_bytes(p_block, prev_c))
        c_block = xor_bytes(encrypted, prev_p)
        ciphertext << c_block
        prev_c = c_block
        prev_p = p_block
      end
      cipher.final # closes the cipher; with padding=0 returns nothing
      ciphertext
    end

    # Decrypt `ciphertext` (multiple of 16 bytes) under AES-256-IGE.
    def aes_ige_decrypt(key, iv, ciphertext)
      check_ige_inputs!(key, iv, ciphertext)
      cipher = OpenSSL::Cipher.new("AES-256-ECB").tap do |c|
        c.decrypt
        c.padding = 0
        c.key = key
      end

      prev_c = iv[0, 16]
      prev_p = iv[16, 16]
      plaintext = "".b

      slice_blocks(ciphertext).each do |c_block|
        decrypted = cipher.update(xor_bytes(c_block, prev_p))
        p_block = xor_bytes(decrypted, prev_c)
        plaintext << p_block
        prev_c = c_block
        prev_p = p_block
      end
      cipher.final
      plaintext
    end

    # ------------------------------------------------------------------------
    # MTProto 2.0 message key derivation
    # ------------------------------------------------------------------------

    # Compute the 16-byte msg_key for a plaintext.
    #   x = 0 for client->server, x = 8 for server->client.
    def msg_key(auth_key, plaintext, direction:)
      x = direction == :client_to_server ? 0 : 8
      digest = sha256(auth_key[88 + x, 32] + plaintext.b)
      digest[8, 16]
    end

    # Returns [aes_key (32 bytes), aes_iv (32 bytes)] for AES-IGE encryption
    # of a single MTProto 2.0 message.
    def derive_aes_key_iv(auth_key, msg_key, direction:)
      x = direction == :client_to_server ? 0 : 8
      sha_a = sha256(msg_key + auth_key[x, 36])
      sha_b = sha256(auth_key[x + 40, 36] + msg_key)
      aes_key = sha_a[0, 8] + sha_b[8, 16] + sha_a[24, 8]
      aes_iv  = sha_b[0, 8] + sha_a[8, 16] + sha_b[24, 8]
      [aes_key, aes_iv]
    end

    # auth_key_id is the lower 64 bits (little-endian read) of SHA1(auth_key).
    def auth_key_id(auth_key)
      sha1(auth_key)[-8, 8].unpack1("q<")
    end

    # ------------------------------------------------------------------------
    # RSA fingerprint and RSA_PAD encryption
    # ------------------------------------------------------------------------

    # Compute Telegram's RSA public key fingerprint:
    #   lower 64 bits of SHA1( TL-serialize(rsa_public_key n:string e:string) ).
    # `rsa_public_key` is a bare combinator, so we serialize n and e as TL
    # strings only (no constructor id).
    def rsa_fingerprint(rsa_key)
      n = rsa_key.n.to_s(2)
      e = rsa_key.e.to_s(2)
      io = StringIO.new("".b)
      io.set_encoding(Encoding::BINARY)
      write_tl_string(io, n)
      write_tl_string(io, e)
      sha1(io.string)[-8, 8].unpack1("q<")
    end

    # Encrypt up to 144 bytes of `data` against `rsa_key` using Telegram's
    # current RSA_PAD scheme. Returns a 256-byte ciphertext.
    def rsa_pad_encrypt(rsa_key, data)
      raise ArgumentError, "data too large for RSA_PAD (#{data.bytesize} > 144)" if data.bytesize > 144

      n = rsa_key.n
      loop do
        padding_len = RSA_PAD_DATA_LEN - data.bytesize
        data_with_padding = data.b + SecureRandom.bytes(padding_len)
        data_pad_reversed = data_with_padding.reverse

        # Inner loop: pick a temp_key, build aes_encrypted, validate < modulus.
        attempt = inner_rsa_pad(data_pad_reversed, data_with_padding)
        key_aes_encrypted = attempt
        next if OpenSSL::BN.new(key_aes_encrypted, 2) >= n

        # Textbook RSA: c = m^e mod n. NO_PADDING with a 256-byte input does
        # exactly that.
        ciphertext = rsa_key.public_encrypt(key_aes_encrypted, OpenSSL::PKey::RSA::NO_PADDING)
        return ciphertext.b
      end
    end

    # ------------------------------------------------------------------------
    # pq factorization (Pollard's rho)
    # ------------------------------------------------------------------------

    # Factor a small composite given as a big-endian byte string.
    # Returns [p_bytes, q_bytes] with p < q, both big-endian, leading zeros stripped.
    def factor_pq(pq_bytes)
      pq = pq_bytes.b.bytes.inject(0) { |acc, b| (acc << 8) | b }
      raise ArgumentError, "pq must be > 1" if pq <= 1

      d = pollard_rho(pq)
      p, q = d, pq / d
      p, q = q, p if p > q
      [bn_to_bytes(p), bn_to_bytes(q)]
    end

    # ------------------------------------------------------------------------
    # Public key registry loaded from lib/tg_client/schema/public_keys.pem
    # ------------------------------------------------------------------------

    PUBLIC_KEYS_PEM_PATH = File.expand_path("schema/public_keys.pem", __dir__)
    private_constant :PUBLIC_KEYS_PEM_PATH

    # Returns a frozen Hash of { Integer fingerprint => OpenSSL::PKey::RSA }.
    def public_keys
      @public_keys ||= load_public_keys(PUBLIC_KEYS_PEM_PATH).freeze
    end

    def load_public_keys(path)
      text = File.read(path)
      keys = {}
      text.scan(/-----BEGIN RSA PUBLIC KEY-----.*?-----END RSA PUBLIC KEY-----/m).each do |pem|
        rsa = OpenSSL::PKey::RSA.new(pem)
        keys[rsa_fingerprint(rsa)] = rsa
      end
      keys
    end

    # Pick the first matching key for a list of server-advertised fingerprints.
    # Returns [fingerprint, rsa_key] or nil if none match.
    def select_public_key(fingerprints)
      fingerprints.each do |fp|
        key = public_keys[fp]
        return [fp, key] if key
      end
      nil
    end

    # ------------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------------

    def check_ige_inputs!(key, iv, data)
      raise ArgumentError, "AES-IGE key must be 32 bytes (got #{key.bytesize})" unless key.bytesize == 32
      raise ArgumentError, "AES-IGE iv must be 32 bytes (got #{iv.bytesize})" unless iv.bytesize == 32
      raise ArgumentError, "AES-IGE data must be a multiple of 16 bytes (got #{data.bytesize})" unless (data.bytesize % 16).zero?
    end

    def slice_blocks(data)
      Array.new(data.bytesize / 16) { |i| data.byteslice(i * 16, 16) }
    end

    def write_tl_string(io, value)
      bytes = value.b
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

    def inner_rsa_pad(data_pad_reversed, data_with_padding)
      temp_key = SecureRandom.bytes(32)
      data_with_hash = data_pad_reversed + sha256(temp_key + data_with_padding)
      aes_encrypted = aes_ige_encrypt(temp_key, "\x00".b * 32, data_with_hash)
      temp_key_xor = xor_bytes(temp_key, sha256(aes_encrypted))
      temp_key_xor + aes_encrypted # 32 + 224 = 256 bytes
    end

    def pollard_rho(n)
      return 2 if n.even?
      loop do
        c = SecureRandom.random_number(n - 1) + 1
        x = SecureRandom.random_number(n - 1) + 1
        y = x
        d = 1
        while d == 1
          x = ((x * x) + c) % n
          y = ((y * y) + c) % n
          y = ((y * y) + c) % n
          d = (x - y).abs.gcd(n)
        end
        return d unless d == n
      end
    end

    def bn_to_bytes(n)
      return "\x00".b if n.zero?
      OpenSSL::BN.new(n).to_s(2).b
    end
  end
end
