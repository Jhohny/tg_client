# frozen_string_literal: true

RSpec.describe TgClient::Crypto do
  describe ".aes_ige_encrypt / .aes_ige_decrypt" do
    let(:key) { ("\x11" * 32).b }
    let(:iv)  { ("\x22" * 32).b }

    it "round-trips a single-block plaintext" do
      pt = ("a" * 16).b
      ct = described_class.aes_ige_encrypt(key, iv, pt)
      expect(ct.bytesize).to eq(16)
      expect(described_class.aes_ige_decrypt(key, iv, ct)).to eq(pt)
    end

    it "round-trips multi-block plaintext" do
      pt = SecureRandom.bytes(160) # 10 blocks
      ct = described_class.aes_ige_encrypt(key, iv, pt)
      expect(ct.bytesize).to eq(160)
      expect(described_class.aes_ige_decrypt(key, iv, ct)).to eq(pt)
    end

    it "encryption is non-trivial (output differs from input)" do
      pt = ("a" * 16).b
      ct = described_class.aes_ige_encrypt(key, iv, pt)
      expect(ct).not_to eq(pt)
    end

    it "uses iv for the first block (different ivs give different ciphertexts)" do
      pt = ("a" * 16).b
      ct1 = described_class.aes_ige_encrypt(key, iv, pt)
      ct2 = described_class.aes_ige_encrypt(key, ("\x33" * 32).b, pt)
      expect(ct1).not_to eq(ct2)
    end

    it "rejects non-32-byte keys" do
      expect { described_class.aes_ige_encrypt("k" * 16, iv, "p" * 16) }
        .to raise_error(ArgumentError, /key must be 32 bytes/)
    end

    it "rejects non-32-byte ivs" do
      expect { described_class.aes_ige_encrypt(key, "i" * 16, "p" * 16) }
        .to raise_error(ArgumentError, /iv must be 32 bytes/)
    end

    it "rejects non-aligned data" do
      expect { described_class.aes_ige_encrypt(key, iv, "p" * 15) }
        .to raise_error(ArgumentError, /multiple of 16/)
    end

    it "matches a deterministic known-answer when re-run" do
      # Self-consistency: encrypting the same input twice yields the same output.
      pt = ("abcdef0123456789" * 4).b
      a = described_class.aes_ige_encrypt(key, iv, pt)
      b = described_class.aes_ige_encrypt(key, iv, pt)
      expect(a).to eq(b)
    end
  end

  describe ".xor_bytes" do
    it "xors two byte strings of equal length" do
      expect(described_class.xor_bytes("\xff".b, "\x0f".b)).to eq("\xf0".b)
    end

    it "raises on length mismatch" do
      expect { described_class.xor_bytes("\x00".b, "\x00\x01".b) }
        .to raise_error(ArgumentError, /length mismatch/)
    end
  end

  describe ".msg_key and .derive_aes_key_iv" do
    let(:auth_key) { SecureRandom.bytes(256) }
    let(:plaintext) { SecureRandom.bytes(64) }

    it "produces a 16-byte msg_key" do
      expect(described_class.msg_key(auth_key, plaintext, direction: :client_to_server).bytesize).to eq(16)
    end

    it "produces different keys for the two directions" do
      mk_cs = described_class.msg_key(auth_key, plaintext, direction: :client_to_server)
      mk_sc = described_class.msg_key(auth_key, plaintext, direction: :server_to_client)
      expect(mk_cs).not_to eq(mk_sc)
    end

    it "derives a 32-byte aes_key and 32-byte aes_iv" do
      mk = described_class.msg_key(auth_key, plaintext, direction: :client_to_server)
      k, iv = described_class.derive_aes_key_iv(auth_key, mk, direction: :client_to_server)
      expect(k.bytesize).to eq(32)
      expect(iv.bytesize).to eq(32)
    end
  end

  describe ".auth_key_id" do
    it "produces an 8-byte signed integer derived from the last 8 bytes of SHA1(auth_key)" do
      auth_key = SecureRandom.bytes(256)
      kid = described_class.auth_key_id(auth_key)
      expect(kid).to be_a(Integer)
      # Verify it matches the expected derivation.
      sha = OpenSSL::Digest::SHA1.digest(auth_key)
      expect(kid).to eq(sha[-8, 8].unpack1("q<"))
    end
  end

  describe ".factor_pq" do
    it "factors a known pq" do
      # pq = 1724114033281923457 = 1229739323 * 1402015859 (both prime)
      pq_int = 1724114033281923457
      pq_bytes = [pq_int].pack("Q>")
      p_bytes, q_bytes = described_class.factor_pq(pq_bytes)
      p = p_bytes.bytes.inject(0) { |a, b| (a << 8) | b }
      q = q_bytes.bytes.inject(0) { |a, b| (a << 8) | b }
      expect(p).to be < q
      expect(p * q).to eq(pq_int)
    end

    it "factors several random products of small primes" do
      [
        [13, 17],
        [101, 103],
        [65537, 65539],
        [4294967291, 4294967279]  # both ~2^32
      ].each do |(a, b)|
        pq = a * b
        bytes = [pq].pack("Q>").sub(/\A\x00+/, "")
        bytes = "\x00".b + bytes if bytes.empty?
        p_bytes, q_bytes = described_class.factor_pq(bytes)
        p = p_bytes.bytes.inject(0) { |acc, byte| (acc << 8) | byte }
        q = q_bytes.bytes.inject(0) { |acc, byte| (acc << 8) | byte }
        expect([p, q].sort).to eq([a, b].sort)
      end
    end
  end

  describe ".public_keys" do
    it "loads at least one RSA key from the bundled PEM" do
      keys = described_class.public_keys
      expect(keys).not_to be_empty
      keys.each_value do |rsa|
        expect(rsa).to be_a(OpenSSL::PKey::RSA)
        expect(rsa.n.num_bytes).to eq(256) # 2048-bit modulus
      end
    end

    it "indexes by fingerprint matching SHA1(TL(n,e))[-8,8] as int64 LE" do
      fp, rsa = described_class.public_keys.first
      expect(described_class.rsa_fingerprint(rsa)).to eq(fp)
    end
  end

  describe ".rsa_pad_encrypt" do
    let(:rsa) { described_class.public_keys.values.first }

    it "produces a 256-byte ciphertext for valid input" do
      data = SecureRandom.bytes(40) # small payload like p_q_inner_data
      ct = described_class.rsa_pad_encrypt(rsa, data)
      expect(ct.bytesize).to eq(256)
    end

    it "rejects oversized data" do
      expect { described_class.rsa_pad_encrypt(rsa, SecureRandom.bytes(200)) }
        .to raise_error(ArgumentError, /too large/)
    end

    it "produces different ciphertexts on repeated calls (random padding)" do
      data = SecureRandom.bytes(40)
      a = described_class.rsa_pad_encrypt(rsa, data)
      b = described_class.rsa_pad_encrypt(rsa, data)
      expect(a).not_to eq(b)
    end
  end

  describe ".select_public_key" do
    it "returns the matching key for a known fingerprint" do
      known_fp = described_class.public_keys.keys.first
      fp, rsa = described_class.select_public_key([0xdeadbeef, known_fp])
      expect(fp).to eq(known_fp)
      expect(rsa).to be_a(OpenSSL::PKey::RSA)
    end

    it "returns nil for unknown fingerprints" do
      expect(described_class.select_public_key([0xdeadbeef, 0xbadbeef])).to be_nil
    end
  end
end
