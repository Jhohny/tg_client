# frozen_string_literal: true

# Component-level tests for the DH handshake helpers. The full handshake is
# exercised end-to-end against Telegram's real servers via the smoke script
# (examples/smoke.rb).
RSpec.describe TgClient::Client, "DH handshake helpers" do
  describe ".dh_kdf" do
    let(:new_nonce)    { ("\xaa" * 32).b }
    let(:server_nonce) { ("\xbb" * 16).b }
    subject { described_class.dh_kdf(new_nonce, server_nonce) }

    it "returns a 32-byte tmp_aes_key and 32-byte tmp_aes_iv" do
      key, iv = subject
      expect(key.bytesize).to eq(32)
      expect(iv.bytesize).to eq(32)
    end

    it "matches the MTProto KDF: key = SHA1(NS||SN) ++ SHA1(SN||NS)[0,12]" do
      key, _iv = subject
      sha_ns = OpenSSL::Digest::SHA1.digest(new_nonce + server_nonce)
      sha_sn = OpenSSL::Digest::SHA1.digest(server_nonce + new_nonce)
      expect(key).to eq(sha_ns + sha_sn[0, 12])
    end

    it "matches the MTProto KDF: iv = SHA1(SN||NS)[12,8] ++ SHA1(NS||NS) ++ NS[0,4]" do
      _key, iv = subject
      sha_sn = OpenSSL::Digest::SHA1.digest(server_nonce + new_nonce)
      sha_nn = OpenSSL::Digest::SHA1.digest(new_nonce + new_nonce)
      expect(iv).to eq(sha_sn[12, 8] + sha_nn + new_nonce[0, 4])
    end

    it "produces different keys for different new_nonces" do
      k1, _ = subject
      k2, _ = described_class.dh_kdf(SecureRandom.bytes(32), server_nonce)
      expect(k1).not_to eq(k2)
    end
  end

  describe ".compute_server_salt" do
    it "is the XOR of the first 8 bytes of new_nonce and server_nonce, as int64 LE" do
      nn = "\x01\x02\x03\x04\x05\x06\x07\x08".b + ("\x00" * 24).b
      sn = "\xff\xff\xff\xff\xff\xff\xff\xff".b + ("\x00" * 8).b
      salt = described_class.compute_server_salt(nn, sn)
      expect([salt].pack("q<")).to eq("\xfe\xfd\xfc\xfb\xfa\xf9\xf8\xf7".b)
    end

    it "is zero when first 8 bytes are equal" do
      nn = ("\x42" * 32).b
      sn = ("\x42" * 16).b
      expect(described_class.compute_server_salt(nn, sn)).to eq(0)
    end
  end

  describe ".pad_bn_to" do
    it "left-pads a short bn to the requested byte size" do
      bn = OpenSSL::BN.new(0xabcd)
      bytes = described_class.pad_bn_to(bn, 256)
      expect(bytes.bytesize).to eq(256)
      expect(bytes[-2, 2]).to eq("\xab\xcd".b)
      expect(bytes[0, 254]).to eq("\x00".b * 254)
    end

    it "passes through a bn that is exactly the target size" do
      data = SecureRandom.bytes(256)
      bn = OpenSSL::BN.new(data, 2)
      expect(described_class.pad_bn_to(bn, 256).bytesize).to eq(256)
    end

    it "raises if the bn would overflow the target size" do
      bn = OpenSSL::BN.new("\xff" * 257, 2)
      expect { described_class.pad_bn_to(bn, 256) }
        .to raise_error(TgClient::AuthError, /larger than/)
    end
  end
end
