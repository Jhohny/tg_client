# frozen_string_literal: true

require "tmpdir"

RSpec.describe TgClient::Session do
  let(:tmpdir) { Dir.mktmpdir("tg_session") }
  let(:path)   { File.join(tmpdir, "session.json") }
  after        { FileUtils.remove_entry(tmpdir) }

  let(:session) do
    {
      dc_id:       2,
      auth_key:    SecureRandom.bytes(256),
      auth_key_id: 0x1234_5678_9abc_def0,
      server_salt: SecureRandom.bytes(8),
      user_id:     12345,
      layer:       TgClient::SCHEMA_LAYER
    }
  end

  describe ".load" do
    it "returns nil when the file does not exist" do
      expect(described_class.load(path)).to be_nil
    end

    it "expands ~ in the path" do
      expect(described_class.load("~/this-does-not-exist.tg")).to be_nil
    end
  end

  describe ".save and .load round-trip" do
    it "preserves every field, including binary auth_key and server_salt" do
      described_class.save(path, session)
      back = described_class.load(path)
      expect(back).to eq(session.merge(auth_key: session[:auth_key].b, server_salt: session[:server_salt].b))
    end

    it "preserves nil user_id" do
      described_class.save(path, session.merge(user_id: nil))
      expect(described_class.load(path)[:user_id]).to be_nil
    end

    it "writes the file with mode 0600" do
      described_class.save(path, session)
      expect(File.stat(path).mode & 0o777).to eq(0o600)
    end

    it "writes atomically (no leftover .tmp on success)" do
      described_class.save(path, session)
      expect(File.exist?("#{path}.tmp")).to be false
    end

    it "writes valid pretty-printed JSON" do
      described_class.save(path, session)
      json = File.read(path)
      expect { JSON.parse(json) }.not_to raise_error
      expect(json).to include("\n") # pretty-printed
    end
  end

  describe "validation" do
    it "raises on a corrupted file (missing required fields)" do
      File.write(path, JSON.dump({ "dc_id" => 1 }))
      expect { described_class.load(path) }.to raise_error(TgClient::Error, /missing fields/)
    end

    it "raises on invalid JSON" do
      File.write(path, "not json at all{")
      expect { described_class.load(path) }.to raise_error(JSON::ParserError)
    end
  end
end
