# frozen_string_literal: true

RSpec.describe TgClient::Client, "#get_history" do
  let(:auth_key)    { SecureRandom.bytes(256) }
  let(:auth_key_id) { TgClient::Crypto.auth_key_id(auth_key) }
  let(:transport)   { FakeTransport.new }
  let(:client) do
    described_class.new(123, "abc", transport: transport).tap do |c|
      c.instance_variable_set(:@auth_key, auth_key)
      c.instance_variable_set(:@auth_key_id, auth_key_id)
      c.instance_variable_set(:@initialized, true)
    end
  end

  let(:base_response) do
    {
      _:        "messages.messages",
      messages: [
        { _: "message", id: 1, date: 1_700_000_000,
          from_id: { _: "peerUser", user_id: 100 },
          peer_id: { _: "peerChannel", channel_id: 555 },
          message: "hello" },
        { _: "message", id: 2, date: 1_700_000_100,
          from_id: { _: "peerUser", user_id: 200 },
          peer_id: { _: "peerChannel", channel_id: 555 },
          message: "world" },
        # Channel-post style: from_id absent, peer is the channel.
        { _: "message", id: 3, date: 1_700_000_200,
          peer_id: { _: "peerChannel", channel_id: 555 },
          message: "broadcast" },
        # Service message — must be skipped.
        { _: "messageService", id: 4, date: 1_700_000_300,
          peer_id: { _: "peerChannel", channel_id: 555 } }
      ],
      chats: [
        { _: "channel", id: 555, title: "Tech Talk", access_hash: 0xaaaa }
      ],
      users: [
        { _: "user", id: 100, first_name: "Ada",   last_name: "Lovelace" },
        { _: "user", id: 200, first_name: "Grace", last_name: "" }
      ]
    }
  end

  describe "InputPeer construction by chat_id sign convention" do
    it "builds inputPeerChannel for chat_id ≤ -1_000_000_000_000" do
      client.instance_variable_get(:@peer_cache)[:channels][555] = 0xcafe
      expect(client).to receive(:invoke) do |method, **kw|
        expect(method).to eq("messages.getHistory")
        expect(kw[:peer]).to eq({ _: "inputPeerChannel", channel_id: 555, access_hash: 0xcafe })
        base_response
      end
      client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
    end

    it "builds inputPeerChat for plain negative chat_id" do
      expect(client).to receive(:invoke) do |_, **kw|
        expect(kw[:peer]).to eq({ _: "inputPeerChat", chat_id: 42 })
        base_response.merge(messages: [], chats: [], users: [])
      end
      client.get_history(chat_id: -42, date_from: 0, limit: 10)
    end

    it "builds inputPeerUser for positive chat_id when access_hash is cached" do
      client.instance_variable_get(:@peer_cache)[:users][100] = 0xface
      expect(client).to receive(:invoke) do |_, **kw|
        expect(kw[:peer]).to eq({ _: "inputPeerUser", user_id: 100, access_hash: 0xface })
        base_response.merge(messages: [], chats: [], users: [])
      end
      client.get_history(chat_id: 100, date_from: 0, limit: 10)
    end

    it "raises a helpful error when access_hash is missing" do
      expect {
        client.get_history(chat_id: 999, date_from: 0, limit: 10)
      }.to raise_error(TgClient::Error, /access_hash.*get_dialogs/)

      expect {
        client.get_history(chat_id: -1_000_000_000_999, date_from: 0, limit: 10)
      }.to raise_error(TgClient::Error, /access_hash.*get_dialogs/)
    end
  end

  describe "date_from normalization" do
    before { client.instance_variable_get(:@peer_cache)[:channels][555] = 0xaa }

    it "accepts Integer (unix timestamp) directly" do
      expect(client).to receive(:invoke).with("messages.getHistory", hash_including(offset_date: 1_700_000_000)).and_return(base_response)
      client.get_history(chat_id: -1_000_000_000_555, date_from: 1_700_000_000, limit: 10)
    end

    it "accepts Time and converts to to_i" do
      t = Time.at(1_700_000_000)
      expect(client).to receive(:invoke).with("messages.getHistory", hash_including(offset_date: 1_700_000_000)).and_return(base_response)
      client.get_history(chat_id: -1_000_000_000_555, date_from: t, limit: 10)
    end

    it "accepts Date and converts to a midnight timestamp" do
      d = Date.new(2024, 1, 1)
      expect(client).to receive(:invoke).with("messages.getHistory", hash_including(offset_date: d.to_time.to_i)).and_return(base_response)
      client.get_history(chat_id: -1_000_000_000_555, date_from: d, limit: 10)
    end

    it "rejects unsupported types" do
      expect {
        client.get_history(chat_id: -1_000_000_000_555, date_from: "yesterday", limit: 10)
      }.to raise_error(ArgumentError, /Integer.*Time.*Date/)
    end
  end

  describe "result shape" do
    before do
      client.instance_variable_get(:@peer_cache)[:channels][555] = 0xaa
      allow(client).to receive(:invoke).and_return(base_response)
    end

    it "returns an array of plain hashes with the documented keys" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records).to be_an(Array)
      expect(records.size).to eq(3) # service message skipped
      expect(records.first.keys).to match_array(%i[id date from_id from_name text])
    end

    it "wraps date in Time" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records.first[:date]).to be_a(Time)
      expect(records.first[:date].to_i).to eq(1_700_000_000)
    end

    it "resolves from_name via the users array" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records[0][:from_id]).to eq(100)
      expect(records[0][:from_name]).to eq("Ada Lovelace")
      expect(records[1][:from_name]).to eq("Grace")
    end

    it "falls back to peer_id when from_id is absent (channel post style)" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records[2][:from_id]).to eq(555)
      expect(records[2][:from_name]).to eq("Tech Talk")
    end

    it "skips messageService entries" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records.map { |r| r[:id] }).to eq([1, 2, 3])
    end

    it "passes through the message text" do
      records = client.get_history(chat_id: -1_000_000_000_555, date_from: 0, limit: 10)
      expect(records[0][:text]).to eq("hello")
      expect(records[2][:text]).to eq("broadcast")
    end
  end
end
