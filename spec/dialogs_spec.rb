# frozen_string_literal: true

RSpec.describe TgClient::Client, "#get_dialogs" do
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

  let(:fake_response) do
    {
      _:        "messages.dialogs",
      dialogs:  [],
      messages: [],
      chats: [
        { _: "channel", flags: (1 << 13), id: 555, access_hash: 0x7777_aaaa, title: "BroadcastCh" },
        { _: "chat",    id: 333, title: "Regular group" } # no access_hash
      ],
      users: [
        { _: "user", flags: 1, flags2: 0, id: 100, access_hash: 0xdead_beef }, # flag bit 0 set
        { _: "userEmpty", id: 200 } # no access_hash
      ]
    }
  end

  it "calls messages.getDialogs with the expected default args" do
    expect(client).to receive(:invoke).with(
      "messages.getDialogs",
      offset_date: 0, offset_id: 0,
      offset_peer: { _: "inputPeerEmpty" },
      limit: 100, hash: 0
    ).and_return(fake_response)

    client.get_dialogs
  end

  it "honors the limit: kwarg" do
    expect(client).to receive(:invoke).with(
      "messages.getDialogs", hash_including(limit: 25)
    ).and_return(fake_response)

    client.get_dialogs(limit: 25)
  end

  it "caches access_hash for users that have one" do
    allow(client).to receive(:invoke).and_return(fake_response)
    client.get_dialogs

    cache = client.instance_variable_get(:@peer_cache)
    expect(cache[:users][100]).to eq(0xdead_beef)
    expect(cache[:users][200]).to be_nil
  end

  it "caches access_hash for channels that have one" do
    allow(client).to receive(:invoke).and_return(fake_response)
    client.get_dialogs

    cache = client.instance_variable_get(:@peer_cache)
    expect(cache[:channels][555]).to eq(0x7777_aaaa)
    expect(cache[:channels][333]).to be_nil # basic group, no access_hash
  end

  it "returns the raw dialogs response" do
    allow(client).to receive(:invoke).and_return(fake_response)
    expect(client.get_dialogs).to eq(fake_response)
  end
end
