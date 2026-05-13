# frozen_string_literal: true

require "tmpdir"

RSpec.describe TgClient::Client, "#authenticate" do
  let(:tmpdir)       { Dir.mktmpdir("tg_auth") }
  let(:session_file) { File.join(tmpdir, "test.session") }
  let(:transport)    { FakeTransport.new }
  let(:client) do
    described_class.new(123, "abc", session_file: session_file, transport: transport)
  end

  after { FileUtils.remove_entry(tmpdir) }

  describe "resuming from an existing session file" do
    let(:auth_key)    { SecureRandom.bytes(256) }
    let(:auth_key_id) { TgClient::Crypto.auth_key_id(auth_key) }

    before do
      TgClient::Session.save(session_file, {
                               dc_id: 2,
                               auth_key: auth_key,
                               auth_key_id: auth_key_id,
                               server_salt: ("\x00" * 8).b,
                               user_id: 4242,
                               layer: TgClient::SCHEMA_LAYER
                             })
    end

    it "returns :resumed without contacting the network" do
      expect(client.authenticate(phone: "+1")).to eq(:resumed)
      expect(transport.sent).to be_empty
    end

    it "loads auth_key, auth_key_id, and dc_id from the file" do
      client.authenticate(phone: "+1")
      expect(client.instance_variable_get(:@auth_key)).to eq(auth_key.b)
      expect(client.instance_variable_get(:@auth_key_id)).to eq(auth_key_id)
      expect(client.dc_id).to eq(2)
    end

    it "does not prompt the user for a code" do
      expect($stdin).not_to receive(:gets)
      client.authenticate(phone: "+1")
    end
  end

  describe "fresh authentication" do
    let(:auth_key)    { SecureRandom.bytes(256) }
    let(:auth_key_id) { TgClient::Crypto.auth_key_id(auth_key) }
    let(:session_id)  { client.instance_variable_get(:@session_id) }

    # Stub the DH handshake to set fake auth state directly. The handshake
    # itself is exercised by handshake_spec.rb and end-to-end by the smoke
    # script — testing it through #authenticate requires mocking 5+ canned
    # frames which adds little signal beyond what the helpers already cover.
    before do
      allow(client).to receive(:do_dh_handshake) do
        client.instance_variable_set(:@auth_key, auth_key)
        client.instance_variable_set(:@auth_key_id, auth_key_id)
        client.instance_variable_set(:@server_salt, 0)
      end
    end

    it "runs sendCode, prompts for the code, calls signIn, and persists the session" do
      call_count = 0
      transport.on_send do |sent_frame|
        call_count += 1
        msg_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        body = case call_count
               when 1
                 # auth.sendCode response: a fake auth.sentCode
                 sent_code = client.send(:instance_variable_get, :@serializer).serialize_object(
                   _:                "auth.sentCode",
                   type:             { _: "auth.sentCodeTypeSms", length: 5 },
                   phone_code_hash:  "deadbeefhash"
                 )
                 [client.registry.by_name("rpc_result").id, msg_id].pack("L<q<") + sent_code
               when 2
                 # auth.signIn response: auth.authorization
                 auth_resp = client.send(:instance_variable_get, :@serializer).serialize_object(
                   _:    "auth.authorization",
                   flags: 0,
                   user: { _: "userEmpty", id: 7777 }
                 )
                 [client.registry.by_name("rpc_result").id, msg_id].pack("L<q<") + auth_resp
               end
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body, session_id: session_id))
      end

      result = client.authenticate(phone: "+5215512345678", code_provider: -> { "12345" })
      expect(result).to eq(:authenticated)
      expect(File.exist?(session_file)).to be true

      saved = TgClient::Session.load(session_file)
      expect(saved[:auth_key]).to eq(auth_key.b)
      expect(saved[:user_id]).to eq(7777)
      expect(call_count).to eq(2)
    end

    it "raises PasswordRequired when auth.signIn returns SESSION_PASSWORD_NEEDED" do
      call_count = 0
      transport.on_send do |sent_frame|
        call_count += 1
        msg_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        body = if call_count == 1
                 sent_code = client.send(:instance_variable_get, :@serializer).serialize_object(
                   _:               "auth.sentCode",
                   type:            { _: "auth.sentCodeTypeSms", length: 5 },
                   phone_code_hash: "h"
                 )
                 [client.registry.by_name("rpc_result").id, msg_id].pack("L<q<") + sent_code
               else
                 err = client.send(:instance_variable_get, :@serializer).serialize_object(
                   _:             "rpc_error",
                   error_code:    401,
                   error_message: "SESSION_PASSWORD_NEEDED"
                 )
                 [client.registry.by_name("rpc_result").id, msg_id].pack("L<q<") + err
               end
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body, session_id: session_id))
      end

      expect {
        client.authenticate(phone: "+1", code_provider: -> { "00000" })
      }.to raise_error(TgClient::PasswordRequired)
      expect(File.exist?(session_file)).to be false
    end
  end
end
