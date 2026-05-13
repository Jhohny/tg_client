# frozen_string_literal: true

# Fake transport that records sent frames and serves responses on demand.
# The optional `on_send` hook lets the test inspect each sent frame and queue
# a tailored response (e.g. an rpc_result with matching req_msg_id).
class FakeTransport
  attr_reader :sent, :dc_id

  def initialize(dc_id: 2)
    @dc_id     = dc_id
    @sent      = []
    @responses = []
    @on_send   = nil
  end

  def on_send(&block)
    @on_send = block
  end

  def queue_recv(frame)
    @responses << frame.b
  end

  def send_frame(payload)
    @sent << payload.b
    @on_send&.call(payload.b)
  end

  def recv_frame
    raise "no responses queued for recv" if @responses.empty?
    @responses.shift
  end

  def close; end
  def reconnect_to(dc_id); @dc_id = dc_id; end
end

# Helpers to construct fully-formed encrypted server responses for tests.
module ServerHelper
  module_function

  def encrypted_frame(auth_key:, body_bytes:, server_salt: 0, session_id:, msg_id: nil, seq_no: 1)
    msg_id ||= ((Time.now.to_i + 1) << 32) | 4
    inner = [server_salt].pack("q<") + [session_id].pack("q<") + [msg_id].pack("q<") +
            [seq_no, body_bytes.bytesize].pack("l<l<") + body_bytes
    remainder = inner.bytesize % 16
    pad_needed = 16 - remainder
    pad_needed += 16 if pad_needed < 12
    padded = inner + SecureRandom.bytes(pad_needed)

    mk = TgClient::Crypto.msg_key(auth_key, padded, direction: :server_to_client)
    aes_key, aes_iv = TgClient::Crypto.derive_aes_key_iv(auth_key, mk, direction: :server_to_client)
    encrypted = TgClient::Crypto.aes_ige_encrypt(aes_key, aes_iv, padded)
    auth_key_id = TgClient::Crypto.auth_key_id(auth_key)
    [auth_key_id].pack("q<") + mk + encrypted
  end

  def extract_msg_id_from_client_frame(frame, auth_key)
    mk = frame[8, 16]
    encrypted = frame.byteslice(24..)
    aes_key, aes_iv = TgClient::Crypto.derive_aes_key_iv(auth_key, mk, direction: :client_to_server)
    plaintext = TgClient::Crypto.aes_ige_decrypt(aes_key, aes_iv, encrypted)
    plaintext[16, 8].unpack1("q<")
  end
end

RSpec.describe TgClient::Client do
  let(:auth_key)    { SecureRandom.bytes(256) }
  let(:auth_key_id) { TgClient::Crypto.auth_key_id(auth_key) }
  let(:transport)   { FakeTransport.new }
  let(:client) do
    TgClient::Client.new(123, "abc", transport: transport).tap do |c|
      c.instance_variable_set(:@auth_key, auth_key)
      c.instance_variable_set(:@auth_key_id, auth_key_id)
      c.instance_variable_set(:@initialized, true) # skip wrap_first_call
    end
  end

  let(:session_id) { client.instance_variable_get(:@session_id) }

  # Encode a body in the same way the deserializer expects: constructor id + params.
  def encode_rpc_result(req_msg_id, result_body_hash)
    inner_body = client.send(:instance_variable_get, :@serializer).serialize_object(result_body_hash)
    [client.registry.by_name("rpc_result").id, req_msg_id].pack("L<q<") + inner_body
  end

  def encode_object(hash)
    client.send(:instance_variable_get, :@serializer).serialize_object(hash)
  end

  describe "#invoke (happy path)" do
    it "encrypts a method call, decrypts the rpc_result, and returns the parsed body" do
      transport.on_send do |sent_frame|
        req_msg_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        # Reply with a Bool=true wrapped in rpc_result
        body_bytes = [client.registry.by_name("rpc_result").id, req_msg_id].pack("L<q<") +
                     [TgClient::TL::BOOL_TRUE_ID].pack("L<")
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body_bytes, session_id: session_id))
      end

      expect(client.invoke("help.getConfig")).to eq(true)
    end

    it "ignores rpc_results with non-matching req_msg_id and keeps reading" do
      transport.on_send do |sent_frame|
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)

        # First response: someone else's rpc_result.
        other_body = [client.registry.by_name("rpc_result").id, my_id + 4].pack("L<q<") +
                     [TgClient::TL::BOOL_FALSE_ID].pack("L<")
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: other_body, session_id: session_id))

        # Second response: ours.
        my_body = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") +
                  [TgClient::TL::BOOL_TRUE_ID].pack("L<")
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: my_body, session_id: session_id))
      end

      expect(client.invoke("help.getConfig")).to eq(true)
    end
  end

  describe "#invoke error handling" do
    it "raises RPCError when the result is an rpc_error" do
      transport.on_send do |sent_frame|
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        err = encode_object({ _: "rpc_error", error_code: 400, error_message: "PHONE_INVALID" })
        body = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") + err
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body, session_id: session_id))
      end

      expect { client.invoke("help.getConfig") }.to raise_error(TgClient::RPCError) do |e|
        expect(e.code).to eq(400)
        expect(e.error_message).to eq("PHONE_INVALID")
      end
    end

    it "raises MigrateError carrying the destination DC on *_MIGRATE_N errors" do
      transport.on_send do |sent_frame|
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        err = encode_object({ _: "rpc_error", error_code: 303, error_message: "PHONE_MIGRATE_4" })
        body = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") + err
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body, session_id: session_id))
      end

      expect { client.invoke("help.getConfig") }.to raise_error(TgClient::MigrateError) do |e|
        expect(e.dc_id).to eq(4)
      end
    end

    it "raises PasswordRequired on SESSION_PASSWORD_NEEDED" do
      transport.on_send do |sent_frame|
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        err = encode_object({ _: "rpc_error", error_code: 401, error_message: "SESSION_PASSWORD_NEEDED" })
        body = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") + err
        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: body, session_id: session_id))
      end

      expect { client.invoke("help.getConfig") }.to raise_error(TgClient::PasswordRequired)
    end
  end

  describe "#invoke and bad_server_salt" do
    it "updates @server_salt and retries when the server replies with bad_server_salt" do
      sent_frames = 0
      new_salt = 0x1122_3344_5566_7788

      transport.on_send do |sent_frame|
        sent_frames += 1
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)

        if sent_frames == 1
          bad = encode_object({
                                _: "bad_server_salt",
                                bad_msg_id: my_id, bad_msg_seqno: 1,
                                error_code: 48, new_server_salt: new_salt
                              })
          transport.queue_recv(ServerHelper.encrypted_frame(
                                 auth_key: auth_key, body_bytes: bad, session_id: session_id))
        else
          ok = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") +
               [TgClient::TL::BOOL_TRUE_ID].pack("L<")
          transport.queue_recv(ServerHelper.encrypted_frame(
                                 auth_key: auth_key, body_bytes: ok,
                                 server_salt: new_salt, session_id: session_id))
        end
      end

      expect(client.invoke("help.getConfig")).to eq(true)
      expect(sent_frames).to eq(2)
      expect(client.instance_variable_get(:@server_salt)).to eq(new_salt)
    end
  end

  describe "#invoke and msg_container" do
    it "walks msg_container to find the rpc_result and applies side-effect messages" do
      transport.on_send do |sent_frame|
        my_id = ServerHelper.extract_msg_id_from_client_frame(sent_frame, auth_key)
        new_salt = 0x1234_5678_abcd_dead

        new_session = encode_object({ _: "new_session_created",
                                      first_msg_id: my_id, unique_id: 1, server_salt: new_salt })
        rpc = [client.registry.by_name("rpc_result").id, my_id].pack("L<q<") +
              [TgClient::TL::BOOL_TRUE_ID].pack("L<")

        container_inner = [
          { _: "message", msg_id: my_id + 4, seqno: 0, bytes: new_session.bytesize, body: { _: "new_session_created", first_msg_id: my_id, unique_id: 1, server_salt: new_salt } },
          { _: "message", msg_id: my_id + 8, seqno: 1, bytes: rpc.bytesize, body: { _: "rpc_result", req_msg_id: my_id, result: true } }
        ]
        # Build the container body by hand because our serializer can't handle the
        # raw rpc_result body's :result containing a primitive `true`.
        # Simpler: build the container body via raw bytes.
        container_id = client.registry.by_name("msg_container").id
        # bare message: msg_id(8) + seqno(4) + bytes(4) + body
        msg1 = [my_id + 4].pack("q<") + [0, new_session.bytesize].pack("l<l<") + new_session
        msg2 = [my_id + 8].pack("q<") + [1, rpc.bytesize].pack("l<l<") + rpc
        container = [container_id, 2].pack("L<l<") + msg1 + msg2

        transport.queue_recv(ServerHelper.encrypted_frame(
                               auth_key: auth_key, body_bytes: container, session_id: session_id))
      end

      expect(client.invoke("help.getConfig")).to eq(true)
      expect(client.instance_variable_get(:@server_salt)).to eq(0x1234_5678_abcd_dead)
    end
  end

  describe "msg_id and seq_no generation" do
    it "produces strictly monotonically increasing msg_ids per session" do
      ids = Array.new(5) { client.send(:next_msg_id) }
      expect(ids).to eq(ids.sort)
      expect(ids.uniq.size).to eq(ids.size)
    end

    it "increments content seq_no by 2 (odd values)" do
      a = client.send(:next_seq_no, content: true)
      b = client.send(:next_seq_no, content: true)
      expect(b - a).to eq(2)
      expect(a.odd?).to be true
      expect(b.odd?).to be true
    end

    it "uses even seq_no for pure service messages" do
      client.send(:next_seq_no, content: true) # bump counter
      s = client.send(:next_seq_no, content: false)
      expect(s.even?).to be true
    end
  end

  describe "padding" do
    it "pads inner messages to a 16-byte boundary with at least 12 bytes of padding" do
      inner = SecureRandom.bytes(40)
      padded = client.send(:pad_message, inner)
      expect(padded.bytesize % 16).to eq(0)
      expect(padded.bytesize - inner.bytesize).to be >= 12
    end

    it "pads even when input is already 16-aligned (adds an extra 16 bytes)" do
      inner = SecureRandom.bytes(32)
      padded = client.send(:pad_message, inner)
      expect(padded.bytesize).to eq(48)
    end
  end

  describe "#invoke_plain (unencrypted)" do
    it "wraps the body with auth_key_id=0 and reads an unencrypted response" do
      # Construct an unencrypted response: [auth_key_id=0][msg_id][msg_len][body]
      body = [TgClient::TL::BOOL_TRUE_ID].pack("L<")
      msg_id = ((Time.now.to_i + 1) << 32) | 4
      frame = [0, msg_id].pack("q<q<") + [body.bytesize].pack("l<") + body
      transport.queue_recv(frame)

      result = client.invoke_plain("help.getConfig")
      expect(result).to eq(true)

      # And the sent frame should have auth_key_id=0.
      expect(transport.sent.last[0, 8].unpack1("q<")).to eq(0)
    end
  end
end
