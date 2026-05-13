# frozen_string_literal: true

# Test doubles used by client_spec.rb and authenticate_spec.rb.

# Records sent frames and serves pre-queued responses. Lets the test inspect
# each outgoing frame (to discover its msg_id) and queue a tailored reply.
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

# Helpers for synthesizing server-side encrypted frames using the same crypto
# as the client.
module ServerHelper
  module_function

  def encrypted_frame(auth_key:, body_bytes:, session_id:, server_salt: 0, msg_id: nil, seq_no: 1)
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
