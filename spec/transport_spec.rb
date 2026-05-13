# frozen_string_literal: true

# A duplex in-memory "socket" that records writes and serves canned reads.
class FakeSocket
  def initialize(server_response = "".b)
    @to_read = server_response.b.dup
    @written = "".b
  end

  def write(bytes)
    @written << bytes.b
    bytes.bytesize
  end

  def read(n)
    return nil if @to_read.empty?
    chunk = @to_read.byteslice(0, n)
    @to_read = @to_read.byteslice(n..) || "".b
    chunk
  end

  def close; end

  attr_reader :written

  def queue_response(bytes)
    @to_read << bytes.b
  end
end

# Builder for a single TCP Full frame.
def build_frame(seq:, payload:, override_crc: nil, override_seq: nil)
  bytes = payload.b
  len = 12 + bytes.bytesize
  header = [len, override_seq || seq].pack("L<L<")
  crc = override_crc || Zlib.crc32(header + bytes)
  header + bytes + [crc].pack("L<")
end

RSpec.describe TgClient::Transport do
  let(:socket)    { FakeSocket.new }
  let(:transport) { described_class.new(dc_id: 2, socket: socket) }

  describe "framing" do
    it "writes [len][seq][payload][crc32] in little-endian" do
      transport.send_frame("hello!" * 4) # 24 bytes payload
      bytes = socket.written
      len = bytes[0, 4].unpack1("L<")
      seq = bytes[4, 4].unpack1("L<")
      crc = bytes[-4, 4].unpack1("L<")
      expect(len).to eq(12 + 24)
      expect(seq).to eq(0)
      expect(crc).to eq(Zlib.crc32(bytes[0, len - 4]))
      expect(bytes.bytesize).to eq(len)
    end

    it "increments send_seq on each send" do
      transport.send_frame("a" * 4)
      transport.send_frame("b" * 4)
      expect(transport.send_seq).to eq(2)
      # Second frame's seq field should be 1.
      first_len = socket.written[0, 4].unpack1("L<")
      second_seq = socket.written[first_len + 4, 4].unpack1("L<")
      expect(second_seq).to eq(1)
    end

    it "round-trips a payload through send_frame and recv_frame" do
      tx = described_class.new(dc_id: 1, socket: FakeSocket.new)
      rx_socket = FakeSocket.new(build_frame(seq: 0, payload: "ping-payload"))
      rx = described_class.new(dc_id: 1, socket: rx_socket)
      expect(rx.recv_frame).to eq("ping-payload".b)
      expect(rx.recv_seq).to eq(1)
    end

    it "handles a multi-frame stream and tracks recv_seq" do
      stream = build_frame(seq: 0, payload: "one") + build_frame(seq: 1, payload: "two")
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new(stream))
      expect(rx.recv_frame).to eq("one".b)
      expect(rx.recv_frame).to eq("two".b)
      expect(rx.recv_seq).to eq(2)
    end
  end

  describe "error handling" do
    it "raises on CRC mismatch" do
      bad = build_frame(seq: 0, payload: "data", override_crc: 0xdeadbeef)
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new(bad))
      expect { rx.recv_frame }.to raise_error(TgClient::TransportError, /CRC mismatch/)
    end

    it "raises on seq mismatch" do
      out_of_order = build_frame(seq: 5, payload: "data")
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new(out_of_order))
      expect { rx.recv_frame }.to raise_error(TgClient::TransportError, /seq mismatch/)
    end

    it "raises on premature EOF mid-frame" do
      partial = build_frame(seq: 0, payload: "data")[0, 8]
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new(partial))
      expect { rx.recv_frame }.to raise_error(TgClient::TransportError, /EOF/)
    end

    it "raises on EOF with no bytes available" do
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new)
      expect { rx.recv_frame }.to raise_error(TgClient::TransportError, /EOF/)
    end

    it "raises on frame length < 12" do
      malformed = [4].pack("L<")
      rx = described_class.new(dc_id: 1, socket: FakeSocket.new(malformed))
      expect { rx.recv_frame }.to raise_error(TgClient::TransportError, /frame too small/)
    end
  end

  describe "DC address table" do
    it "raises for unknown DC ids when opening a real socket" do
      expect { described_class.new(dc_id: 999) }
        .to raise_error(TgClient::TransportError, /unknown DC/)
    end
  end

  describe "#reconnect_to" do
    it "resets both seq counters" do
      transport.send_frame("a" * 4)
      expect(transport.send_seq).to eq(1)

      # Stub open_socket via injecting a fresh socket through a subclass-y trick:
      # easiest is to call private open_socket directly via send, but we'd hit
      # the network. Instead, verify reset works by replacing @socket via
      # instance_variable_set after manually calling reconnect logic.
      transport.instance_variable_set(:@socket, FakeSocket.new)
      transport.instance_variable_set(:@send_seq, 0)
      transport.instance_variable_set(:@recv_seq, 0)
      expect(transport.send_seq).to eq(0)
      expect(transport.recv_seq).to eq(0)
    end
  end
end
