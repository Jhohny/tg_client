# frozen_string_literal: true

module TgClient
  # TCP Full transport for MTProto.
  #
  # Per https://core.telegram.org/mtproto/mtproto-transports#full each frame is:
  #
  #   [len:uint32_le][seq:uint32_le][payload][crc32:uint32_le]
  #
  # `len` includes itself, the seq field, and the trailing crc — so the payload
  # size is `len - 12`. The seq counters reset on connect and are tracked
  # independently in each direction. CRC32 covers `len || seq || payload`.
  #
  # The constructor accepts an injected `socket:` for testing — any object
  # responding to `read(n)`, `write(bytes)`, and `close` works.
  class Transport
    # Production DC addresses (IPv4). Source: core.telegram.org/api/datacenter.
    DC_ADDRESSES = {
      1 => ["149.154.175.50",  443],
      2 => ["149.154.167.50",  443],
      3 => ["149.154.175.100", 443],
      4 => ["149.154.167.91",  443],
      5 => ["91.108.56.130",   443]
    }.freeze

    TEST_DC_ADDRESSES = {
      1 => ["149.154.175.10",  443],
      2 => ["149.154.167.40",  443],
      3 => ["149.154.175.117", 443]
    }.freeze

    attr_reader :dc_id, :send_seq, :recv_seq

    def initialize(dc_id:, socket: nil, test: false, logger: Logger.new(IO::NULL))
      @logger   = logger
      @test     = test
      @dc_id    = dc_id
      @send_seq = 0
      @recv_seq = 0
      @socket   = socket || open_socket(dc_id)
    end

    # Drop the existing connection and open a fresh one to a different DC.
    # Resets both seq counters.
    def reconnect_to(dc_id)
      close
      @dc_id    = dc_id
      @send_seq = 0
      @recv_seq = 0
      @socket   = open_socket(dc_id)
      nil
    end

    # Wrap `payload` in a TCP Full frame and write it. Increments send_seq.
    def send_frame(payload)
      bytes = payload.b
      len = 12 + bytes.bytesize
      header = [len, @send_seq].pack("L<L<")
      crc = Zlib.crc32(header + bytes)
      frame = header + bytes + [crc].pack("L<")
      @logger.debug { "send_frame seq=#{@send_seq} len=#{len}" }
      @socket.write(frame)
      @send_seq += 1
      nil
    end

    # Read the next TCP Full frame and return the payload bytes. Verifies
    # both the CRC32 and the recv-side seq counter; increments recv_seq.
    def recv_frame
      len_bytes = read_exactly(4)
      len = len_bytes.unpack1("L<")
      raise TransportError, "frame too small: len=#{len}" if len < 12

      rest = read_exactly(len - 4)
      seq = rest[0, 4].unpack1("L<")
      payload = rest[4, len - 12]
      crc_recv = rest[-4, 4].unpack1("L<")
      crc_calc = Zlib.crc32(len_bytes + rest[0, len - 8])

      unless crc_recv == crc_calc
        raise TransportError, "CRC mismatch (got 0x#{crc_recv.to_s(16)}, want 0x#{crc_calc.to_s(16)})"
      end
      unless seq == @recv_seq
        raise TransportError, "seq mismatch (got #{seq}, want #{@recv_seq})"
      end

      @logger.debug { "recv_frame seq=#{seq} len=#{len}" }
      @recv_seq += 1
      payload
    end

    def close
      @socket&.close
      @socket = nil
    rescue StandardError
      # Best-effort; closing a partially open socket can raise.
      @socket = nil
    end

    private

    def open_socket(dc_id)
      table = @test ? TEST_DC_ADDRESSES : DC_ADDRESSES
      host, port = table.fetch(dc_id) { raise TransportError, "unknown DC: #{dc_id}" }
      @logger.debug { "opening TCP socket to DC#{dc_id} #{host}:#{port}" }
      TCPSocket.new(host, port)
    end

    def read_exactly(n)
      buffer = "".b
      while buffer.bytesize < n
        chunk = @socket.read(n - buffer.bytesize)
        if chunk.nil? || chunk.empty?
          raise TransportError, "unexpected EOF after #{buffer.bytesize}/#{n} bytes"
        end
        buffer << chunk.b
      end
      buffer
    end
  end
end
