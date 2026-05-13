# frozen_string_literal: true

RSpec.describe TgClient::TL do
  let(:fixture_path) { File.expand_path("fixtures/sample.tl", __dir__) }
  let(:registry) { described_class::Parser.parse(fixture_path) }
  let(:serializer) { described_class::Serializer.new(registry) }
  let(:deserializer) { described_class::Deserializer.new(registry) }

  describe "Parser" do
    it "registers constructors with the right id and params" do
      c = registry.by_name("simple")
      expect(c.id).to eq(0x11111111)
      expect(c.is_function).to be false
      expect(c.params.map(&:name)).to eq(%w[a b c])
      expect(c.params.map(&:type)).to eq(%w[int long string])
    end

    it "marks functions with is_function" do
      expect(registry.by_name("doSignIn").is_function).to be true
      expect(registry.by_name("doSignIn").result_type).to eq("Bool")
    end

    it "looks up by 32-bit constructor id" do
      expect(registry.by_id(0x11111111).name).to eq("simple")
    end

    it "parses conditional flag params" do
      c = registry.by_name("withFlags")
      maybe = c.params.find { |p| p.name == "maybe" }
      expect(maybe.conditional?).to be true
      expect(maybe.flag_field).to eq("flags")
      expect(maybe.flag_bit).to eq(0)
      expect(maybe.type).to eq("string")
    end

    it "indexes bare combinators by result type" do
      expect(registry.bare_for("BareMsg").name).to eq("bareMsg")
    end

    it "skips built-in declarations like int/long/string" do
      expect(registry.by_name("int")).to be_nil
      expect(registry.by_name("vector")).to be_nil
    end
  end

  describe "scalar round-trips" do
    it "round-trips int (signed, little-endian)" do
      expect(serializer.serialize_value(-1, "int")).to eq("\xff\xff\xff\xff".b)
      expect(deserializer.read_value(StringIO.new("\x01\x00\x00\x00".b), "int")).to eq(1)
    end

    it "round-trips long" do
      bytes = serializer.serialize_value(0x0102030405060708, "long")
      expect(bytes.bytesize).to eq(8)
      expect(deserializer.read_value(StringIO.new(bytes), "long")).to eq(0x0102030405060708)
    end

    it "treats int128 as a 16-byte string, not an integer" do
      nonce = SecureRandom.bytes(16)
      bytes = serializer.serialize_value(nonce, "int128")
      expect(bytes).to eq(nonce.b)
      expect(deserializer.read_value(StringIO.new(bytes), "int128")).to eq(nonce.b)
    end

    it "rejects int128 values that are not 16 bytes" do
      expect { serializer.serialize_value(0, "int128") }.to raise_error(TgClient::SchemaError, /int128/)
      expect { serializer.serialize_value("short", "int128") }.to raise_error(TgClient::SchemaError, /int128/)
    end

    it "treats int256 as a 32-byte string" do
      nonce = SecureRandom.bytes(32)
      expect(serializer.serialize_value(nonce, "int256")).to eq(nonce.b)
    end

    it "round-trips Bool" do
      expect(serializer.serialize_value(true, "Bool")).to eq([TgClient::TL::BOOL_TRUE_ID].pack("L<"))
      expect(serializer.serialize_value(false, "Bool")).to eq([TgClient::TL::BOOL_FALSE_ID].pack("L<"))
    end
  end

  describe "string encoding" do
    it "uses short form (1-byte length) for strings under 254 bytes" do
      bytes = serializer.serialize_value("hi", "string")
      expect(bytes).to eq("\x02hi\x00".b) # len=2, 'h', 'i', 1 byte padding to align to 4
    end

    it "pads short strings to 4-byte boundary" do
      bytes = serializer.serialize_value("a", "string")
      expect(bytes.bytesize).to eq(4)
      bytes = serializer.serialize_value("abcd", "string")
      expect(bytes.bytesize).to eq(8) # 1 len + 4 data + 3 pad
    end

    it "uses long form (254 prefix + 3-byte length) for strings >= 254 bytes" do
      payload = "x" * 300
      bytes = serializer.serialize_value(payload, "string")
      expect(bytes.bytes[0]).to eq(254)
      expect(bytes.bytes[1..3]).to eq([300 & 0xff, (300 >> 8) & 0xff, 0])
      expect(deserializer.read_value(StringIO.new(bytes), "string").bytesize).to eq(300)
    end

    it "round-trips both forms" do
      ["", "x", "ab", "abc", "abcd", "a" * 253, "a" * 254, "a" * 1024].each do |s|
        bytes = serializer.serialize_value(s, "string")
        expect(deserializer.read_value(StringIO.new(bytes), "string")).to eq(s.b)
        expect(bytes.bytesize % 4).to eq(0), "expected 4-byte aligned for size #{s.bytesize}"
      end
    end
  end

  describe "Vector<T>" do
    it "round-trips a boxed Vector<long>" do
      hash = { _: "withVector", ids: [1, 2, 3, -1] }
      bytes = serializer.serialize_object(hash)
      back = deserializer.deserialize(bytes)
      expect(back).to eq(hash)
    end

    it "emits the Vector boxed id (0x1cb5c415) for Vector<T> params" do
      bytes = serializer.serialize_object({ _: "withVector", ids: [] })
      # 4 bytes constructor + 4 bytes vector id + 4 bytes count
      vector_id = bytes[4, 4].unpack1("L<")
      expect(vector_id).to eq(TgClient::TL::VECTOR_ID)
    end
  end

  describe "flag bitmap and conditional params" do
    it "computes flags from which optional params are present" do
      bytes = serializer.serialize_object({ _: "withFlags", name: "x", maybe: "yes", toggle: true })
      flags = bytes[4, 4].unpack1("L<")
      expect(flags & 0b001).not_to eq(0)  # maybe present
      expect(flags & 0b010).not_to eq(0)  # toggle present
      expect(flags & 0b100).to eq(0)      # count absent
    end

    it "omits absent optional params from the wire" do
      hash = { _: "withFlags", name: "x" }
      bytes = serializer.serialize_object(hash)
      back = deserializer.deserialize(bytes)
      expect(back[:_]).to eq("withFlags")
      expect(back[:name]).to eq("x".b)
      expect(back).not_to have_key(:maybe)
      expect(back).not_to have_key(:toggle)
      expect(back).not_to have_key(:count)
    end

    it "round-trips all flag combinations" do
      [
        { _: "withFlags", name: "a" },
        { _: "withFlags", name: "b", maybe: "yes" },
        { _: "withFlags", name: "c", toggle: true },
        { _: "withFlags", name: "d", count: 42 },
        { _: "withFlags", name: "e", maybe: "y", toggle: true, count: 7 }
      ].each do |hash|
        bytes = serializer.serialize_object(hash)
        back = deserializer.deserialize(bytes)
        expected = hash.transform_values { |v| v.is_a?(String) ? v.b : v }
        expected[:flags] = back[:flags] # flags field is derived
        expect(back).to eq(expected)
      end
    end
  end

  describe "boxed nested types" do
    it "round-trips a constructor that holds another boxed type" do
      hash = { _: "wrapper", peer: { _: "inputPeerUser", user_id: 42, access_hash: 99 }, note: "hello" }
      bytes = serializer.serialize_object(hash)
      back = deserializer.deserialize(bytes)
      expect(back[:_]).to eq("wrapper")
      expect(back[:peer][:_]).to eq("inputPeerUser")
      expect(back[:peer][:user_id]).to eq(42)
      expect(back[:note]).to eq("hello".b)
    end

    it "dispatches by constructor id on read" do
      h = { _: "wrapper", peer: { _: "inputPeerChat", chat_id: 7 }, note: "x" }
      bytes = serializer.serialize_object(h)
      back = deserializer.deserialize(bytes)
      expect(back[:peer][:_]).to eq("inputPeerChat")
      expect(back[:peer][:chat_id]).to eq(7)
    end
  end

  describe "bare types and bare vectors" do
    it "round-trips vector<%BareMsg> (bare lowercase vector of bare combinator)" do
      hash = {
        _: "bareContainer",
        items: [
          { _: "bareMsg", msg_id: 1, body: { _: "boolTrue" } },
          { _: "bareMsg", msg_id: 2, body: { _: "boolFalse" } }
        ]
      }
      bytes = serializer.serialize_object(hash)

      # No vector id should appear after the bareContainer id — bare vector is
      # just count + items.
      after_ctor = bytes[4, 4].unpack1("L<")
      expect(after_ctor).not_to eq(TgClient::TL::VECTOR_ID)
      expect(after_ctor).to eq(2) # count

      back = deserializer.deserialize(bytes)
      expect(back[:_]).to eq("bareContainer")
      expect(back[:items].size).to eq(2)
      expect(back[:items][0][:msg_id]).to eq(1)
      expect(back[:items][0][:body]).to eq(true)
      expect(back[:items][1][:body]).to eq(false)
    end
  end

  describe "method serialization" do
    it "writes the method constructor id followed by params" do
      bytes = serializer.serialize_method("doSignIn", phone: "+1", code: 42)
      ctor_id = bytes[0, 4].unpack1("L<")
      expect(ctor_id).to eq(0x66666666)
    end

    it "rejects calling serialize_method on a non-function constructor" do
      expect { serializer.serialize_method("simple", a: 1, b: 2, c: "x") }
        .to raise_error(TgClient::SchemaError, /not a function/)
    end

    it "rejects unknown methods" do
      expect { serializer.serialize_method("nope", a: 1) }
        .to raise_error(TgClient::SchemaError, /unknown method/)
    end
  end

  describe "error cases" do
    it "raises on unexpected EOF" do
      expect { deserializer.read_value(StringIO.new("\x01\x00".b), "int") }
        .to raise_error(TgClient::SchemaError, /EOF/)
    end

    it "raises on unknown constructor id" do
      bad = [0xdeadbeef].pack("L<")
      expect { deserializer.deserialize(bad) }
        .to raise_error(TgClient::SchemaError, /unknown constructor/)
    end
  end
end
