# frozen_string_literal: true

module TgClient
  # Parser, serializer, and deserializer for Telegram's TL schema language.
  #
  # The schema text is a list of combinator declarations separated by `;`. A
  # combinator is one of two flavors:
  #
  #   * a *constructor* — a value-bearing struct, e.g. `inputPeerUser#7b8e7de6 user_id:long access_hash:long = InputPeer;`
  #   * a *function* — an RPC method, e.g. `auth.sendCode#a677244f phone_number:string ... = auth.SentCode;`
  #
  # The schema is split into sections by `---types---` and `---functions---`
  # marker lines. Generic declarations like `{X:Type}` are skipped — we only
  # support the `!X` / `Object` style at call sites.
  module TL
    VECTOR_ID     = 0x1cb5c415
    BOOL_TRUE_ID  = 0x997275b5
    BOOL_FALSE_ID = 0xbc799737

    Param = Data.define(:name, :type, :flag_field, :flag_bit) do
      def conditional? = !flag_bit.nil?
      def flags_bitmap? = type == "#"
    end

    Combinator = Data.define(:name, :id, :params, :result_type, :is_function) do
      # Bare combinators are referenced via `%Foo` and read/written without a
      # constructor id prefix. By TL convention they start with a lowercase letter.
      def bare? = name[0]&.match?(/[a-z_]/)
    end

    class Registry
      def initialize
        @by_id     = {}
        @by_name   = {}
        @bare_by_result_type = {}
      end

      def add(combinator)
        @by_id[combinator.id] = combinator if combinator.id
        @by_name[combinator.name] = combinator
        @bare_by_result_type[combinator.result_type] = combinator if combinator.bare?
      end

      def by_id(id)               = @by_id[id]
      def by_name(name)           = @by_name[name]
      def bare_for(result_type)   = @bare_by_result_type[result_type]
      def size                    = @by_name.size
      def each(&)                 = @by_name.each_value(&)
    end

    module Parser
      # Built-in primitive names declared without an #id in the schema. The
      # bare-form `vector`/`boolFalse`/`boolTrue`/`true` combinators *do* have
      # ids in api.tl and are registered like any other combinator — the
      # serializer/deserializer just short-circuits Bool and Vector to their
      # hardcoded constants.
      SKIP_NAMES = %w[int long int128 int256 double string bytes].freeze
      private_constant :SKIP_NAMES

      module_function

      # Parse one or more `.tl` files and return a populated Registry.
      def parse(*paths)
        registry = Registry.new
        paths.each { |path| parse_into(registry, File.read(path)) }
        registry
      end

      def parse_string(text)
        registry = Registry.new
        parse_into(registry, text)
        registry
      end

      def parse_into(registry, text)
        text = text.gsub(%r{/\*.*?\*/}m, "").gsub(%r{//[^\n]*}, "")

        section = :types
        buffer = +""

        text.each_line do |line|
          stripped = line.strip
          if stripped.start_with?("---") && stripped.end_with?("---")
            section = stripped.tr("-", "").strip.to_sym
            buffer.clear
            next
          end
          buffer << line
          while (idx = buffer.index(";"))
            stmt = buffer[0...idx].strip
            buffer.replace(buffer[(idx + 1)..])
            parse_statement(stmt, section, registry) unless stmt.empty?
          end
        end
      end

      def parse_statement(stmt, section, registry)
        lhs, rhs = stmt.split("=", 2).map(&:strip)
        raise SchemaError, "missing '=' in: #{stmt.inspect}" unless rhs

        tokens = lhs.split(/\s+/)
        head = tokens.shift or raise SchemaError, "empty combinator: #{stmt.inspect}"

        if head.include?("#")
          name, id_hex = head.split("#", 2)
          id = id_hex.to_i(16)
        else
          name = head
          id = nil
        end

        return if SKIP_NAMES.include?(name)

        params = tokens.filter_map { |tok| parse_param(tok) }

        registry.add(
          Combinator.new(
            name: name,
            id: id,
            params: params,
            result_type: rhs,
            is_function: section == :functions
          )
        )
      end

      def parse_param(token)
        return nil if token.start_with?("{")
        return nil unless token.include?(":")

        pname, ptype = token.split(":", 2)
        return nil if pname.empty?

        if (m = ptype.match(/\A(\w+)\.(\d+)\?(.+)\z/))
          Param.new(name: pname, type: m[3], flag_field: m[1], flag_bit: m[2].to_i)
        else
          Param.new(name: pname, type: ptype, flag_field: nil, flag_bit: nil)
        end
      end
    end

    # Encode Ruby hashes into TL byte strings.
    class Serializer
      def initialize(registry)
        @registry = registry
      end

      def serialize_method(method_name, args)
        combinator = @registry.by_name(method_name) or raise SchemaError, "unknown method: #{method_name}"
        raise SchemaError, "#{method_name} is not a function" unless combinator.is_function
        io = binary_io
        write_combinator(io, combinator, args)
        io.string
      end

      def serialize_object(value)
        io = binary_io
        write_object(io, value)
        io.string
      end

      def serialize_value(value, type_str)
        io = binary_io
        write_value(io, value, type_str)
        io.string
      end

      def write_combinator(io, combinator, args, boxed: true)
        io.write([combinator.id].pack("L<")) if boxed && combinator.id
        flag_values = compute_flag_values(combinator, args)

        combinator.params.each do |param|
          if param.flags_bitmap?
            io.write([flag_values.fetch(param.name, 0)].pack("L<"))
          elsif param.conditional?
            mask = flag_values.fetch(param.flag_field, 0)
            next if (mask & (1 << param.flag_bit)).zero?
            next if param.type == "true"
            write_value(io, args[param.name.to_sym], param.type)
          else
            write_value(io, args[param.name.to_sym], param.type)
          end
        end
      end

      def write_object(io, value, expected: nil)
        unless value.is_a?(Hash) && value[:_]
          raise SchemaError, "expected hash with :_ for #{expected || "object"}, got #{value.inspect}"
        end
        combinator = @registry.by_name(value[:_]) or raise SchemaError, "unknown combinator: #{value[:_]}"
        write_combinator(io, combinator, value)
      end

      def write_value(io, value, type_str)
        case type_str
        when "int"    then io.write([value].pack("l<"))
        when "long"   then io.write([value].pack("q<"))
        when "int128" then write_raw(io, value, 16, "int128")
        when "int256" then write_raw(io, value, 32, "int256")
        when "double" then io.write([value].pack("E"))
        when "string", "bytes" then write_string(io, value)
        when "Bool"   then io.write([value ? BOOL_TRUE_ID : BOOL_FALSE_ID].pack("L<"))
        when "true"   then # flag-only sentinel; emits nothing
        when "#"      then io.write([value.to_i].pack("L<"))
        else
          if (m = type_str.match(/\AVector<(.+)>\z/))
            write_vector(io, value, m[1], boxed: true)
          elsif (m = type_str.match(/\Avector<(.+)>\z/))
            write_vector(io, value, m[1], boxed: false)
          elsif (m = type_str.match(/\A%(.+)\z/))
            bare = @registry.bare_for(m[1]) or raise SchemaError, "no bare type for #{m[1]}"
            write_combinator(io, bare, value, boxed: false)
          elsif type_str.start_with?("!") || type_str == "Object"
            write_object(io, value, expected: type_str)
          else
            write_object(io, value, expected: type_str)
          end
        end
      end

      private

      def binary_io
        StringIO.new("".b).tap { |io| io.set_encoding(Encoding::BINARY) }
      end

      def compute_flag_values(combinator, args)
        masks = Hash.new(0)
        combinator.params.each do |param|
          next unless param.conditional?
          present = if param.type == "true"
                      args[param.name.to_sym] == true
                    else
                      !args[param.name.to_sym].nil?
                    end
          masks[param.flag_field] |= (1 << param.flag_bit) if present
        end
        masks
      end

      def write_raw(io, value, size, name)
        unless value.is_a?(String) && value.bytesize == size
          got = value.respond_to?(:bytesize) ? "#{value.class}(#{value.bytesize})" : value.class.to_s
          raise SchemaError, "#{name} must be a #{size}-byte String, got #{got}"
        end
        io.write(value.b)
      end

      def write_string(io, value)
        bytes = value.is_a?(String) ? value.b : value.to_s.b
        len = bytes.bytesize
        if len < 254
          io.write([len].pack("C"))
          header = 1
        else
          io.write([254].pack("C"))
          io.write([len].pack("L<")[0, 3])
          header = 4
        end
        io.write(bytes)
        pad = (4 - ((header + len) % 4)) % 4
        io.write("\x00".b * pad) if pad.positive?
      end

      def write_vector(io, values, inner_type, boxed:)
        io.write([VECTOR_ID].pack("L<")) if boxed
        io.write([values.size].pack("l<"))
        values.each { |v| write_value(io, v, inner_type) }
      end
    end

    # Decode TL byte strings into Ruby hashes (with :_ for the constructor name).
    class Deserializer
      def initialize(registry)
        @registry = registry
      end

      def deserialize(bytes)
        read_value(StringIO.new(bytes.b), "Object")
      end

      def read_value(io, type_str)
        case type_str
        when "int"    then read_bytes(io, 4).unpack1("l<")
        when "long"   then read_bytes(io, 8).unpack1("q<")
        when "int128" then read_bytes(io, 16)
        when "int256" then read_bytes(io, 32)
        when "double" then read_bytes(io, 8).unpack1("E")
        when "string", "bytes" then read_string(io)
        when "Bool"   then read_bool(io)
        when "true"   then true
        when "#"      then read_bytes(io, 4).unpack1("L<")
        else
          if (m = type_str.match(/\AVector<(.+)>\z/))
            read_vector(io, m[1], boxed: true)
          elsif (m = type_str.match(/\Avector<(.+)>\z/))
            read_vector(io, m[1], boxed: false)
          elsif (m = type_str.match(/\A%(.+)\z/))
            bare = @registry.bare_for(m[1]) or raise SchemaError, "no bare type for #{m[1]}"
            read_combinator_body(io, bare)
          elsif type_str.start_with?("!") || type_str == "Object"
            read_object(io)
          else
            read_object(io)
          end
        end
      end

      def read_object(io)
        id = read_bytes(io, 4).unpack1("L<")
        case id
        when VECTOR_ID
          count = read_bytes(io, 4).unpack1("l<")
          Array.new(count) { read_object(io) }
        when BOOL_TRUE_ID  then true
        when BOOL_FALSE_ID then false
        else
          combinator = @registry.by_id(id) or raise SchemaError, "unknown constructor 0x#{id.to_s(16)}"
          read_combinator_body(io, combinator)
        end
      end

      def read_combinator_body(io, combinator)
        result = { _: combinator.name }
        flag_values = Hash.new(0)

        combinator.params.each do |param|
          if param.flags_bitmap?
            v = read_bytes(io, 4).unpack1("L<")
            flag_values[param.name] = v
            result[param.name.to_sym] = v
          elsif param.conditional?
            mask = flag_values.fetch(param.flag_field, 0)
            next if (mask & (1 << param.flag_bit)).zero?
            result[param.name.to_sym] = param.type == "true" ? true : read_value(io, param.type)
          else
            result[param.name.to_sym] = read_value(io, param.type)
          end
        end
        result
      end

      private

      def read_bool(io)
        id = read_bytes(io, 4).unpack1("L<")
        case id
        when BOOL_TRUE_ID  then true
        when BOOL_FALSE_ID then false
        else raise SchemaError, "expected Bool, got 0x#{id.to_s(16)}"
        end
      end

      def read_string(io)
        first = read_bytes(io, 1).unpack1("C")
        if first < 254
          len = first
          header = 1
        else
          parts = read_bytes(io, 3).unpack("C3")
          len = parts[0] | (parts[1] << 8) | (parts[2] << 16)
          header = 4
        end
        data = read_bytes(io, len)
        pad = (4 - ((header + len) % 4)) % 4
        read_bytes(io, pad) if pad.positive?
        data
      end

      def read_vector(io, inner_type, boxed:)
        if boxed
          id = read_bytes(io, 4).unpack1("L<")
          raise SchemaError, "expected Vector id, got 0x#{id.to_s(16)}" unless id == VECTOR_ID
        end
        count = read_bytes(io, 4).unpack1("l<")
        Array.new(count) { read_value(io, inner_type) }
      end

      def read_bytes(io, n)
        return "".b if n.zero?
        data = io.read(n)
        if data.nil? || data.bytesize != n
          raise SchemaError, "unexpected EOF: wanted #{n}, got #{data&.bytesize || 0}"
        end
        data
      end
    end
  end
end
