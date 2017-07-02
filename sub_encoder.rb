#!/usr/bin/env ruby
# modified from https://github.com/rapid7/metasploit-framework/blob/master/modules/encoders/x86/opt_sub.rb

require 'rex'
require 'rex/text'
require 'optparse'

class SubEncoder
  ASM_SUBESP20 = "\x83\xEC\x20".freeze

  SET_ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.freeze
  SET_SYM = '!@#$%^&*()_+\\-=[]{};\'":<>,.?/|~'.freeze
  SET_NUM = '0123456789'.freeze
  SET_FILESYM = '()_+-=\\/.,[]{}@!$%^&='.freeze

  CHAR_SET_ALPHA = SET_ALPHA + SET_SYM
  CHAR_SET_ALPHANUM = SET_ALPHA + SET_NUM + SET_SYM
  CHAR_SET_FILEPATH = SET_ALPHA + SET_NUM + SET_FILESYM

  def initialize(opts)
    @opts = opts
    # configure our instruction dictionary
    @asm = {
        'NOP' => "\x90",
        'AND' => {'EAX' => "\x25"},
        'SUB' => {'EAX' => "\x2D"},
        'PUSH' => {
            'EBP' => "\x55", 'ESP' => "\x54",
            'EAX' => "\x50", 'EBX' => "\x53",
            'ECX' => "\x51", 'EDX' => "\x52",
            'EDI' => "\x57", 'ESI' => "\x56"
        },
        'POP' => {'ESP' => "\x5C", 'EAX' => "\x58", }
    }

    # determine the required bytes
    @required_bytes = @asm['SUB']['EAX'] + @asm['PUSH']['EAX']

    # generate a sorted list of valid characters
    char_set = ""
    case (@opts[:charset] || "").upcase
      when 'ALPHA'
        char_set = CHAR_SET_ALPHA
      when 'ALPHANUM'
        char_set = CHAR_SET_ALPHANUM
      when 'FILEPATH'
        char_set = CHAR_SET_FILEPATH
      else
        for i in 0 .. 255
          char_set += i.chr.to_s
        end
    end

    # remove any bad chars and populate our valid chars array.
    @valid_chars = ""
    char_set.each_char do |c|
      @valid_chars << c.to_s unless @opts[:badchars].include?(c.to_s)
    end

    # we need the valid chars sorted because of the algorithm we use
    @valid_chars = @valid_chars.chars.sort.join
    @valid_bytes = @valid_chars.bytes.to_a

    all_bytes_valid = @required_bytes.bytes.reduce(true) {|a, byte| a && @valid_bytes.include?(byte)}

    # determine if we have any invalid characters that we rely on.
    unless all_bytes_valid
      raise EncodingError, 'Bad character set contains characters that are required for this encoder to function.'
    end
  end

  #
  # Determine the bytes, if any, that will result in the given chunk
  # being decoded using SUB instructions from the previous EAX value
  #
  def calc(from, to)
    carry = 0
    shift = 0
    target = from - to
    sum = [0, 0, 0]

    4.times do |idx|
      b = (target >> shift) & 0xFF
      lo = md = hi = 0

      # keep going through the character list under the "lowest" valid
      # becomes too high (ie. we run out)
      while lo < @valid_bytes.length
        # get the total of the three current bytes, including the carry from
        # the previous calculation
        total = @valid_bytes[lo] + @valid_bytes[md] + @valid_bytes[hi] + carry

        # if we matched a byte...
        if (total & 0xFF) == b
          # store the carry for the next calculation
          carry = (total >> 8) & 0xFF

          # store the values in the respective locations
          sum[2] |= @valid_bytes[lo] << shift
          sum[1] |= @valid_bytes[md] << shift
          sum[0] |= @valid_bytes[hi] << shift
          break
        end

        hi += 1
        if hi >= @valid_bytes.length
          md += 1
          hi = md
        end

        if md >= @valid_bytes.length
          lo += 1
          hi = md = lo
        end
      end

      # we ran out of chars to try
      if lo >= @valid_bytes.length
        return nil, nil
      end

      shift += 8
    end

    sum
  end

  #
  # Helper that writes instructions to zero out EAX using two AND instructions.
  #
  def zero_eax
    data = ""
    data << @asm['AND']['EAX']
    data << @clear1
    data << @asm['AND']['EAX']
    data << @clear2
    data
  end

  class OptsConsole
    def self.parse(args)
      options = {}
      parser = OptionParser.new do |opt|
        opt.banner = "Usage: #{__FILE__} [from] [to]\nExample: #{__FILE__} 0x00000000 0xffffffff"
        opt.separator ''
        opt.separator 'Specific options:'

        opt.on('-f', '--from <String>', 'From address') do |v|
          options[:from] = v
        end

        opt.on('-t', '--to <String>', 'To address') do |v|
          options[:to] = v
        end

        opt.on('-b', '--badchars <String>', '(Optional) Bad characters to avoid') do |v|
          options[:badchars] = v
        end

        opt.on('-c', '--charset <String>', '(Optional) Charset') do |v|
          options[:charset] = v
        end

        opt.on_tail('-h', '--help', 'Show this message') do
          $stdout.puts opt
          exit
        end
      end

      parser.parse(args)

      if options.empty?
        raise OptionParser::MissingArgument, 'No options set, try -h for usage'
      elsif options.has_key?('from') && options.has_key?('to')
        raise OptionParser::MissingArgument, '-f and -t are required'
      end

      options[:badchars] = '' unless options[:badchars]
      options[:charset] = 'ALPHANUM' unless options[:charset]

      options
    end
  end


  class Driver
    def initialize
      begin
        @opts = OptsConsole.parse(ARGV)
      rescue OptionParser::ParseError => e
        $stderr.puts "[x] #{e.message}"
        exit
      end
    end

    def run
      from = @opts[:from].to_i
      to = @opts[:to].to_i

      enc = SubEncoder.new(@opts)
      puts "Transforming from #{@opts[:from]} to #{@opts[:to]}\n"
      result = enc.calc(from, to)

      puts 'Instructions:'
      result.each_index {|idx| puts "sub eax, 0x#{result[idx].to_s(16)}"}
      puts

      puts 'Shellcode:'
      result.each_index {|idx|
        tmp = result[idx].to_s(16)
        tmp = [tmp].pack('H*').unpack('N*').pack('V*').unpack('H*')
        tmp = tmp[0]
        tmp = '2d' + tmp
        puts tmp
      }
      puts

      puts 'Shellcode (Hex):'
      result.each_index {|idx|
        tmp = result[idx].to_s(16)
        tmp = [tmp].pack('H*').unpack('N*').pack('V*').unpack('H*')
        tmp = tmp[0]
        tmp = '2d' + tmp
        puts tmp.gsub(/[0-9a-f]{2}/, '\\x\0')
      }
      puts
    end
  end

end

if __FILE__ == $0
  driver = SubEncoder::Driver.new
  begin
    driver.run
  rescue ::Exception => e
    $stderr.puts "[x] #{e.class}: #{e.message}"
  end
end
