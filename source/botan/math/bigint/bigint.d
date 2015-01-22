/*
* BigInt
* (C) 1999-2008,2012 Jack Lloyd
*    2007 FlexSecure
*
* Distributed under the terms of the botan license.
*/
module botan.math.bigint.bigint;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

public import botan.math.mp.mp_types;
public import botan.utils.types;
import botan.constants;
import botan.rng.rng;
import botan.utils.memory.zeroise;
import botan.utils.charset;
import botan.codec.hex;
import botan.math.bigint.divide;
import botan.math.mp.mp_core;
import botan.utils.get_byte;
import botan.utils.parsing;
import botan.utils.rounding;
import botan.utils.parsing;
import botan.utils.bit_ops;
import std.algorithm;
import std.traits : isNumeric;

/**
* Arbitrary precision integer
*/
struct BigInt
{
    enum NOGC = true;
public:
    /*
    * Write the BigInt into a vector
    */
    Array!ubyte toArray(Base base = Decimal) const
    {
        Array!ubyte buffer = BigInt.encode(this, base);
		Array!ubyte ret;
        size_t skip = 0;
        while(skip < buffer.length && buffer[skip] == '0')
            ++skip;
        ret[] = (buffer.ptr + skip)[0 .. buffer.length - skip];
        return ret;
    }

	/*
    * Write the BigInt into a string
    */
	string toString(Base base = Decimal) const
	{
		return toArray(base)[].idup;
	}
    alias Base = int;
    /**
    * Base enumerator for encoding and decoding
    */
    enum : Base { Decimal = 10, Hexadecimal = 16, Binary = 256 }

    alias Sign = bool;
    /**
    * Sign symbol definitions for positive and negative numbers
    */
    enum : Sign { Negative = 0, Positive = 1 }

    /**
    * DivideByZero Exception
    */
    class DivideByZero : Exception
    { 
        this() {
            super("BigInt divide by zero");
        }
    }

    /**
    * Create BigInt from any integer
    * @param n = initial value of this BigInt
    */
    this(T)(T n)
        if (isNumeric!T)
    {
        import std.algorithm : max;
        if (n == 0)
            return;
        const size_t limbs_needed = std.algorithm.max(1, T.sizeof / word.sizeof);
        m_reg.resize(4*limbs_needed);
        foreach (size_t i; 0 .. limbs_needed)
            m_reg[i] = ((n >> (i*MP_WORD_BITS)) & MP_WORD_MASK);
    }

	@disable this(this);

    ref BigInt opAssign(size_t other)
    {
        BigInt bigInt = BigInt(other);
        this.swap(bigInt);
        
        return this;
    }

    /**
    * Copy Constructor
    * @param other = the BigInt to copy
    */
    this(const ref BigInt other)
    {
        m_reg = other.m_reg.dup;
        m_signedness = cast(Sign)other.m_signedness;
    }

    /**
    * Create BigInt from a string. If the string starts with 0x the
    * rest of the string will be interpreted as hexadecimal digits.
    * Otherwise, it will be interpreted as a decimal number.
    *
    * @param str = the string to parse for an integer value
    */
    this(in string str)
    {
        Base base = Decimal;
        size_t markers = 0;
        bool negative = false;
        
        if (str.length > 0 && str[0] == '-')
        {
            markers += 1;
            negative = true;
        }
        
        if (str.length > markers + 2 && str[markers     ] == '0' &&
        str[markers + 1] == 'x')
        {
            markers += 2;
            base = Hexadecimal;
        }
        
		this.m_reg = decode(cast(const(ubyte)*)(str.ptr) + markers, str.length - markers, base);

        if (negative) setSign(Negative);
        else          setSign(Positive);
    }

    /**
    * Create a BigInt from an integer in a ubyte array
    * @param input = the ubyte array holding the value
    * @param length = size of buf
    * @param base = is the number base of the integer in buf
    */
    this(const(ubyte)* input, size_t length, Base base = Binary)
    {
		this.m_reg = decode(input, length, base);
        this.m_signedness = model.m_signedness;
    }

    /**
    * Create a random BigInt of the specified size
    * @param rng = random number generator
    * @param bits = size in bits
    */
    this(RandomNumberGenerator rng, size_t bits)
    {
        randomize(rng, bits);
    }
    /**
    * Create BigInt of specified size, all zeros
    * @param sign = the sign
    * @param size = of the internal register in words
    */
    this(Sign s, size_t size)
    {
        m_reg.resize(roundUp!size_t(size, 8));
        m_signedness = s;
    }

    /**
    * Move constructor
    */
    this(ref BigInt other)
    {
        BigInt other_ = other.dup;
        this.swap(other_);
    }
    
    this(ref SecureVector!ubyte payload, in Sign sign) {
        this(payload.ptr, payload.length);
    }

    
    this(SecureVector!word reg, in Sign sign) {
        m_reg = reg;
        m_signedness = sign;
    }

	/**
    * Move assignment
    */
	ref BigInt opAssign(BigInt other)
	{
		if (&this !is &other)
			this.swap(other);
		return this;
	}

    /**
    * Copy assignment
    */
    // BigInt operator=(const ref BigInt) = default;

    /**
    * Swap this value with another
    * @param other = BigInt to swap values with
    */
    void swap(const ref BigInt other)
    {
		if (other.m_reg.length > 0) {
			auto val = other.m_reg.ptr[0 .. other.length];
			m_reg[] = val;
		}
        else {
			m_reg[] = [cast(word)0];
		}

        m_signedness = other.m_signedness;
    }

    /**
    * += operator
    * @param y = the BigInt to add to this
    */
    void opOpAssign(string op)(const ref BigInt y)
        if (op == "+")
    {
        const size_t x_sw = sigWords(), y_sw = y.sigWords();
        
        const size_t reg_size = std.algorithm.max(x_sw, y_sw) + 1;
        growTo(reg_size);
        
        if (sign() == y.sign())
            bigint_add2(mutablePtr(), reg_size - 1, y.ptr, y_sw);
        else
        {
            int relative_size = bigint_cmp(m_reg.ptr, x_sw, y.ptr, y_sw);
            
            if (relative_size < 0)
            {
                SecureVector!word z = SecureVector!word(reg_size - 1);
                bigint_sub3(z.ptr, y.ptr, reg_size - 1, m_reg.ptr, x_sw);
                m_reg[] = z;
                setSign(y.sign());
            }
            else if (relative_size == 0)
            {
                zeroise(m_reg);
                setSign(Positive);
            }
            else if (relative_size > 0)
                bigint_sub2(mutablePtr(), x_sw, y.ptr, y_sw);
        }
        
    }

    void opOpAssign(string op)(in word y)
        if (op == "+")
    {
        this += BigInt(y);
    }

    /**
    * -= operator
    * @param y = the BigInt to subtract from this
    */
    void opOpAssign(string op)(const ref BigInt y)
        if (op == "-")
    {
        const size_t x_sw = sigWords(), y_sw = y.sigWords();
        
        int relative_size = bigint_cmp(m_reg.ptr, x_sw, y.ptr, y_sw);
        
        const size_t reg_size = std.algorithm.max(x_sw, y_sw) + 1;
        growTo(reg_size);
        
        if (relative_size < 0)
        {
            if (sign() == y.sign())
                bigint_sub2_rev(mutablePtr(), y.ptr, y_sw);
            else
                bigint_add2(mutablePtr(), reg_size - 1, y.ptr, y_sw);
            
            setSign(y.reverseSign());
        }
        else if (relative_size == 0)
        {
            if (sign() == y.sign())
            {
                clear();
                setSign(Positive);
            }
            else
                bigint_shl1(mutablePtr(), x_sw, 0, 1);
        }
        else if (relative_size > 0)
        {
            if (sign() == y.sign())
                bigint_sub2(mutablePtr(), x_sw, y.ptr, y_sw);
            else
                bigint_add2(mutablePtr(), reg_size - 1, y.ptr, y_sw);
        }
    }


    void opOpAssign(string op)(in word y)
        if (op == "-")
    {
        this -= BigInt(y);
    }


    /**
    * *= operator
    * @param y = the BigInt to multiply with this
    */
    void opOpAssign(string op)(const ref BigInt y)
        if (op == "*")
    {
        const size_t x_sw = sigWords(), y_sw = y.sigWords();
        setSign((sign() == y.sign()) ? Positive : Negative);
        
        if (x_sw == 0 || y_sw == 0)
        {
            clear();
            setSign(Positive);
        }
        else if (x_sw == 1 && y_sw)
        {
            growTo(y_sw + 2);
            bigint_linmul3(mutablePtr(), y.ptr, y_sw, wordAt(0));
        }
        else if (y_sw == 1 && x_sw)
        {
            growTo(x_sw + 2);
            bigint_linmul2(mutablePtr(), x_sw, y.wordAt(0));
        }
        else
        {
            growTo(size() + y.length);
            
            SecureVector!word z = SecureVector!word(m_reg.ptr[0 .. x_sw]);
            SecureVector!word workspace = SecureVector!word(size());
            
            bigint_mul(mutablePtr(), size(), workspace.ptr, z.ptr, z.length, x_sw, y.ptr, y.length, y_sw);
        }
    }


    void opOpAssign(string op)(in word y)
        if (op == "*")
    {
        this *= BigInt(y);
    }

    /**
    * /= operator
    * @param y = the BigInt to divide this by
    */
    void opOpAssign(string op)(const ref BigInt y)
        if (op == "/")
    {
        if (y.sigWords() == 1 && isPowerOf2(y.wordAt(0)))
            this >>= (y.bits() - 1);
        else
            this = this / y;
    }


    void opOpAssign(string op)(in word y)
        if (op == "/")
    {
        this /= BigInt(y);
    }


    /**
    * Modulo operator
    * @param y = the modulus to reduce this by
    */
    void opOpAssign(string op)(const ref BigInt mod)
        if (op == "%")
    {
        this = this % mod;
    }

    /**
    * Modulo operator
    * @param y = the modulus (word) to reduce this by
    */
    void opOpAssign(string op)(word mod)
        if (op == "%")
    {
        if (mod == 0)
            throw new DivideByZero();
        
        if (isPowerOf2(mod))
        {
            word result = (wordAt(0) & (mod - 1));
            clear();
            growTo(2);
            m_reg[0] = result;
            return;
        }
        
        word remainder = 0;
        
        for (size_t j = sigWords(); j > 0; --j)
            remainder = bigint_modop(remainder, wordAt(j-1), mod);
        clear();
        growTo(2);
        
        if (remainder && sign() == Negative)
            m_reg[0] = mod - remainder;
        else
            m_reg[0] = remainder;
        
        setSign(Positive);
    }


    /**
    * Left shift operator
    * @param shift = the number of bits to shift this left by
    */
    void opOpAssign(string op)(size_t shift)
        if (op == "<<")
    {
        if (shift)
        {
            const size_t shift_words = shift / MP_WORD_BITS;
            const size_t shift_bits  = shift % MP_WORD_BITS;
            const size_t words = sigWords();
            
            growTo(words + shift_words + (shift_bits ? 1 : 0));
            bigint_shl1(mutablePtr(), words, shift_words, shift_bits);
        }
        
    }

    /**
    * Right shift operator
    * @param shift = the number of bits to shift this right by
    */
    void opOpAssign(string op)(size_t shift)
        if (op == ">>")
    {
        if (shift)
        {
            const size_t shift_words = shift / MP_WORD_BITS;
            const size_t shift_bits  = shift % MP_WORD_BITS;
            
            bigint_shr1(mutablePtr(), sigWords(), shift_words, shift_bits);
            
            if (isZero())
                setSign(Positive);
        }
    }

    /**
    * Increment operator
    */
    BigInt opUnary(string op)() if (op == "++") { return (this + BigInt(1)); }

    /**
    * Decrement operator
    */
    BigInt opUnary(string op)() if (op == "--") { return (this - BigInt(1)); }

    /**
    * Unary negation operator
    * @return negative this
    */
    BigInt opUnary(string op)()
        if (op == "-")
    {
        BigInt ret = this.dup;
        ret.flipSign();
        return ret;
    }

    /**
    * bool cast
    * @return true iff this is not zero, otherwise false
    */
    T opCast(T : bool)() const { return isNonzero(); }

    T opCast(T : BigInt)() const { return *cast(BigInt*)&this; }

    /**
    * Zeroize the BigInt. The size of the underlying register is not
    * modified.
    */
    void clear() 
    { 
        zeroise(m_reg);
    }

    /**
    * Compare this to another BigInt
    * @param other = the BigInt value to compare with
    * @param check_signs = include sign in comparison?
    * @result if (this<n) return -1, if (this>n) return 1, if both
    * values are identical return 0 [like Perl's <=> operator]
    */
    int cmp(const ref BigInt other, bool check_signs = true) const
    {
        if (check_signs)
        {
            if (other.isPositive() && this.isNegative())
                return -1;
            
            if (other.isNegative() && this.isPositive())
                return 1;
            
            if (other.isNegative() && this.isNegative())
                return (-bigint_cmp(m_reg.ptr, this.sigWords(), other.ptr, other.sigWords()));
        }
        
        return bigint_cmp(m_reg.ptr, this.sigWords(), other.ptr, other.sigWords());
    }
    /*
    * Comparison Operators
    */
    bool opEquals(const ref BigInt b) const
    { return (cmp(b) == 0); }

    bool opEquals(in size_t n) const
    { 
        BigInt b = n;
        return (cmp(b) == 0); 
    }


    int opCmp(const ref BigInt b) const
    { 
        return cmp(b);
    }

    int opCmp(in size_t n) const
    { 
        BigInt b = n; 
        return cmp(b); 
    }

    /**
    * Test if the integer has an even value
    * @result true if the integer is even, false otherwise
    */
    bool isEven() const { return (getBit(0) == 0); }

    /**
    * Test if the integer has an odd value
    * @result true if the integer is odd, false otherwise
    */
    bool isOdd()  const { return (getBit(0) == 1); }

    /**
    * Test if the integer is not zero
    * @result true if the integer is non-zero, false otherwise
    */
    bool isNonzero() const { return (!isZero()); }

    /**
    * Test if the integer is zero
    * @result true if the integer is zero, false otherwise
    */
    bool isZero() const
    {
        if (!m_reg) return true;
        const size_t sw = sigWords();
        foreach (size_t i; 0 .. sw)
            if (m_reg[i] > 0)
                return false;
        return true;
    }

    /**
    * Set bit at specified position
    * @param n = bit position to set
    */
    void setBit(size_t n)
    {
        const size_t which = n / MP_WORD_BITS;
        const word mask = cast(word)(1) << (n % MP_WORD_BITS);
        if (which >= size()) growTo(which + 1);
        m_reg[which] |= mask;
    }

    /**
    * Clear bit at specified position
    * @param n = bit position to clear
    */
    void clearBit(size_t n)
    {
        const size_t which = n / MP_WORD_BITS;
        const word mask = cast(word)(1) << (n % MP_WORD_BITS);
        if (which < size())
            m_reg[which] &= ~mask;
    }

    /**
    * Clear all but the lowest n bits
    * @param n = amount of bits to keep
    */
    void maskBits(size_t n)
    {
        if (n == 0) { clear(); return; }
        if (n >= bits()) return;
        
        const size_t top_word = n / MP_WORD_BITS;
        const word mask = (cast(word)(1) << (n % MP_WORD_BITS)) - 1;
        
        if (top_word < size())
            clearMem(&m_reg[top_word+1], size() - (top_word + 1));
        
        m_reg[top_word] &= mask;
    }

    /**
    * Return bit value at specified position
    * @param n = the bit offset to test
    * @result true, if the bit at position n is set, false otherwise
    */
    bool getBit(size_t n) const
    {
        return ((wordAt(n / MP_WORD_BITS) >> (n % MP_WORD_BITS)) & 1);
    }

    /**
    * Return (a maximum of) 32 bits of the complete value
    * @param offset = the offset to start extracting
    * @param length = amount of bits to extract (starting at offset)
    * @result the integer extracted from the register starting at
    * offset with specified length
    */
    uint getSubstring(size_t offset, size_t length) const
    {
        if (length > 32)
            throw new InvalidArgument("BigInt.getSubstring: Substring size too big");
        
        ulong piece = 0;
        foreach (size_t i; 0 .. 8)
        {
            const ubyte part = byteAt((offset / 8) + (7-i));
            piece = (piece << 8) | part;
        }
        
        const ulong mask = (cast(ulong)(1) << length) - 1;
        const size_t shift = (offset % 8);
        
        return cast(uint)((piece >> shift) & mask);
    }

    /**
    * Convert this value into a uint, if it is in the range
    * [0 ... 2**32-1], or otherwise throw new an exception.
    * @result the value as a uint if conversion is possible
    */
    uint toUint() const
    {
        if (isNegative())
            throw new EncodingError("BigInt.to_uint: Number is negative");
        if (bits() >= 32)
            throw new EncodingError("BigInt.to_uint: Number is too big to convert");
        
        uint output = 0;
        for (uint j = 0; j != 4; ++j)
            output = (output << 8) | byteAt(3-j);
        return output;
    }

    /**
    * @param n = the offset to get a ubyte from
    * @result ubyte at offset n
    */
    ubyte byteAt(size_t n) const
    {
        const size_t WORD_BYTES = (word).sizeof;
        size_t word_num = n / WORD_BYTES;
        size_t byte_num = n % WORD_BYTES;
        if (word_num >= size())
            return 0;
        else
            return get_byte(WORD_BYTES - byte_num - 1, m_reg[word_num]);
    }

    /**
    * Return the word at a specified position of the internal register
    * @param n = position in the register
    * @return value at position n
    */
    word wordAt(size_t n) const
    { return ((n < size()) ? m_reg[n] : 0); }

    /**
    * Tests if the sign of the integer is negative
    * @result true, iff the integer has a negative sign
    */
    bool isNegative() const { return (sign() == Negative); }

    /**
    * Tests if the sign of the integer is positive
    * @result true, iff the integer has a positive sign
    */
    bool isPositive() const { return (sign() == Positive); }

    /**
    * Return the sign of the integer
    * @result the sign of the integer
    */
    Sign sign() const { return (m_signedness); }

    /**
    * @result the opposite sign of the represented integer value
    */
    Sign reverseSign() const
    {
        if (sign() == Positive)
            return Negative;
        return Positive;
    }

    /**
    * Flip the sign of this BigInt
    */
    void flipSign()
    {
        setSign(reverseSign());
    }

    /**
    * Set sign of the integer
    * @param sign = new Sign to set
    */
    void setSign(Sign s)
    {
        if (isZero())
            m_signedness = Positive;
        else
            m_signedness = s;
    }

    /**
    * @result absolute (positive) value of this
    */
    BigInt abs() const
    {
        BigInt ret = this.dup;
        ret.setSign(Positive);
        return ret;
    }

    /**
    * Give size of internal register
    * @result size of internal register in words
    */
    size_t size() const { return m_reg.length; }

    // ditto
    size_t length() const { return size(); }

    /**
    * Return how many words we need to hold this value
    * @result significant words of the represented integer value
    */
    size_t sigWords() const
    {
        const word* x = m_reg.ptr;
        size_t sig = m_reg.length;

        while (sig && (x[sig-1] == 0))
            sig--;
        return sig;
    }

    /**
    * Give ubyte length of the integer
    * @result ubyte length of the represented integer value
    */
    size_t bytes() const
    {
        return (bits() + 7) / 8;
    }

    /**
    * Get the bit length of the integer
    * @result bit length of the represented integer value
    */
    size_t bits() const
    {
        const size_t words = sigWords();
        if(words == 0)
            return 0;
        
        const size_t full_words = words - 1;
        return (full_words * MP_WORD_BITS + highBit(wordAt(full_words)));
    }

    /**
    * Return a mutable pointer to the register
    * @result a pointer to the start of the internal register
    */
    word* mutablePtr() { return m_reg.ptr; }

    /**
    * Return a const pointer to the register
    * @result a pointer to the start of the internal register
    */
    @property const(word*) ptr() const { return m_reg.ptr; }

    /**
    * Increase internal register buffer to at least n words
    * @param n = new size of register
    */
    void growTo(size_t n)
    {
        m_reg.resize(roundUp!size_t(n, 8));
    }

    /**
    * Fill BigInt with a random number with size of bitsize
    * @param rng = the random number generator to use
    * @param bitsize = number of bits the created random value should have
    */
    void randomize(RandomNumberGenerator rng, size_t bitsize = 0)
    {
        setSign(Positive);
        
        if (bitsize == 0)
            clear();
        else
        {
            SecureVector!ubyte array = rng.randomVec((bitsize + 7) / 8);
            
            if (bitsize % 8)
                array[0] &= 0xFF >> (8 - (bitsize % 8));
            array[0] |= 0x80 >> ((bitsize % 8) ? (8 - bitsize % 8) : 0);
            binaryDecode(array.ptr, array.length);
        }
    }

    /**
    * Store BigInt-value in a given ubyte array
    * @param buf = destination ubyte array for the integer value
    */
    void binaryEncode(ubyte* output) const
    {
        const size_t sig_bytes = bytes();
        foreach (size_t i; 0 .. sig_bytes)
            output[sig_bytes-i-1] = byteAt(i);
    }

    /**
    * Read integer value from a ubyte array with given size
    * @param buf = ubyte array buffer containing the integer
    * @param length = size of buf
    */
    void binaryDecode(const(ubyte)* buf, size_t length)
    {
        const size_t WORD_BYTES = (word).sizeof;
        
        clear();
        m_reg.resize(roundUp!size_t((length / WORD_BYTES) + 1, 8));
        
        foreach (size_t i; 0 .. (length / WORD_BYTES))
        {
            const size_t top = length - WORD_BYTES*i;
            for (size_t j = WORD_BYTES; j > 0; --j)
                m_reg[i] = (m_reg[i] << 8) | buf[top - j];
        }
        
        foreach (size_t i; 0 .. (length % WORD_BYTES))
            m_reg[length / WORD_BYTES] = (m_reg[length / WORD_BYTES] << 8) | buf[i];
    }


    /**
    * Read integer value from a ubyte array (SecureVector!ubyte)
    * @param buf = the array to load from
    */
    void binaryDecode(const ref SecureVector!ubyte buf)
    {
        binaryDecode(buf.ptr, buf.length);
    }

    /**
    * @param base = the base to measure the size for
    * @return size of this integer in base base
    */
    size_t encodedSize(Base base = Binary) const
    {
        static const double LOG_2_BASE_10 = 0.30102999566;
        
        if (base == Binary)
            return bytes();
        else if (base == Hexadecimal)
            return 2*bytes();
        else if (base == Decimal)
            return cast(size_t)(((cast(double)bits()) * LOG_2_BASE_10) + 1.0);
        else
            throw new InvalidArgument("Unknown base for BigInt encoding");
    }

    /**
    * @param rng = a random number generator
    * @param min = the minimum value
    * @param max = the maximum value
    * @return random integer in [min,max)
    */
    static BigInt randomInteger(RandomNumberGenerator rng, BigInt min, const ref BigInt max)
    {
        BigInt range = -min + max;

        if (range <= 0)
            throw new InvalidArgument("randomInteger: invalid min/max values");
        
        return (min + (BigInt(rng, range.bits() + 2) % range));
    }

    /**
    * Create a power of two
    * @param n = the power of two to create
    * @return bigint representing 2^n
    */
    static BigInt powerOf2(size_t n)
    {
        BigInt b;
        b.setBit(n);
        return b;
    }

    /**
    * Encode the integer value from a BigInt to a std::vector of bytes
    * @param n = the BigInt to use as integer source
    * @param base = number-base of resulting ubyte array representation
    * @result SecureVector of bytes containing the integer with given base
    */
    static Array!ubyte encode(const ref BigInt n, Base base = Binary)
    {
        Array!ubyte output = Vector!ubyte(n.encodedSize(base));
        encode(output.ptr, n, base);
        if (base != Binary)
            for (size_t j = 0; j != output.length; ++j)
                if (output[j] == 0)
                    output[j] = '0';
        return output;
    }

    /**
    * Encode the integer value from a BigInt to a SecureVector of bytes
    * @param n = the BigInt to use as integer source
    * @param base = number-base of resulting ubyte array representation
    * @result SecureVector of bytes containing the integer with given base
    */
    static SecureVector!ubyte encodeLocked(const ref BigInt n, Base base = Binary)
    {
        SecureVector!ubyte output = SecureVector!ubyte(n.encodedSize(base));
        encode(output.ptr, n, base);
        if (base != Binary)
            for (size_t j = 0; j != output.length; ++j)
                if (output[j] == 0)
                    output[j] = '0';
        return output;
    }

    /**
    * Encode the integer value from a BigInt to a ubyte array
    * @param output = destination ubyte array for the encoded integer
    * value with given base
    * @param n = the BigInt to use as integer source
    * @param base = number-base of resulting ubyte array representation
    */
    static void encode(ubyte* output, const ref BigInt n, Base base = Binary)
    {
        if (base == Binary)
        {
            n.binaryEncode(output);
        }
        else if (base == Hexadecimal)
        {
            SecureVector!ubyte binary = SecureVector!ubyte(n.encodedSize(Binary));
            n.binaryEncode(binary.ptr);
            
            hexEncode(cast(char*)(output), binary.ptr, binary.length);
        }
        else if (base == Decimal)
        {
            BigInt copy = n.dup();
            BigInt remainder;
            copy.setSign(Positive);
            const size_t output_size = n.encodedSize(Decimal);
            foreach (size_t j; 0 .. output_size)
            {
                divide(copy, BigInt(10), copy, remainder);
                output[output_size - 1 - j] = digit2char(cast(ubyte)(remainder.wordAt(0)));
                if (copy.isZero())
                    break;
            }
        }
        else
            throw new InvalidArgument("Unknown BigInt encoding method");
    }

    /**
    * Create a BigInt from an integer in a ubyte array
    * @param buf = the binary value to load
    * @param length = size of buf
    * @param base = number-base of the integer in buf
    * @result BigInt representing the integer in the ubyte array
    */
    static BigInt decode(const(ubyte)* buf, size_t length, Base base = Binary)
    {
        BigInt r;
        if (base == Binary)
            r.binaryDecode(buf, length);
        else if (base == Hexadecimal)
        {
            SecureVector!ubyte binary;
            
            if (length % 2)
            {
                // Handle lack of leading 0
                const char[2] buf0_with_leading_0 = [ '0', cast(char)(buf[0]) ];
                
                binary = hexDecodeLocked(buf0_with_leading_0.ptr, 2);
                
                binary ~= hexDecodeLocked(cast(const(char)*)&buf[1], length - 1, false);
            }
            else
                binary = hexDecodeLocked(cast(const(char)*)buf, length, false);
            
            r.binaryDecode(binary.ptr, binary.length);
        }
        else if (base == Decimal)
        {
            foreach (size_t i; 0 .. length)
            {
                if (isSpace(buf[i]))
                    continue;
                
                if (!isDigit(buf[i]))
                    throw new InvalidArgument("BigInt.decode: " ~ "Invalid character in decimal input");
                
                const ubyte x = char2digit(buf[i]);
                
                if (x >= 10)
                    throw new InvalidArgument("BigInt: Invalid decimal string");
                
                r *= 10;
                r += x;
            }
        }
        else
            throw new InvalidArgument("Unknown BigInt decoding method");
        return r;
    }


    /**
    * Create a BigInt from an integer in a ubyte array
    * @param buf = the binary value to load
    * @param base = number-base of the integer in buf
    * @result BigInt representing the integer in the ubyte array
    */
    static BigInt decode(const ref SecureVector!ubyte buf, Base base = Binary)
    {
        return BigInt.decode(buf.ptr, buf.length, base);
    }

    /**
    * Create a BigInt from an integer in a ubyte array
    * @param buf = the binary value to load
    * @param base = number-base of the integer in buf
    * @result BigInt representing the integer in the ubyte array
    */
    static BigInt decode(const ref Vector!ubyte buf, Base base = Binary)
    {
        return BigInt.decode(buf.ptr, buf.length, base);
    }

    /**
    * Encode a BigInt to a ubyte array according to IEEE 1363
    * @param n = the BigInt to encode
    * @param bytes = the length of the resulting SecureVector!ubyte
    * @result a SecureVector!ubyte containing the encoded BigInt
    */
    static SecureVector!ubyte encode1363(const ref BigInt n, size_t bytes)
    {
        const size_t n_bytes = n.bytes();
        if (n_bytes > bytes)
            throw new EncodingError("encode1363: n is too large to encode properly");
        
        const size_t leading_0s = bytes - n_bytes;
        
        SecureVector!ubyte output = SecureVector!ubyte(bytes);
        encode(&output[leading_0s], n, Binary);
        return output;
    }

    /*
    * Addition Operator
    */
    BigInt opBinary(string op)(const ref BigInt y) const
        if (op == "+")
    {
        const BigInt x = this;
        const size_t x_sw = x.sigWords(), y_sw = y.sigWords();
        
        BigInt z = BigInt(x.sign(), std.algorithm.max(x_sw, y_sw) + 1);
        
        if ((x.sign() == y.sign()))
            bigint_add3(z.mutablePtr(), x.ptr, x_sw, y.ptr, y_sw);
        else
        {
            int relative_size = bigint_cmp(x.ptr, x_sw, y.ptr, y_sw);
            
            if (relative_size < 0)
            {
                bigint_sub3(z.mutablePtr(), y.ptr, y_sw, x.ptr, x_sw);
                z.setSign(y.sign());
            }
            else if (relative_size == 0)
                z.setSign(BigInt.Positive);
            else if (relative_size > 0)
                bigint_sub3(z.mutablePtr(), x.ptr, x_sw, y.ptr, y_sw);
        }
        return z;
    }

    BigInt opBinary(string op)(in word y) const
        if (op == "+")
    {
        return this + BigInt(y);
    }

    /*
    * Subtraction Operator
    */
    BigInt opBinary(string op)(const ref BigInt y) const
        if (op == "-")
    {
        const BigInt x = this;
        const size_t x_sw = x.sigWords(), y_sw = y.sigWords();
        
        int relative_size = bigint_cmp(x.ptr, x_sw, y.ptr, y_sw);
        
        BigInt z = BigInt(BigInt.Positive, std.algorithm.max(x_sw, y_sw) + 1);
        
        if (relative_size < 0)
        {
            if (x.sign() == y.sign())
                bigint_sub3(z.mutablePtr(), y.ptr, y_sw, x.ptr, x_sw);
            else
                bigint_add3(z.mutablePtr(), x.ptr, x_sw, y.ptr, y_sw);
            z.setSign(y.reverseSign());
        }
        else if (relative_size == 0)
        {
            if (x.sign() != y.sign())
                bigint_shl2(z.mutablePtr(), x.ptr, x_sw, 0, 1);
        }
        else if (relative_size > 0)
        {
            if (x.sign() == y.sign())
                bigint_sub3(z.mutablePtr(), x.ptr, x_sw, y.ptr, y_sw);
            else
                bigint_add3(z.mutablePtr(), x.ptr, x_sw, y.ptr, y_sw);
            z.setSign(x.sign());
        }
        return z;
    }


    BigInt opBinary(string op)(in word y) const
        if (op == "-")
    {
        return this - BigInt(y);
    }

    /*
    * Multiplication Operator
    */
    BigInt opBinary(string op)(const ref BigInt y) const
        if (op == "*")
    {
        const BigInt x = this;
        const size_t x_sw = x.sigWords(), y_sw = y.sigWords();
        
        BigInt z = BigInt(BigInt.Positive, x.length + y.length);
        
        if (x_sw == 1 && y_sw)
            bigint_linmul3(z.mutablePtr(), y.ptr, y_sw, x.wordAt(0));
        else if (y_sw == 1 && x_sw)
            bigint_linmul3(z.mutablePtr(), x.ptr, x_sw, y.wordAt(0));
        else if (x_sw && y_sw)
        {
            SecureVector!word workspace = SecureVector!word(z.length);
            bigint_mul(z.mutablePtr(), z.length, workspace.ptr,
                        x.ptr, x.length, x_sw,
                        y.ptr, y.length, y_sw);
        }
        
        if (x_sw && y_sw && x.sign() != y.sign())
            z.flipSign();
        return z;
    }


    BigInt opBinary(string op)(in word y) const
        if (op == "*")
    {
        return this * BigInt(y);
    }
    
    /*
    * Division Operator
    */
    BigInt opBinary(string op)(const ref BigInt y) const
        if (op == "/")
    {
        const BigInt x = this;
        BigInt q, r;
        divide(x, y, q, r);
        return q;
    }


    BigInt opBinary(string op)(in word y) const
        if (op == "/")
    {
        return this / BigInt(y);
    }

    /*
    * Modulo Operator
    */
    BigInt opBinary(string op)(const ref BigInt mod) const
        if (op == "%")
    {
        const BigInt n = this;
        if (mod.isZero())
            throw new BigInt.DivideByZero();
        if (mod.isNegative())
            throw new InvalidArgument("BigInt.operator%: modulus must be > 0");
        if (n.isPositive() && mod.isPositive() && n < mod)
            return n.dup;
        
		BigInt q, r;
        divide(n, mod, q, r);
        return r;
    }

    /*
    * Modulo Operator
    */
    word opBinary(string op)(word mod) const
        if (op == "%")
    {
        const BigInt n = this;
        if (mod == 0)
            throw new BigInt.DivideByZero();
        
        if (isPowerOf2(mod))
            return (n.wordAt(0) & (mod - 1));
        
        word remainder = 0;
        
        for (size_t j = n.sigWords(); j > 0; --j)
            remainder = bigint_modop(remainder, n.wordAt(j-1), mod);
        
        if (remainder && n.sign() == BigInt.Negative)
            return mod - remainder;
        return remainder;
    }
    
    /*
    * Left Shift Operator
    */
    BigInt opBinary(string op)(size_t shift) const
        if (op == "<<")
    {
        const BigInt x = this;
        if (shift == 0)
            return BigInt(x);
        
        const size_t shift_words = shift / MP_WORD_BITS,
            shift_bits  = shift % MP_WORD_BITS;
        
        const size_t x_sw = x.sigWords();
        
        BigInt y = BigInt(x.sign(), x_sw + shift_words + (shift_bits ? 1 : 0));
        bigint_shl2(y.mutablePtr(), x.ptr, x_sw, shift_words, shift_bits);
        return y;
    }
    
    /*
    * Right Shift Operator
    */
    BigInt opBinary(string op)(size_t shift) const
        if (op == ">>")
    {
        if (shift == 0)
            return BigInt(this);
        if (bits() <= shift)
            return BigInt(0);
        
        const size_t shift_words = shift / MP_WORD_BITS,
            shift_bits  = shift % MP_WORD_BITS,
            x_sw = sigWords();
        
        BigInt y = BigInt(sign(), x_sw - shift_words);
        bigint_shr2(y.mutablePtr(), ptr, x_sw, shift_words, shift_bits);
        return y;
    }

    @property BigInt dup() const {
        return BigInt(m_reg.dup(), m_signedness);
    }
private:
    SecureVector!word m_reg;
    Sign m_signedness = Positive;
}
