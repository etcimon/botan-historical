/*
* BigInt
* (C) 1999-2008,2012 Jack Lloyd
*	2007 FlexSecure
*
* Distributed under the terms of the botan license.
*/

import botan.rng;
import botan.alloc.secmem;
import botan.mp_types;
import iosfwd;
import botan.divide;
import botan.charset;
import botan.codec.hex;
/**
* Arbitrary precision integer
*/
struct BigInt
{
public:
	/**
	* Base enumerator for encoding and decoding
	*/
	enum Base { Decimal = 10, Hexadecimal = 16, Binary = 256 };

	/**
	* Sign symbol definitions for positive and negative numbers
	*/
	enum Sign { Negative = 0, Positive = 1 };

	/**
	* DivideByZero Exception
	*/
	class DivideByZero : Exception
	{ 
		this() {
			super("BigInt divide by zero");
		}
	};

	/**
	* Create empty BigInt
	*/
	BigInt() { m_signedness = Positive; }

	/**
	* Create BigInt from 64 bit integer
	* @param n initial value of this BigInt
	*/
	BigInt(ulong n);

	/**
	* Copy Constructor
	* @param other the BigInt to copy
	*/
	BigInt(in BigInt other);

	/**
	* Create BigInt from a string. If the string starts with 0x the
	* rest of the string will be interpreted as hexadecimal digits.
	* Otherwise, it will be interpreted as a decimal number.
	*
	* @param str the string to parse for an integer value
	*/
	BigInt(in string str);

	/**
	* Create a BigInt from an integer in a ubyte array
	* @param buf the ubyte array holding the value
	* @param length size of buf
	* @param base is the number base of the integer in buf
	*/
	BigInt(in ubyte* buf, size_t length, Base base = Binary);

	/**
	* Create a random BigInt of the specified size
	* @param rng random number generator
	* @param bits size in bits
	*/
	BigInt(RandomNumberGenerator rng, size_t bits);

	/**
	* Create BigInt of specified size, all zeros
	* @param sign the sign
	* @param n size of the internal register in words
	*/
	BigInt(Sign sign, size_t n);

	/**
	* Move constructor
	*/
	BigInt(ref BigInt other)
	{
	this.swap(other);
	}

	/**
	* Move assignment
	*/
	BigInt operator=(ref BigInt other)
	{
	if (this != &other)
		this.swap(other);

	return (*this);
	}

	/**
	* Copy assignment
	*/
	BigInt operator=(in BigInt) = default;

	/**
	* Swap this value with another
	* @param other BigInt to swap values with
	*/
	void swap(BigInt other)
	{
	m_reg.swap(other.m_reg);
	std.algorithm.swap(m_signedness, other.m_signedness);
	}

	/**
	* += operator
	* @param y the BigInt to add to this
	*/
	BigInt operator+=(in BigInt y);

	/**
	* -= operator
	* @param y the BigInt to subtract from this
	*/
	BigInt operator-=(in BigInt y);

	/**
	* *= operator
	* @param y the BigInt to multiply with this
	*/
	BigInt operator*=(in BigInt y);

	/**
	* /= operator
	* @param y the BigInt to divide this by
	*/
	BigInt operator/=(in BigInt y);

	/**
	* Modulo operator
	* @param y the modulus to reduce this by
	*/
	BigInt operator%=(in BigInt y);

	/**
	* Modulo operator
	* @param y the modulus (word) to reduce this by
	*/
	word	 operator%=(word y);

	/**
	* Left shift operator
	* @param shift the number of bits to shift this left by
	*/
	BigInt operator<<=(size_t shift);

	/**
	* Right shift operator
	* @param shift the number of bits to shift this right by
	*/
	BigInt operator>>=(size_t shift);

	/**
	* Increment operator
	*/
	BigInt operator++() { return (*this += 1); }

	/**
	* Decrement operator
	*/
	BigInt operator--() { return (*this -= 1); }

	/**
	* Postfix increment operator
	*/
	BigInt  operator++(int) { BigInt x = (*this); ++(*this); return x; }

	/**
	* Postfix decrement operator
	*/
	BigInt  operator--(int) { BigInt x = (*this); --(*this); return x; }

	/**
	* Unary negation operator
	* @return negative this
	*/
	BigInt operator-() const;

	/**
	* ! operator
	* @return true iff this is zero, otherwise false
	*/
	bool operator !() const { return (!is_nonzero()); }

	/**
	* Zeroize the BigInt. The size of the underlying register is not
	* modified.
	*/
	void clear() { zeroise(m_reg); }

	/**
	* Compare this to another BigInt
	* @param n the BigInt value to compare with
	* @param check_signs include sign in comparison?
	* @result if (this<n) return -1, if (this>n) return 1, if both
	* values are identical return 0 [like Perl's <=> operator]
	*/
	int cmp(in BigInt n, bool check_signs = true) const;

	/**
	* Test if the integer has an even value
	* @result true if the integer is even, false otherwise
	*/
	bool is_even() const { return (get_bit(0) == 0); }

	/**
	* Test if the integer has an odd value
	* @result true if the integer is odd, false otherwise
	*/
	bool is_odd()  const { return (get_bit(0) == 1); }

	/**
	* Test if the integer is not zero
	* @result true if the integer is non-zero, false otherwise
	*/
	bool is_nonzero() const { return (!is_zero()); }

	/**
	* Test if the integer is zero
	* @result true if the integer is zero, false otherwise
	*/
	bool is_zero() const
	{
	const size_t sw = sig_words();

	for (size_t i = 0; i != sw; ++i)
		if (m_reg[i])
			return false;
	return true;
	}

	/**
	* Set bit at specified position
	* @param n bit position to set
	*/
	void set_bit(size_t n);

	/**
	* Clear bit at specified position
	* @param n bit position to clear
	*/
	void clear_bit(size_t n);

	/**
	* Clear all but the lowest n bits
	* @param n amount of bits to keep
	*/
	void mask_bits(size_t n);

	/**
	* Return bit value at specified position
	* @param n the bit offset to test
	* @result true, if the bit at position n is set, false otherwise
	*/
	bool get_bit(size_t n) const;

	/**
	* Return (a maximum of) 32 bits of the complete value
	* @param offset the offset to start extracting
	* @param length amount of bits to extract (starting at offset)
	* @result the integer extracted from the register starting at
	* offset with specified length
	*/
	uint get_substring(size_t offset, size_t length) const;

	/**
	* Convert this value into a uint, if it is in the range
	* [0 ... 2**32-1], or otherwise throw new an exception.
	* @result the value as a uint if conversion is possible
	*/
	uint to_uint() const;

	/**
	* @param n the offset to get a ubyte from
	* @result ubyte at offset n
	*/
	ubyte byte_at(size_t n) const;

	/**
	* Return the word at a specified position of the internal register
	* @param n position in the register
	* @return value at position n
	*/
	word word_at(size_t n) const
	{ return ((n < size()) ? m_reg[n] : 0); }

	/**
	* Tests if the sign of the integer is negative
	* @result true, iff the integer has a negative sign
	*/
	bool is_negative() const { return (sign() == Negative); }

	/**
	* Tests if the sign of the integer is positive
	* @result true, iff the integer has a positive sign
	*/
	bool is_positive() const { return (sign() == Positive); }

	/**
	* Return the sign of the integer
	* @result the sign of the integer
	*/
	Sign sign() const { return (m_signedness); }

	/**
	* @result the opposite sign of the represented integer value
	*/
	Sign reverse_sign() const;

	/**
	* Flip the sign of this BigInt
	*/
	void flip_sign();

	/**
	* Set sign of the integer
	* @param sign new Sign to set
	*/
	void set_sign(Sign sign);

	/**
	* @result absolute (positive) value of this
	*/
	ref BigInt abs() const;

	/**
	* Give size of internal register
	* @result size of internal register in words
	*/
	size_t size() const { return m_reg.size(); }

	/**
	* Return how many words we need to hold this value
	* @result significant words of the represented integer value
	*/
	size_t sig_words() const
	{
	const word* x = &m_reg[0];
	size_t sig = m_reg.size();

	while(sig && (x[sig-1] == 0))
		sig--;
	return sig;
	}

	/**
	* Give ubyte length of the integer
	* @result ubyte length of the represented integer value
	*/
	size_t bytes() const;

	/**
	* Get the bit length of the integer
	* @result bit length of the represented integer value
	*/
	size_t bits() const;

	/**
	* Return a mutable pointer to the register
	* @result a pointer to the start of the internal register
	*/
	word* mutable_data() { return &m_reg[0]; }

	/**
	* Return a const pointer to the register
	* @result a pointer to the start of the internal register
	*/
	const word* data() const { return &m_reg[0]; }

	/**
	* Increase internal register buffer to at least n words
	* @param n new size of register
	*/
	void grow_to(size_t n);

	/**
	* Fill BigInt with a random number with size of bitsize
	* @param rng the random number generator to use
	* @param bitsize number of bits the created random value should have
	*/
	void randomize(RandomNumberGenerator rng, size_t bitsize = 0);

	/**
	* Store BigInt-value in a given ubyte array
	* @param buf destination ubyte array for the integer value
	*/
	void binary_encode(ubyte buf[]) const;

	/**
	* Read integer value from a ubyte array with given size
	* @param buf ubyte array buffer containing the integer
	* @param length size of buf
	*/
	void binary_decode(in ubyte* buf, size_t length);

	/**
	* Read integer value from a ubyte array (SafeVector!ubyte)
	* @param buf the array to load from
	*/
	void binary_decode(in SafeVector!ubyte buf)
	{
	binary_decode(&buf[0], buf.size());
	}

	/**
	* @param base the base to measure the size for
	* @return size of this integer in base base
	*/
	size_t encoded_size(Base base = Binary) const;

	/**
	* @param rng a random number generator
	* @param min the minimum value
	* @param max the maximum value
	* @return random integer in [min,max)
	*/
	static ref BigInt random_integer(RandomNumberGenerator rng,
										 const BigInt min,
										 const BigInt max);

	/**
	* Create a power of two
	* @param n the power of two to create
	* @return bigint representing 2^n
	*/
	static ref BigInt power_of_2(size_t n)
	{
	BigInt b;
	b.set_bit(n);
	return b;
	}

	/**
	* Encode the integer value from a BigInt to a std::vector of bytes
	* @param n the BigInt to use as integer source
	* @param base number-base of resulting ubyte array representation
	* @result SafeVector of bytes containing the integer with given base
	*/
	static Vector!ubyte encode(in BigInt n, Base base = Binary);

	/**
	* Encode the integer value from a BigInt to a SafeVector of bytes
	* @param n the BigInt to use as integer source
	* @param base number-base of resulting ubyte array representation
	* @result SafeVector of bytes containing the integer with given base
	*/
	static SafeVector!ubyte encode_locked(in BigInt n,
														 Base base = Binary);

	/**
	* Encode the integer value from a BigInt to a ubyte array
	* @param buf destination ubyte array for the encoded integer
	* value with given base
	* @param n the BigInt to use as integer source
	* @param base number-base of resulting ubyte array representation
	*/
	staticvoid encode(ubyte buf[], const BigInt n, Base base = Binary);

	/**
	* Create a BigInt from an integer in a ubyte array
	* @param buf the binary value to load
	* @param length size of buf
	* @param base number-base of the integer in buf
	* @result BigInt representing the integer in the ubyte array
	*/
	static ref BigInt decode(in ubyte* buf, size_t length,
							Base base = Binary);

	/**
	* Create a BigInt from an integer in a ubyte array
	* @param buf the binary value to load
	* @param base number-base of the integer in buf
	* @result BigInt representing the integer in the ubyte array
	*/
	static ref BigInt decode(in SafeVector!ubyte buf,
							Base base = Binary)
	{
		return BigInt.decode(&buf[0], buf.size(), base);
	}

	/**
	* Create a BigInt from an integer in a ubyte array
	* @param buf the binary value to load
	* @param base number-base of the integer in buf
	* @result BigInt representing the integer in the ubyte array
	*/
	static ref BigInt decode(in Vector!ubyte buf,
							Base base = Binary)
	{
		return BigInt.decode(&buf[0], buf.size(), base);
	}

	/**
	* Encode a BigInt to a ubyte array according to IEEE 1363
	* @param n the BigInt to encode
	* @param bytes the length of the resulting SafeVector!ubyte
	* @result a SafeVector!ubyte containing the encoded BigInt
	*/
	static SafeVector!ubyte encode_1363(in BigInt n, size_t bytes);

private:
	SafeVector!word m_reg;
	Sign m_signedness = Positive;
};

/*
* Arithmetic Operators
*/
BigInt operator+(in BigInt x, const BigInt y);
BigInt operator-(in BigInt x, const BigInt y);
BigInt operator*(in BigInt x, const BigInt y);
BigInt operator/(in BigInt x, const BigInt d);
BigInt operator%(in BigInt x, const BigInt m);
word	operator%(in BigInt x, word m);
BigInt operator<<(in BigInt x, size_t n);
BigInt operator>>(in BigInt x, size_t n);

/*
* Comparison Operators
*/
 bool operator==(in BigInt a, const BigInt b)
{ return (a.cmp(b) == 0); }
 bool operator!=(in BigInt a, const BigInt b)
{ return (a.cmp(b) != 0); }
 bool operator<=(in BigInt a, const BigInt b)
{ return (a.cmp(b) <= 0); }
 bool operator>=(in BigInt a, const BigInt b)
{ return (a.cmp(b) >= 0); }
 bool operator<(in BigInt a, const BigInt b)
{ return (a.cmp(b) < 0); }
 bool operator>(in BigInt a, const BigInt b)
{ return (a.cmp(b) > 0); }

/*
* I/O Operators
*/
ref std.ostream operator<<(ref std.ostream, const BigInt);
std::istream& operator>>(std::istream&, BigInt);

}

namespace std {

template<>
void swap<Botan::BigInt>(Botan::BigInt x, Botan::BigInt y)
{
	x.swap(y);
}
}


/*
* Encode a BigInt
*/
void encode(ubyte* output, ref const BigInt n, Base base)
{
	if (base == Binary)
	{
		n.binary_encode(output);
	}
	else if (base == Hexadecimal)
	{
		SafeVector!ubyte binary = SafeVector!ubyte(n.encoded_size(Binary));
		n.binary_encode(&binary[0]);
		
		hex_encode(cast(char*)(output),
		           &binary[0], binary.size());
	}
	else if (base == Decimal)
	{
		BigInt copy = n;
		BigInt remainder;
		copy.set_sign(Positive);
		const size_t output_size = n.encoded_size(Decimal);
		for (size_t j = 0; j != output_size; ++j)
		{
			divide(copy, 10, copy, remainder);
			output[output_size - 1 - j] =
				Charset.digit2char(cast(ubyte)(remainder.word_at(0)));
			if (copy.is_zero())
				break;
		}
	}
	else
		throw new Invalid_Argument("Unknown BigInt encoding method");
}

/*
* Encode a BigInt
*/
Vector!ubyte encode(in BigInt n, Base base)
{
	Vector!ubyte output = Vector!ubyte(n.encoded_size(base));
	encode(&output[0], n, base);
	if (base != Binary)
		for (size_t j = 0; j != output.size(); ++j)
			if (output[j] == 0)
				output[j] = '0';
	return output;
}

/*
* Encode a BigInt
*/
SafeVector!ubyte encode_locked(in BigInt n, Base base)
{
	SafeVector!ubyte output = SafeVector!ubyte(n.encoded_size(base));
	encode(&output[0], n, base);
	if (base != Binary)
		for (size_t j = 0; j != output.size(); ++j)
			if (output[j] == 0)
				output[j] = '0';
	return output;
}

/*
* Encode a BigInt, with leading 0s if needed
*/
SafeVector!ubyte encode_1363(in BigInt n, size_t bytes)
{
	const size_t n_bytes = n.bytes();
	if (n_bytes > bytes)
		throw new Encoding_Error("encode_1363: n is too large to encode properly");
	
	const size_t leading_0s = bytes - n_bytes;
	
	SafeVector!ubyte output = SafeVector!ubyte(bytes);
	encode(&output[leading_0s], n, Binary);
	return output;
}

/*
* Decode a BigInt
*/
ref BigInt decode(in ubyte* buf, size_t length, Base base)
{
	BigInt r;
	if (base == Binary)
		r.binary_decode(buf, length);
	else if (base == Hexadecimal)
	{
		SafeVector!ubyte binary;
		
		if (length % 2)
		{
			// Handle lack of leading 0
			const char buf0_with_leading_0[2] =
			{ '0', cast(char)(buf[0]) };
			
			binary = hex_decode_locked(buf0_with_leading_0, 2);
			
			binary += hex_decode_locked(cast(string)(buf[1]),
			                            length - 1,
			                            false);
		}
		else
			binary = hex_decode_locked(cast(string)(buf),
			                           length, false);
		
		r.binary_decode(&binary[0], binary.size());
	}
	else if (base == Decimal)
	{
		for (size_t i = 0; i != length; ++i)
		{
			if (Charset.is_space(buf[i]))
				continue;
			
			if (!Charset.is_digit(buf[i]))
				throw new Invalid_Argument("BigInt.decode: "
				                           "Invalid character in decimal input");
			
			const ubyte x = Charset.char2digit(buf[i]);
			
			if (x >= 10)
				throw new Invalid_Argument("BigInt: Invalid decimal string");
			
			r *= 10;
			r += x;
		}
	}
	else
		throw new Invalid_Argument("Unknown BigInt decoding method");
	return r;
}
