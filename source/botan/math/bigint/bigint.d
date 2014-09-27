/*
* BigInt Base
* (C) 1999-2011,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.bigint;
import botan.internal.mp_core;
import botan.get_byte;
import botan.parsing;
import botan.internal.rounding;
/*
* Construct a BigInt from a regular number
*/
BigInt::BigInt(ulong n)
{
	if (n == 0)
		return;

	const size_t limbs_needed = sizeof(ulong) / sizeof(word);

	m_reg.resize(4*limbs_needed);
	for (size_t i = 0; i != limbs_needed; ++i)
		m_reg[i] = ((n >> (i*MP_WORD_BITS)) & MP_WORD_MASK);
}

/*
* Construct a BigInt of the specified size
*/
BigInt::BigInt(Sign s, size_t size)
{
	m_reg.resize(round_up<size_t>(size, 8));
	m_signedness = s;
}

/*
* Copy constructor
*/
BigInt::BigInt(in BigInt other)
{
	m_reg = other.m_reg;
	m_signedness = other.m_signedness;
}

/*
* Construct a BigInt from a string
*/
BigInt::BigInt(in string str)
{
	Base base = Decimal;
	size_t markers = 0;
	bool negative = false;

	if (str.length() > 0 && str[0] == '-')
	{
		markers += 1;
		negative = true;
	}

	if (str.length() > markers + 2 && str[markers	 ] == '0' &&
												str[markers + 1] == 'x')
	{
		markers += 2;
		base = Hexadecimal;
	}

	*this = decode(cast(const byte*)(str.data()) + markers,
						str.length() - markers, base);

	if (negative) set_sign(Negative);
	else			set_sign(Positive);
}

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(in byte* input, size_t length, Base base)
{
	*this = decode(input, length, base);
}

/*
* Construct a BigInt from an encoded BigInt
*/
BigInt::BigInt(RandomNumberGenerator& rng, size_t bits)
{
	randomize(rng, bits);
}

/*
* Grow the internal storage
*/
void BigInt::grow_to(size_t n)
{
	if (n > size())
		m_reg.resize(round_up<size_t>(n, 8));
}

/*
* Comparison Function
*/
s32bit BigInt::cmp(in BigInt other, bool check_signs) const
{
	if (check_signs)
	{
		if (other.is_positive() && this->is_negative())
			return -1;

		if (other.is_negative() && this->is_positive())
			return 1;

		if (other.is_negative() && this->is_negative())
			return (-bigint_cmp(this->data(), this->sig_words(),
									  other.data(), other.sig_words()));
	}

	return bigint_cmp(this->data(), this->sig_words(),
							other.data(), other.sig_words());
}

/*
* Return byte n of this number
*/
byte BigInt::byte_at(size_t n) const
{
	const size_t WORD_BYTES = sizeof(word);
	size_t word_num = n / WORD_BYTES, byte_num = n % WORD_BYTES;
	if (word_num >= size())
		return 0;
	else
		return get_byte(WORD_BYTES - byte_num - 1, m_reg[word_num]);
}

/*
* Return bit n of this number
*/
bool BigInt::get_bit(size_t n) const
{
	return ((word_at(n / MP_WORD_BITS) >> (n % MP_WORD_BITS)) & 1);
}

/*
* Return bits {offset...offset+length}
*/
uint BigInt::get_substring(size_t offset, size_t length) const
{
	if (length > 32)
		throw new Invalid_Argument("BigInt::get_substring: Substring size too big");

	ulong piece = 0;
	for (size_t i = 0; i != 8; ++i)
	{
		const byte part = byte_at((offset / 8) + (7-i));
		piece = (piece << 8) | part;
	}

	const ulong mask = (cast(ulong)(1) << length) - 1;
	const size_t shift = (offset % 8);

	return cast(uint)((piece >> shift) & mask);
}

/*
* Convert this number to a uint, if possible
*/
uint BigInt::to_uint() const
{
	if (is_negative())
		throw new Encoding_Error("BigInt::to_uint: Number is negative");
	if (bits() >= 32)
		throw new Encoding_Error("BigInt::to_uint: Number is too big to convert");

	uint out = 0;
	for (uint j = 0; j != 4; ++j)
		out = (out << 8) | byte_at(3-j);
	return out;
}

/*
* Set bit number n
*/
void BigInt::set_bit(size_t n)
{
	const size_t which = n / MP_WORD_BITS;
	const word mask = cast(word)(1) << (n % MP_WORD_BITS);
	if (which >= size()) grow_to(which + 1);
	m_reg[which] |= mask;
}

/*
* Clear bit number n
*/
void BigInt::clear_bit(size_t n)
{
	const size_t which = n / MP_WORD_BITS;
	const word mask = cast(word)(1) << (n % MP_WORD_BITS);
	if (which < size())
		m_reg[which] &= ~mask;
}

/*
* Clear all but the lowest n bits
*/
void BigInt::mask_bits(size_t n)
{
	if (n == 0) { clear(); return; }
	if (n >= bits()) return;

	const size_t top_word = n / MP_WORD_BITS;
	const word mask = (cast(word)(1) << (n % MP_WORD_BITS)) - 1;

	if (top_word < size())
		clear_mem(&m_reg[top_word+1], size() - (top_word + 1));

	m_reg[top_word] &= mask;
}

/*
* Count how many bytes are being used
*/
size_t BigInt::bytes() const
{
	return (bits() + 7) / 8;
}

/*
* Count how many bits are being used
*/
size_t BigInt::bits() const
{
	const size_t words = sig_words();

	if (words == 0)
		return 0;

	size_t full_words = words - 1, top_bits = MP_WORD_BITS;
	word top_word = word_at(full_words), mask = MP_WORD_TOP_BIT;

	while(top_bits && ((top_word & mask) == 0))
	{ mask >>= 1; top_bits--; }

	return (full_words * MP_WORD_BITS + top_bits);
}

/*
* Calcluate the size in a certain base
*/
size_t BigInt::encoded_size(Base base) const
{
	static const double LOG_2_BASE_10 = 0.30102999566;

	if (base == Binary)
		return bytes();
	else if (base == Hexadecimal)
		return 2*bytes();
	else if (base == Decimal)
		return cast(size_t)((bits() * LOG_2_BASE_10) + 1);
	else
		throw new Invalid_Argument("Unknown base for BigInt encoding");
}

/*
* Set the sign
*/
void BigInt::set_sign(Sign s)
{
	if (is_zero())
		m_signedness = Positive;
	else
		m_signedness = s;
}

/*
* Reverse the value of the sign flag
*/
void BigInt::flip_sign()
{
	set_sign(reverse_sign());
}

/*
* Return the opposite value of the current sign
*/
BigInt::Sign BigInt::reverse_sign() const
{
	if (sign() == Positive)
		return Negative;
	return Positive;
}

/*
* Return the negation of this number
*/
BigInt BigInt::operator-() const
{
	BigInt x = (*this);
	x.flip_sign();
	return x;
}

/*
* Return the absolute value of this number
*/
BigInt BigInt::abs() const
{
	BigInt x = (*this);
	x.set_sign(Positive);
	return x;
}

/*
* Encode this number into bytes
*/
void BigInt::binary_encode(byte* output) const
{
	const size_t sig_bytes = bytes();
	for (size_t i = 0; i != sig_bytes; ++i)
		output[sig_bytes-i-1] = byte_at(i);
}

/*
* Set this number to the value in buf
*/
void BigInt::binary_decode(in byte* buf, size_t length)
{
	const size_t WORD_BYTES = sizeof(word);

	clear();
	m_reg.resize(round_up<size_t>((length / WORD_BYTES) + 1, 8));

	for (size_t i = 0; i != length / WORD_BYTES; ++i)
	{
		const size_t top = length - WORD_BYTES*i;
		for (size_t j = WORD_BYTES; j > 0; --j)
			m_reg[i] = (m_reg[i] << 8) | buf[top - j];
	}

	for (size_t i = 0; i != length % WORD_BYTES; ++i)
		m_reg[length / WORD_BYTES] = (m_reg[length / WORD_BYTES] << 8) | buf[i];
}

}
