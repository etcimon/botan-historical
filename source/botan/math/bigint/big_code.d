/*
* BigInt Encoding/Decoding
* (C) 1999-2010,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.bigint;
import botan.divide;
import botan.charset;
import botan.hex;
/*
* Encode a BigInt
*/
void BigInt::encode(ubyte* output, ref const BigInt n, Base base)
{
	if (base == Binary)
	{
		n.binary_encode(output);
	}
	else if (base == Hexadecimal)
	{
		SafeVector!ubyte binary(n.encoded_size(Binary));
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
Vector!ubyte BigInt::encode(in BigInt n, Base base)
{
	Vector!ubyte output(n.encoded_size(base));
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
SafeVector!ubyte BigInt::encode_locked(in BigInt n, Base base)
{
	SafeVector!ubyte output(n.encoded_size(base));
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
SafeVector!ubyte BigInt::encode_1363(in BigInt n, size_t bytes)
{
	const size_t n_bytes = n.bytes();
	if (n_bytes > bytes)
		throw new Encoding_Error("encode_1363: n is too large to encode properly");

	const size_t leading_0s = bytes - n_bytes;

	SafeVector!ubyte output(bytes);
	encode(&output[leading_0s], n, Binary);
	return output;
}

/*
* Decode a BigInt
*/
BigInt BigInt::decode(in ubyte* buf, size_t length, Base base)
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
				throw new Invalid_Argument("BigInt::decode: "
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

}
