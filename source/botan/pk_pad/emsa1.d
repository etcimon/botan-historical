/*
* EMSA1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa1;

import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.utils.types;

/**
* EMSA1 from IEEE 1363
* Essentially, sign the hash directly
*/
class EMSA1 : EMSA
{
public:
	/**
	* @param hash the hash function to use
	*/
	this(HashFunction hash) 
	{
		m_hash = hash;
	}

protected:
	size_t hash_output_length() const { return m_hash.output_length; }

private:
	void update(in ubyte* input, size_t length)
	{
		m_hash.update(input, length);
	}

	Secure_Vector!ubyte raw_data()
	{
		return m_hash.flush();
	}

	Secure_Vector!ubyte encoding_of(in Secure_Vector!ubyte msg,
	                             size_t output_bits,
	                             RandomNumberGenerator)
	{
		if (msg.length != hash_output_length())
			throw new Encoding_Error("encoding_of: Invalid size for input");
		return emsa1_encoding(msg, output_bits);
	}

	bool verify(in Secure_Vector!ubyte coded,
	            in Secure_Vector!ubyte raw, size_t key_bits)
	{
		try {
			if (raw.length != m_hash.output_length)
				throw new Encoding_Error("encoding_of: Invalid size for input");
			
			Secure_Vector!ubyte our_coding = emsa1_encoding(raw, key_bits);
			
			if (our_coding == coded) return true;
			if (our_coding.empty || our_coding[0] != 0) return false;
			if (our_coding.length <= coded.length) return false;
			
			size_t offset = 0;
			while (offset < our_coding.length && our_coding[offset] == 0)
				++offset;
			if (our_coding.length - offset != coded.length)
				return false;
			
			for (size_t j = 0; j != coded.length; ++j)
				if (coded[j] != our_coding[j+offset])
					return false;
			
			return true;
		}
		catch(Invalid_Argument)
		{
			return false;
		}
	}

	Unique!HashFunction m_hash;
}

private:

Secure_Vector!ubyte emsa1_encoding(in Secure_Vector!ubyte msg,
                                size_t output_bits)
{
	if (8*msg.length <= output_bits)
		return msg;
	
	size_t shift = 8*msg.length - output_bits;
	
	size_t byte_shift = shift / 8, bit_shift = shift % 8;
	Secure_Vector!ubyte digest = Secure_Vector!ubyte(msg.length - byte_shift);
	
	for (size_t j = 0; j != msg.length - byte_shift; ++j)
		digest[j] = msg[j];
	
	if (bit_shift)
	{
		ubyte carry = 0;
		for (size_t j = 0; j != digest.length; ++j)
		{
			ubyte temp = digest[j];
			digest[j] = (temp >> bit_shift) | carry;
			carry = (temp << (8 - bit_shift));
		}
	}
	return digest;
}
