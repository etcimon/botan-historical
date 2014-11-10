/*
* X9.31 EMSA
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa_x931;

import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.pk_pad.hash_id;

/**
* EMSA from X9.31 (EMSA2 in IEEE 1363)
* Useful for Rabin-Williams, also sometimes used with RSA in
* odd protocols.
*/
final class EMSA_X931 : EMSA
{
public:
	/**
	* @param hash the hash object to use
	*/
	this(HashFunction hash)
	{
		m_hash = hash;
		m_empty_hash = m_hash.flush();
		
		m_hash_id = ieee1363_hash_id(hash.name);
		
		if (!m_hash_id)
			throw new Encoding_Error("EMSA_X931 no hash identifier for " ~ hash.name);
	}
private:
	void update(in ubyte* input, size_t length)
	{
		m_hash.update(input, length);
	}

	Secure_Vector!ubyte raw_data()
	{
		return m_hash.flush();
	}

	/*
	* EMSA_X931 Encode Operation
	*/
	Secure_Vector!ubyte encoding_of(in Secure_Vector!ubyte msg,
	                             size_t output_bits,
	                             RandomNumberGenerator)
	{
		return emsa2_encoding(msg, output_bits, m_empty_hash, m_hash_id);
	}

	/*
	* EMSA_X931 Verify Operation
	*/
	bool verify(in Secure_Vector!ubyte coded,
	            in Secure_Vector!ubyte raw,
	            size_t key_bits)
	{
		try
		{
			return (coded == emsa2_encoding(raw, key_bits,
			                                m_empty_hash, m_hash_id));
		}
		catch
		{
			return false;
		}
	}

	Secure_Vector!ubyte m_empty_hash;
	Unique!HashFunction m_hash;
	ubyte m_hash_id;
}

private:

Secure_Vector!ubyte emsa2_encoding(in Secure_Vector!ubyte msg,
                                size_t output_bits,
                                in Secure_Vector!ubyte empty_hash,
                                ubyte hash_id)
{
	const size_t HASH_SIZE = empty_hash.length;
	
	size_t output_length = (output_bits + 1) / 8;
	
	if (msg.length != HASH_SIZE)
		throw new Encoding_Error("encoding_of: Bad input length");
	if (output_length < HASH_SIZE + 4)
		throw new Encoding_Error("encoding_of: Output length is too small");
	
	const bool empty_input = (msg == empty_hash);
	
	Secure_Vector!ubyte output = Secure_Vector!ubyte(output_length);
	
	output[0] = (empty_input ? 0x4B : 0x6B);
	output[output_length - 3 - HASH_SIZE] = 0xBA;
	set_mem(&output[1], output_length - 4 - HASH_SIZE, 0xBB);
	buffer_insert(output, output_length - (HASH_SIZE + 2), &msg[0], msg.length);
	output[output_length-2] = hash_id;
	output[output_length-1] = 0xCC;
	
	return output;
}
