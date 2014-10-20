/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa_pkcs1;
import botan.emsa;
import botan.hash.hash;
import botan.pk_pad.emsa_pkcs1;
import botan.pk_pad.hash_id;

/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
class EMSA_PKCS1v15 : EMSA
{
public:
	/**
	* @param hash the hash object to use
	*/
	this(HashFunction hash)
	{
		m_hash = hash;
		m_hash_id = pkcs_hash_id(m_hash.name());
	}

	void update(in ubyte* input, size_t length)
	{
		m_hash.update(input, length);
	}

	SafeVector!ubyte raw_data()
	{
		return m_hash.flush();
	}

	SafeVector!ubyte
		encoding_of(in SafeVector!ubyte msg,
		            size_t output_bits,
		            RandomNumberGenerator)
	{
		if (msg.length != m_hash.output_length())
			throw new Encoding_Error("encoding_of: Bad input length");
		
		return emsa3_encoding(msg, output_bits,
		                      &m_hash_id[0], m_hash_id.length);
	}

	bool verify(in SafeVector!ubyte coded,
	            in SafeVector!ubyte raw,
	            size_t key_bits)
	{
		if (raw.length != m_hash.output_length())
			return false;
		
		try
		{
			return (coded == emsa3_encoding(raw, key_bits,
			                                &m_hash_id[0], m_hash_id.length));
		}
		catch
		{
			return false;
		}
	}
private:
	Unique!HashFunction m_hash;
	Vector!ubyte m_hash_id;
};

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
class EMSA_PKCS1v15_Raw : EMSA
{
public:
	void update(in ubyte* input, size_t length)
	{
		message += Pair(input, length);
	}

	SafeVector!ubyte raw_data()
	{
		SafeVector!ubyte ret;
		std.algorithm.swap(ret, message);
		return ret;
	}

	SafeVector!ubyte
		encoding_of(in SafeVector!ubyte msg,
		            size_t output_bits,
		            RandomNumberGenerator)
	{
		return emsa3_encoding(msg, output_bits, null, 0);
	}

	bool verify(in SafeVector!ubyte coded,
	            in SafeVector!ubyte raw,
	            size_t key_bits)
	{
		try
		{
			return (coded == emsa3_encoding(raw, key_bits, null, 0));
		}
		catch
		{
			return false;
		}
	}

private:
	SafeVector!ubyte message;
};

private:

SafeVector!ubyte emsa3_encoding(in SafeVector!ubyte msg,
                                size_t output_bits,
                                in ubyte* hash_id,
                                size_t hash_id_length)
{
	size_t output_length = output_bits / 8;
	if (output_length < hash_id_length + msg.length + 10)
		throw new Encoding_Error("emsa3_encoding: Output length is too small");
	
	SafeVector!ubyte T = SafeVector!ubyte(output_length);
	const size_t P_LENGTH = output_length - msg.length - hash_id_length - 2;
	
	T[0] = 0x01;
	set_mem(&T[1], P_LENGTH, 0xFF);
	T[P_LENGTH+1] = 0x00;
	buffer_insert(T, P_LENGTH+2, hash_id, hash_id_length);
	buffer_insert(T, output_length-msg.length, &msg[0], msg.length);
	return T;
}