/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.hmac;
import botan.mac.mac;
import botan.hash.hash;
import std.algorithm : fill;
import botan.utils.xor_buf;
/**
* HMAC
*/
final class HMAC : MessageAuthenticationCode
{
public:
	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		m_hash.clear();
		zap(m_ikey);
		zap(m_okey);
	}

	/*
	* Return the name of this type
	*/
	@property string name() const
	{
		return "HMAC(" ~ m_hash.name ~ ")";
	}

	/*
	* Return a clone of this object
	*/
	MessageAuthenticationCode clone() const
	{
		return new HMAC(m_hash.clone());
	}

	@property size_t output_length() const { return m_hash.output_length; }

	Key_Length_Specification key_spec() const
	{
		// Absurd max length here is to support PBKDF2
		return Key_Length_Specification(0, 512);
	}

	/**
	* @param hash the hash to use for HMACing
	*/
	this(HashFunction hash) 
	{
		m_hash = hash;
		if (m_hash.hash_block_size == 0)
			throw new Invalid_Argument("HMAC cannot be used with " ~ m_hash.name);
	}
private:
	/*
	* Update a HMAC Calculation
	*/
	void add_data(in ubyte* input, size_t length)
	{
		m_hash.update(input, length);
	}

	/*
	* Finalize a HMAC Calculation
	*/
	void final_result(ubyte* mac)
	{
		m_hash.flushInto(mac);
		m_hash.update(m_okey);
		m_hash.update(mac, output_length());
		m_hash.flushInto(mac);
		m_hash.update(m_ikey);
	}

	/*
	* HMAC Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		m_hash.clear();
		
		m_ikey.resize(m_hash.hash_block_size);
		m_okey.resize(m_hash.hash_block_size);
		
		std.algorithm.fill(m_ikey.begin(), m_ikey.end(), 0x36);
		std.algorithm.fill(m_okey.begin(), m_okey.end(), 0x5C);
		
		if (length > m_hash.hash_block_size)
		{
			SafeVector!ubyte hmac_key = m_hash.process(key, length);
			xor_buf(m_ikey, hmac_key, hmac_key.length);
			xor_buf(m_okey, hmac_key, hmac_key.length);
		}
		else
		{
			xor_buf(m_ikey, key, length);
			xor_buf(m_okey, key, length);
		}
		
		m_hash.update(m_ikey);
	}

	Unique!HashFunction m_hash;
	SafeVector!ubyte m_ikey, m_okey;
};