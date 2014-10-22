/*
* SSL3-MAC
* (C) 1999-2004 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.ssl3_mac;
import botan.hash.hash;
import botan.mac.mac;
/**
* A MAC only used in SSLv3. Do not use elsewhere! Use HMAC instead.
*/
final class SSL3_MAC : MessageAuthenticationCode
{
public:
	/*
	* Return the name of this type
	*/
	@property string name() const
	{
		return "SSL3-MAC(" ~ m_hash.name ~ ")";
	}

	@property size_t output_length() const { return m_hash.output_length; }

	/*
	* Return a clone of this object
	*/
	MessageAuthenticationCode clone() const
	{
		return new SSL3_MAC(m_hash.clone());
	}


	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		m_hash.clear();
		zap(m_ikey);
		zap(m_okey);
	}

	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(m_hash.output_length);
	}

	/**
	* @param hash the underlying hash to use
	*/
	this(HashFunction hash)
	{
		m_hash = hash;
		if (m_hash.hash_block_size == 0)
			throw new Invalid_Argument("SSL3-MAC cannot be used with " ~ m_hash.name);
	}
private:
	/*
	* Update a SSL3-MAC Calculation
	*/
	void add_data(in ubyte* input, size_t length)
	{
		m_hash.update(input, length);
	}

	/*
	* Finalize a SSL3-MAC Calculation
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
	* SSL3-MAC Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		m_hash.clear();
		
		// Quirk to deal with specification bug
		const size_t inner_hash_length =
			(m_hash.name == "SHA-160") ? 60 : m_hash.hash_block_size;
		
		m_ikey.resize(inner_hash_length);
		m_okey.resize(inner_hash_length);
		
		std.algorithm.fill(m_ikey.begin(), m_ikey.end(), 0x36);
		std.algorithm.fill(m_okey.begin(), m_okey.end(), 0x5C);
		
		copy_mem(&m_ikey[0], key, length);
		copy_mem(&m_okey[0], key, length);
		
		m_hash.update(m_ikey);
	}

	Unique!HashFunction m_hash;
	SafeVector!ubyte m_ikey, m_okey;
};