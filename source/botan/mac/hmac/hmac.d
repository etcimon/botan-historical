/*
* HMAC
* (C) 1999-2007,2014 Jack Lloyd
*	  2007 Yves Jerschow
*
* Distributed under the terms of the Botan license
*/

import botan.hmac;
import botan.internal.xor_buf;
/*
* Update a HMAC Calculation
*/
void HMAC::add_data(in ubyte* input, size_t length)
{
	m_hash.update(input, length);
}

/*
* Finalize a HMAC Calculation
*/
void HMAC::final_result(ubyte mac[])
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
void HMAC::key_schedule(in ubyte* key, size_t length)
{
	m_hash.clear();

	m_ikey.resize(m_hash.hash_block_size());
	m_okey.resize(m_hash.hash_block_size());

	std::fill(m_ikey.begin(), m_ikey.end(), 0x36);
	std::fill(m_okey.begin(), m_okey.end(), 0x5C);

	if (length > m_hash.hash_block_size())
	{
		SafeVector!ubyte hmac_key = m_hash.process(key, length);
		xor_buf(m_ikey, hmac_key, hmac_key.size());
		xor_buf(m_okey, hmac_key, hmac_key.size());
	}
	else
	{
		xor_buf(m_ikey, key, length);
		xor_buf(m_okey, key, length);
	}

	m_hash.update(m_ikey);
}

/*
* Clear memory of sensitive data
*/
void HMAC::clear()
{
	m_hash.clear();
	zap(m_ikey);
	zap(m_okey);
}

/*
* Return the name of this type
*/
string HMAC::name() const
{
	return "HMAC(" ~ m_hash.name() ~ ")";
}

/*
* Return a clone of this object
*/
MessageAuthenticationCode HMAC::clone() const
{
	return new HMAC(m_hash.clone());
}

/*
* HMAC Constructor
*/
HMAC::HMAC(HashFunction hash) : m_hash(hash)
{
	if (m_hash.hash_block_size() == 0)
		throw new Invalid_Argument("HMAC cannot be used with " ~ m_hash.name());
}

}
