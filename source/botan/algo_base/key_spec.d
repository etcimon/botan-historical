/*
* Symmetric Key Length Specification
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.algo_base.key_spec;

import botan.utils.types;
/**
* Represents the length requirements on an algorithm key
*/
struct Key_Length_Specification
{
public:
	/**
	* Constructor for fixed length keys
	* @param keylen the supported key length
	*/
	this(size_t keylen)
	{
		m_min_keylen = keylen;
		m_max_keylen = keylen;
		m_keylen_mod = 1;
	}

	/**
	* Constructor for variable length keys
	* @param min_k the smallest supported key length
	* @param max_k the largest supported key length
	* @param k_mod the number of bytes the key must be a multiple of
	*/
	this(size_t min_k,
		 size_t max_k,
		 size_t k_mod = 1)
	{
		m_min_keylen = min_k;
		m_max_keylen = max_k ? max_k : min_k;
		m_keylen_mod = k_mod;
	}

	/**
	* @param length is a key length in bytes
	* @return true iff this length is a valid length for this algo
	*/
	bool valid_keylength(size_t length) const
	{
		return ((length >= m_min_keylen) &&
				  (length <= m_max_keylen) &&
				  (length % m_keylen_mod == 0));
	}

	/**
	* @return minimum key length in bytes
	*/
	size_t minimum_keylength() const
	{
		return m_min_keylen;
	}

	/**
	* @return maximum key length in bytes
	*/
	size_t maximum_keylength() const
	{
		return m_max_keylen;
	}

	/**
	* @return key length multiple in bytes
	*/
	size_t keylength_multiple() const
	{
		return m_keylen_mod;
	}

	Key_Length_Specification multiple(size_t n) const
	{
		return Key_Length_Specification(n * m_min_keylen,
												  n * m_max_keylen,
												  n * m_keylen_mod);
	}

private:

	size_t m_min_keylen, m_max_keylen, m_keylen_mod;
}