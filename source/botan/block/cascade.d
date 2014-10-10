/*
* Block Cipher Cascade
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.cascade;

import botan.block.block_cipher;

/**
* Block Cipher Cascade
*/
class Cascade_Cipher : BlockCipher
{
public:
	void encrypt_n(ubyte* input, ubyte* output, size_t blocks,
	               size_t blocks) const
	{
		size_t c1_blocks = blocks * (block_size() / m_cipher1.block_size());
		size_t c2_blocks = blocks * (block_size() / m_cipher2.block_size());
		
		m_cipher1.encrypt_n(input, output, c1_blocks);
		m_cipher2.encrypt_n(output, output, c2_blocks);
	}

	void decrypt_n(ubyte* input, ubyte* output, size_t blocks,
	               size_t blocks) const
	{
		size_t c1_blocks = blocks * (block_size() / m_cipher1.block_size());
		size_t c2_blocks = blocks * (block_size() / m_cipher2.block_size());
		
		m_cipher2.decrypt_n(input, output, c2_blocks);
		m_cipher1.decrypt_n(output, output, c1_blocks);
	}

	size_t block_size() const { return m_block; }

	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(m_cipher1.maximum_keylength() +
												  m_cipher2.maximum_keylength());
	}

	void clear()
	{
		m_cipher1.clear();
		m_cipher2.clear();
	}


	string name() const
	{
		return "Cascade(" ~ m_cipher1.name() ~ "," ~ m_cipher2.name() ~ ")";
	}

	BlockCipher clone() const
	{
		return new Cascade_Cipher(m_cipher1.clone(),
		                          m_cipher2.clone());
	}

	/**
	* Create a cascade of two block ciphers
	* @param cipher1 the first cipher
	* @param cipher2 the second cipher
	*/
	this(BlockCipher c1, BlockCipher c2) 
	{
		m_cipher1 = c1; m_cipher2 = c2;
		m_block = block_size_for_cascade(c1.block_size(), c2.block_size());
		
		if (block_size() % c1.block_size() || block_size() % c2.block_size())
			throw new Internal_Error("Failure in " ~ name() ~ " constructor");
	}
private:
	void key_schedule(in ubyte* key, size_t)
	{
		const ubyte* key2 = key + m_cipher1.maximum_keylength();
		
		m_cipher1.set_key(key , m_cipher1.maximum_keylength());
		m_cipher2.set_key(key2, m_cipher2.maximum_keylength());
	}

	size_t m_block;
	Unique!BlockCipher m_cipher1, m_cipher2;
};

package {
	
	size_t euclids_algorithm(size_t a, size_t b)
	{
		while(b != 0) // gcd
		{
			size_t t = b;
			b = a % b;
			a = t;
		}
		
		return a;
	}
	
	size_t block_size_for_cascade(size_t bs, size_t bs2)
	{
		if (bs == bs2)
			return bs;
		
		size_t gcd = euclids_algorithm(bs, bs2);
		
		return (bs * bs2) / gcd;
	}
	
}
