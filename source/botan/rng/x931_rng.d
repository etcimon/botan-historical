/*
* ANSI X9.31 RNG
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.rng.x931_rng;

import botan.rng.rng;
import botan.block.block_cipher;
import botan.utils.xor_buf;
import botan.utils.types;
import std.algorithm;

/**
* ANSI X9.31 RNG
*/
final class ANSI_X931_RNG : RandomNumberGenerator
{
public:
	void randomize(ubyte* output, size_t length)
	{
		if (!is_seeded())
		{
			reseed(BOTAN_RNG_RESEED_POLL_BITS);
			
			if (!is_seeded())
				throw new PRNG_Unseeded(name);
		}
		
		while(length)
		{
			if (m_R_pos == m_R.length)
				update_buffer();
			
			const size_t copied = std.algorithm.min(length, m_R.length - m_R_pos);
			
			copy_mem(output, &m_R[m_R_pos], copied);
			output += copied;
			length -= copied;
			m_R_pos += copied;
		}
	}

	bool is_seeded() const
	{
		return (m_V.length > 0);
	}

	void clear()
	{
		m_cipher.clear();
		m_prng.clear();
		zeroise(m_R);
		m_V.clear();
		
		m_R_pos = 0;
	}

	@property string name() const
	{
		return "X9.31(" ~ m_cipher.name ~ ")";
	}

	void reseed(size_t poll_bits)
	{
		m_prng.reseed(poll_bits);
		rekey();
	}

	void add_entropy(in ubyte* input, size_t length)
	{
		m_prng.add_entropy(input, length);
		rekey();
	}

	/**
	* @param cipher the block cipher to use in this PRNG
	* @param rng the underlying PRNG for generating inputs
	* (eg, an HMAC_RNG)
	*/
	this(BlockCipher cipher,
	     RandomNumberGenerator prng)
	{
		m_cipher = cipher;
		m_prng = prng;
		m_R = m_cipher.block_size;
		m_R_pos = 0;
	}

private:
	/*
	* Reset V and the cipher key with new values
	*/
	void rekey()
	{
		const size_t BLOCK_SIZE = m_cipher.block_size;
		
		if (m_prng.is_seeded())
		{
			m_cipher.set_key(m_prng.random_vec(m_cipher.maximum_keylength()));
			
			if (m_V.length != BLOCK_SIZE)
				m_V.resize(BLOCK_SIZE);
			m_prng.randomize(&m_V[0], m_V.length);
			
			update_buffer();
		}
	}

	/*
	* Refill the internal state
	*/
	void update_buffer()
	{
		const size_t BLOCK_SIZE = m_cipher.block_size;
		
		Secure_Vector!ubyte DT = m_prng.random_vec(BLOCK_SIZE);
		m_cipher.encrypt(DT);
		
		xor_buf(&m_R[0], &m_V[0], &DT[0], BLOCK_SIZE);
		m_cipher.encrypt(m_R);
		
		xor_buf(&m_V[0], &m_R[0], &DT[0], BLOCK_SIZE);
		m_cipher.encrypt(m_V);
		
		m_R_pos = 0;
	}


	Unique!BlockCipher m_cipher;
	Unique!RandomNumberGenerator m_prng;
	Secure_Vector!ubyte m_V, m_R;
	size_t m_R_pos;
};