/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.lion;

import botan.constants;
static if (BOTAN_HAS_LION):

import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.utils.xor_buf;
import botan.utils.parsing;

/**
* Lion is a block cipher construction designed by Ross Anderson and
* Eli Biham, described in "Two Practical and Provably Secure Block
* Ciphers: BEAR and LION". It has a variable block size and is
* designed to encrypt very large blocks (up to a megabyte)

* http://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
*/
final class Lion : BlockCipher
{
public:
	/*
	* Lion Encryption
	*/
	override void encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const size_t LEFT_SIZE = left_size();
		const size_t RIGHT_SIZE = right_size();
		
		Secure_Vector!ubyte buffer_vec = Secure_Vector!ubyte(LEFT_SIZE);
		ubyte* buffer = &buffer_vec[0];
		
		for (size_t i = 0; i != blocks; ++i)
		{
			xor_buf(buffer, input, &m_key1[0], LEFT_SIZE);
			m_cipher.set_key(buffer, LEFT_SIZE);
			m_cipher.cipher(input + LEFT_SIZE, output + LEFT_SIZE, RIGHT_SIZE);
			
			m_hash.update(output + LEFT_SIZE, RIGHT_SIZE);
			m_hash.flushInto(buffer);
			xor_buf(output, input, buffer, LEFT_SIZE);
			
			xor_buf(buffer, output, &m_key2[0], LEFT_SIZE);
			m_cipher.set_key(buffer, LEFT_SIZE);
			m_cipher.cipher1(output + LEFT_SIZE, RIGHT_SIZE);
			
			input += m_block_size;
			output += m_block_size;
		}
	}

	/*
	* Lion Decryption
	*/
	override void decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
	{
		const size_t LEFT_SIZE = left_size();
		const size_t RIGHT_SIZE = right_size();
		
		Secure_Vector!ubyte buffer_vec = Secure_Vector!ubyte(LEFT_SIZE);
		ubyte* buffer = &buffer_vec[0];
		
		for (size_t i = 0; i != blocks; ++i)
		{
			xor_buf(buffer, input, &m_key2[0], LEFT_SIZE);
			m_cipher.set_key(buffer, LEFT_SIZE);
			m_cipher.cipher(input + LEFT_SIZE, output + LEFT_SIZE, RIGHT_SIZE);
			
			m_hash.update(output + LEFT_SIZE, RIGHT_SIZE);
			m_hash.flushInto(buffer);
			xor_buf(output, input, buffer, LEFT_SIZE);
			
			xor_buf(buffer, output, &m_key1[0], LEFT_SIZE);
			m_cipher.set_key(buffer, LEFT_SIZE);
			m_cipher.cipher1(output + LEFT_SIZE, RIGHT_SIZE);
			
			input += m_block_size;
			output += m_block_size;
		}
	}

	@property size_t block_size() const { return m_block_size; }

	override Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(2, 2*m_hash.output_length, 2);
	}

	/*
	* Clear memory of sensitive data
	*/
	override void clear()
	{
		zeroise(m_key1);
		zeroise(m_key2);
		m_hash.clear();
		m_cipher.clear();
	}

	/*
	* Return the name of this type
	*/
	override @property string name() const
	{
		return "Lion(" ~ m_hash.name ~ "," ~
			m_cipher.name ~ "," ~
				std.conv.to!string(block_size()) ~ ")";
	}

	/*
	* Return a clone of this object
	*/
	override BlockCipher clone() const
	{
		return new Lion(m_hash.clone(), m_cipher.clone(), block_size());
	}


	/**
	* @param hash the hash to use internally
	* @param cipher the stream cipher to use internally
	* @param block_size the size of the block to use
	*/
	this(HashFunction hash, StreamCipher cipher, size_t block_size) 
	{
		m_block_size = std.algorithm.max(2*hash.output_length + 1, block_size);
		m_hash = hash;
		m_cipher = cipher;
		
		if (2*left_size() + 1 > m_block_size)
			throw new Invalid_Argument(name ~ ": Chosen block size is too small");
		
		if (!m_cipher.valid_keylength(left_size()))
			throw new Invalid_Argument(name ~ ": This stream/hash combo is invalid");
		
		m_key1.resize(left_size());
		m_key2.resize(left_size());
	}
private:

	/*
	* Lion Key Schedule
	*/
	void key_schedule(in ubyte* key)
	{
		clear();
		
		const size_t half = key.length / 2;
		copy_mem(&m_key1[0], key, half);
		copy_mem(&m_key2[0], key + half, half);
	}

	size_t left_size() const { return m_hash.output_length; }
	size_t right_size() const { return m_block_size - left_size(); }

	const size_t m_block_size;
	Unique!HashFunction m_hash;
	Unique!StreamCipher m_cipher;
	Secure_Vector!ubyte m_key1, m_key2;
};
