/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.lion;
import botan.internal.xor_buf;
import botan.parsing;
/*
* Lion Encryption
*/
void Lion::encrypt_n(ubyte* input, ubyte* output, size_t blocks) const
{
	const size_t LEFT_SIZE = left_size();
	const size_t RIGHT_SIZE = right_size();

	SafeVector!ubyte buffer_vec(LEFT_SIZE);
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
void Lion::decrypt_n(ubyte* input, ubyte* output, size_t blocks) const
{
	const size_t LEFT_SIZE = left_size();
	const size_t RIGHT_SIZE = right_size();

	SafeVector!ubyte buffer_vec(LEFT_SIZE);
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

/*
* Lion Key Schedule
*/
void Lion::key_schedule(in ubyte* key)
{
	clear();

	const size_t half = key.length / 2;
	copy_mem(&m_key1[0], key, half);
	copy_mem(&m_key2[0], key + half, half);
}

/*
* Return the name of this type
*/
string Lion::name() const
{
	return "Lion(" ~ m_hash.name() ~ "," ~
						  m_cipher.name() ~ "," ~
						  std.conv.to!string(block_size()) ~ ")";
}

/*
* Return a clone of this object
*/
BlockCipher Lion::clone() const
{
	return new Lion(m_hash.clone(), m_cipher.clone(), block_size());
}

/*
* Clear memory of sensitive data
*/
void Lion::clear()
{
	zeroise(m_key1);
	zeroise(m_key2);
	m_hash.clear();
	m_cipher.clear();
}

/*
* Lion Constructor
*/
Lion::Lion(HashFunction hash, StreamCipher cipher, size_t block_size) :
	m_block_size(std.algorithm.max<size_t>(2*hash.output_length() + 1, block_size)),
	m_hash(hash),
	m_cipher(cipher)
{
	if (2*left_size() + 1 > m_block_size)
		throw new Invalid_Argument(name() ~ ": Chosen block size is too small");

	if (!m_cipher.valid_keylength(left_size()))
		throw new Invalid_Argument(name() ~ ": This stream/hash combo is invalid");

	m_key1.resize(left_size());
	m_key2.resize(left_size());
}

}
