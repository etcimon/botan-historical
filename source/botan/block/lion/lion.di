/*
* Lion
* (C) 1999-2007,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/block_cipher.h>
#include <botan/stream_cipher.h>
#include <botan/hash.h>
/**
* Lion is a block cipher construction designed by Ross Anderson and
* Eli Biham, described in "Two Practical and Provably Secure Block
* Ciphers: BEAR and LION". It has a variable block size and is
* designed to encrypt very large blocks (up to a megabyte)

* http://www.cl.cam.ac.uk/~rja14/Papers/bear-lion.pdf
*/
class Lion : public BlockCipher
{
	public:
		void encrypt_n(in byte[] input, ref byte[] output) const override;
		void decrypt_n(in byte[] input, ref byte[] output) const override;

		size_t block_size() const override { return m_block_size; }

		Key_Length_Specification key_spec() const override
		{
			return Key_Length_Specification(2, 2*m_hash->output_length(), 2);
		}

		void clear() override;
		string name() const override;
		BlockCipher* clone() const override;

		/**
		* @param hash the hash to use internally
		* @param cipher the stream cipher to use internally
		* @param block_size the size of the block to use
		*/
		Lion(HashFunction* hash,
			  StreamCipher* cipher,
			  size_t block_size);
	private:
		void key_schedule(const byte[], size_t);

		size_t left_size() const { return m_hash->output_length(); }
		size_t right_size() const { return m_block_size - left_size(); }

		const size_t m_block_size;
		std::unique_ptr<HashFunction> m_hash;
		std::unique_ptr<StreamCipher> m_cipher;
		SafeVector!byte m_key1, m_key2;
};