/*
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.block.block_cipher;

import botan.algo_base.sym_algo;

/**
* This class represents a block cipher object.
*/
class BlockCipher : SymmetricAlgorithm
{
	public:

		/**
		* @return block size of this algorithm
		*/
		abstract size_t block_size() const;

		/**
		* @return native parallelism of this cipher in blocks
		*/
		abstract size_t parallelism() const { return 1; }

		/**
		* @return prefererred parallelism of this cipher in bytes
		*/
		size_t parallel_bytes() const
		{
			return parallelism() * block_size() * BOTAN_BLOCK_CIPHER_PAR_MULT;
		}

		/**
		* Encrypt a block.
		* @param in The plaintext block to be encrypted as a ubyte array.
		* Must be of length block_size().
		* @param output The ubyte array designated to hold the encrypted block.
		* Must be of length block_size().
		*/
		void encrypt(ubyte* input, ubyte* output) const
		{ encrypt_n(input, output, 1); }

		/**
		* Decrypt a block.
		* @param in The ciphertext block to be decypted as a ubyte array.
		* Must be of length block_size().
		* @param output The ubyte array designated to hold the decrypted block.
		* Must be of length block_size().
		*/
		void decrypt(ubyte* input, ubyte* output) const
		{ decrypt_n(input, output, 1); }

		/**
		* Encrypt a block.
		* @param block the plaintext block to be encrypted
		* Must be of length block_size(). Will hold the result when the function
		* has finished.
		*/
		void encrypt(ubyte* block) const { encrypt_n(block, block, 1); }

		/**
		* Decrypt a block.
		* @param block the ciphertext block to be decrypted
		* Must be of length block_size(). Will hold the result when the function
		* has finished.
		*/
		void decrypt(ubyte* block) const { decrypt_n(block, block, 1); }

		/**
		* Encrypt one or more blocks
		* @param block the input/output buffer (multiple of block_size())
		*/
		void encrypt(Alloc)(Vector!( ubyte, Alloc ) block) const
		{
			return encrypt_n(&block[0], &block[0], block.size() / block_size());
		}

		/**
		* Decrypt one or more blocks
		* @param block the input/output buffer (multiple of block_size())
		*/
		void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) block) const
		{
			return decrypt_n(&block[0], &block[0], block.size() / block_size());
		}

		/**
		* Encrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		*/
		void encrypt(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) input,
									Vector!( ubyte, Alloc2 ) output) const
		{
			return encrypt_n(&input[0], &output[0], input.size() / block_size());
		}

		/**
		* Decrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param output the output buffer (same size as input)
		*/
		void decrypt(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) input,
									Vector!( ubyte, Alloc2 ) output) const
		{
			return decrypt_n(&input[0], &output[0], input.size() / block_size());
		}

		/**
		* Encrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		* @param blocks the number of blocks to process
		*/
		abstract void encrypt_n(ubyte* input, ubyte* output,
								size_t blocks) const;

		/**
		* Decrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		* @param blocks the number of blocks to process
		*/
		abstract void decrypt_n(ubyte* input, ubyte* output,
								size_t blocks) const;

		/**
		* @return new object representing the same algorithm as *this
		*/
		abstract BlockCipher clone() const;
};

/**
* Represents a block cipher with a single fixed block size
*/
class Block_Cipher_Fixed_Params(size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1) : BlockCipher
{
	public:
		enum { BLOCK_SIZE = BS };
		size_t block_size() const { return BS; }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(KMIN, KMAX, KMOD);
		}
};