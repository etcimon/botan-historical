/*
* Block Cipher Base Class
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/sym_algo.h>
/**
* This class represents a block cipher object.
*/
class BlockCipher : public SymmetricAlgorithm
{
	public:

		/**
		* @return block size of this algorithm
		*/
		abstract size_t block_size() const = 0;

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
		* @param in The plaintext block to be encrypted as a byte array.
		* Must be of length block_size().
		* @param out The byte array designated to hold the encrypted block.
		* Must be of length block_size().
		*/
		void encrypt(in byte[] input, ref byte[] output) const
		{ encrypt_n(input, out, 1); }

		/**
		* Decrypt a block.
		* @param in The ciphertext block to be decypted as a byte array.
		* Must be of length block_size().
		* @param out The byte array designated to hold the decrypted block.
		* Must be of length block_size().
		*/
		void decrypt(in byte[] input, ref byte[] output) const
		{ decrypt_n(input, out, 1); }

		/**
		* Encrypt a block.
		* @param block the plaintext block to be encrypted
		* Must be of length block_size(). Will hold the result when the function
		* has finished.
		*/
		void encrypt(byte block[]) const { encrypt_n(block, block, 1); }

		/**
		* Decrypt a block.
		* @param block the ciphertext block to be decrypted
		* Must be of length block_size(). Will hold the result when the function
		* has finished.
		*/
		void decrypt(byte block[]) const { decrypt_n(block, block, 1); }

		/**
		* Encrypt one or more blocks
		* @param block the input/output buffer (multiple of block_size())
		*/
		template<typename Alloc>
		void encrypt(std::vector<byte, Alloc>& block) const
		{
			return encrypt_n(&block[0], &block[0], block.size() / block_size());
		}

		/**
		* Decrypt one or more blocks
		* @param block the input/output buffer (multiple of block_size())
		*/
		template<typename Alloc>
		void decrypt(std::vector<byte, Alloc>& block) const
		{
			return decrypt_n(&block[0], &block[0], block.size() / block_size());
		}

		/**
		* Encrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		*/
		template<typename Alloc, typename Alloc2>
		void encrypt(const std::vector<byte, Alloc>& in,
						 std::vector<byte, Alloc2>& out) const
		{
			return encrypt_n(&in[0], &out[0], in.size() / block_size());
		}

		/**
		* Decrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		*/
		template<typename Alloc, typename Alloc2>
		void decrypt(const std::vector<byte, Alloc>& in,
						 std::vector<byte, Alloc2>& out) const
		{
			return decrypt_n(&in[0], &out[0], in.size() / block_size());
		}

		/**
		* Encrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		* @param blocks the number of blocks to process
		*/
		abstract void encrypt_n(in byte[] input, ref byte[] output,
									  size_t blocks) const = 0;

		/**
		* Decrypt one or more blocks
		* @param in the input buffer (multiple of block_size())
		* @param out the output buffer (same size as input)
		* @param blocks the number of blocks to process
		*/
		abstract void decrypt_n(in byte[] input, ref byte[] output,
									  size_t blocks) const = 0;

		/**
		* @return new object representing the same algorithm as *this
		*/
		abstract BlockCipher* clone() const = 0;
};

/**
* Represents a block cipher with a single fixed block size
*/
template<size_t BS, size_t KMIN, size_t KMAX = 0, size_t KMOD = 1>
class Block_Cipher_Fixed_Params : public BlockCipher
{
	public:
		enum { BLOCK_SIZE = BS };
		size_t block_size() const { return BS; }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(KMIN, KMAX, KMOD);
		}
};