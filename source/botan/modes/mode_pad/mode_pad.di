/*
* ECB/CBC Padding Methods
* (C) 1999-2008,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.alloc.secmem;
import string;
/**
* Block Cipher Mode Padding Method
* This class is pretty limited, it cannot deal well with
* randomized padding methods, or any padding method that
* wants to add more than one block. For instance, it should
* be possible to define cipher text stealing mode as simply
* a padding mode for CBC, which happens to consume the last
* two block (and requires use of the block cipher).
*/
class BlockCipherModePaddingMethod
{
	public:
		abstract void add_padding(SafeVector!byte buffer,
										 size_t final_block_bytes,
										 size_t block_size) const;

		/**
		* @param block the last block
		* @param size the of the block
		*/
		abstract size_t unpad(in byte* block,
									size_t size) const;

		/**
		* @param block_size of the cipher
		* @return valid block size for this padding mode
		*/
		abstract bool valid_blocksize(size_t block_size) const;

		/**
		* @return name of the mode
		*/
		abstract string name() const;

		/**
		* abstract destructor
		*/
		~this() {}
};

/**
* PKCS#7 Padding
*/
class PKCS7_Padding : public BlockCipherModePaddingMethod
{
	public:
		void add_padding(SafeVector!byte buffer,
							  size_t final_block_bytes,
							  size_t block_size) const override;

		size_t unpad(const byte[], size_t) const;

		bool valid_blocksize(size_t bs) const { return (bs > 0 && bs < 256); }

		string name() const { return "PKCS7"; }
};

/**
* ANSI X9.23 Padding
*/
class ANSI_X923_Padding : public BlockCipherModePaddingMethod
{
	public:
		void add_padding(SafeVector!byte buffer,
							  size_t final_block_bytes,
							  size_t block_size) const override;

		size_t unpad(const byte[], size_t) const;

		bool valid_blocksize(size_t bs) const { return (bs > 0 && bs < 256); }

		string name() const { return "X9.23"; }
};

/**
* One And Zeros Padding
*/
class OneAndZeros_Padding : public BlockCipherModePaddingMethod
{
	public:
		void add_padding(SafeVector!byte buffer,
							  size_t final_block_bytes,
							  size_t block_size) const override;

		size_t unpad(const byte[], size_t) const;

		bool valid_blocksize(size_t bs) const { return (bs > 0); }

		string name() const { return "OneAndZeros"; }
};

/**
* Null Padding
*/
class Null_Padding : public BlockCipherModePaddingMethod
{
	public:
		void add_padding(SafeVector!byte, size_t, size_t) const override {}

		size_t unpad(const byte[], size_t size) const { return size; }

		bool valid_blocksize(size_t) const { return true; }

		string name() const { return "NoPadding"; }
};