/*
* ECB/CBC Padding Methods
* (C) 1999-2008,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.mode_pad;

import botan.utils.memory.zeroize;
import botan.utils.exceptn;
// import string;

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
	abstract void add_padding(Secure_Vector!ubyte buffer, size_t final_block_bytes, size_t block_size) const;

	/**
	* @param block the last block
	* @param size the of the block
	*/
	abstract size_t unpad(in ubyte* block,
								size_t size) const;

	/**
	* @param block_size of the cipher
	* @return valid block size for this padding mode
	*/
	abstract bool valid_blocksize(size_t block_size) const;

	/**
	* @return name of the mode
	*/
	abstract @property string name() const;

	/**
	* abstract destructor
	*/
	~this() {}
}

/**
* PKCS#7 Padding
*/
final class PKCS7_Padding : BlockCipherModePaddingMethod
{
public:
	/*
	* Pad with PKCS #7 Method
	*/
	override void add_padding(Secure_Vector!ubyte buffer, size_t last_byte_pos, size_t block_size) const
	{
		const ubyte pad_value = block_size - last_byte_pos;
		
		foreach (size_t i; 0 .. pad_value)
			buffer.push_back(pad_value);
	}

	/*
	* Unpad with PKCS #7 Method
	*/
	size_t unpad(in ubyte* block, size_t size) const
	{
		size_t position = block[size-1];
		
		if (position > size)
			throw new Decoding_Error("Bad padding in " ~ name);
		
		foreach (size_t j; (size-position) .. (size-1))
			if (block[j] != position)
				throw new Decoding_Error("Bad padding in " ~ name);
		
		return (size-position);
	}

	bool valid_blocksize(size_t bs) const { return (bs > 0 && bs < 256); }

	@property string name() const { return "PKCS7"; }
}

/**
* ANSI X9.23 Padding
*/
final class ANSI_X923_Padding : BlockCipherModePaddingMethod
{
public:
	/*
	* Pad with ANSI X9.23 Method
	*/
	override void add_padding(Secure_Vector!ubyte buffer,
				                 size_t last_byte_pos,
				                 size_t block_size) const
	{
		const ubyte pad_value = block_size - last_byte_pos;
		
		for (size_t i = last_byte_pos; i < block_size; ++i)
			buffer.push_back(0);
		buffer.push_back(pad_value);
	}

	/*
	* Unpad with ANSI X9.23 Method
	*/
	size_t unpad(in ubyte* block, size_t size) const
	{
		size_t position = block[size-1];
		if (position > size)
			throw new Decoding_Error(name);
		foreach (size_t j; (size-position) .. (size-1))
			if (block[j] != 0)
				throw new Decoding_Error(name);
		return (size-position);
	}

	bool valid_blocksize(size_t bs) const { return (bs > 0 && bs < 256); }

	@property string name() const { return "X9.23"; }
}

/**
* One And Zeros Padding
*/
final class OneAndZeros_Padding : BlockCipherModePaddingMethod
{
public:
	/*
	* Pad with One and Zeros Method
	*/
	override void add_padding(Secure_Vector!ubyte buffer, size_t last_byte_pos, size_t block_size) const
	{
		buffer.push_back(0x80);
		
		for (size_t i = last_byte_pos + 1; i % block_size; ++i)
			buffer.push_back(0x00);
	}

	/*
	* Unpad with One and Zeros Method
	*/
	size_t unpad(in ubyte* block, size_t size) const
	{
		while (size)
		{
			if (block[size-1] == 0x80)
				break;
			if (block[size-1] != 0x00)
				throw new Decoding_Error(name);
			size--;
		}
		if (!size)
			throw new Decoding_Error(name);
		return (size-1);
	}

	bool valid_blocksize(size_t bs) const { return (bs > 0); }

	@property string name() const { return "OneAndZeros"; }
}

/**
* Null Padding
*/
final class Null_Padding : BlockCipherModePaddingMethod
{
public:
	override void add_padding(Secure_Vector!ubyte, size_t, size_t) const {}

	size_t unpad(in ubyte[], size_t size) const { return size; }

	bool valid_blocksize(size_t) const { return true; }

	@property string name() const { return "NoPadding"; }
}
