/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cbc;
import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.loadstor;
import botan.internal.xor_buf;
import botan.utils.rounding;

/**
* CBC Mode
*/
class CBC_Mode : Cipher_Mode
{
public:
	override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		/*
		* A nonce of zero length means carry the last ciphertext value over
		* as the new IV, as unfortunately some protocols require this. If
		* this is the first message then we use an IV of all zeros.
		*/
		if (nonce_len)
			m_state.assign(nonce, nonce + nonce_len);
		
		return SafeVector!ubyte();
	}

	override string name() const
	{
		if (m_padding)
			return cipher().name() ~ "/CBC/" ~ padding().name();
		else
			return cipher().name() ~ "/CBC/CTS";
	}

	override size_t update_granularity() const
	{
		return cipher().parallel_bytes();
	}

	override Key_Length_Specification key_spec() const
	{
		return cipher().key_spec();
	}

	override size_t default_nonce_length() const
	{
		return cipher().block_size();
	}

	override bool valid_nonce_length(size_t n) const
	{
		return (n == 0 || n == cipher().block_size());
	}

	override void clear()
	{
		m_cipher.clear();
		m_state.clear();
	}
package:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
	{
		m_cipher = cipher;
		m_padding = padding;
		m_state = m_cipher.block_size();
		if (m_padding && !m_padding.valid_blocksize(cipher.block_size()))
			throw new Invalid_Argument("Padding " ~ m_padding.name() +
			                           " cannot be used with " ~
			                           cipher.name() ~ "/CBC");
	}

	const BlockCipher cipher() const { return *m_cipher; }

	const BlockCipherModePaddingMethod padding() const
	{
		BOTAN_ASSERT_NONNULL(m_padding);
		return *m_padding;
	}

	SafeVector!ubyte state() { return m_state; }

	ubyte* state_ptr() { return &m_state[0]; }

private:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
	}

	Unique!BlockCipher m_cipher;
	Unique!BlockCipherModePaddingMethod m_padding;
	SafeVector!ubyte m_state;
};

/**
* CBC Encryption
*/
class CBC_Encryption : CBC_Mode
{
public:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
	{
		super(cipher, padding);
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		const size_t sz = buffer.size() - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size();
		
		BOTAN_ASSERT(sz % BS == 0, "CBC input is full blocks");
		const size_t blocks = sz / BS;
		
		const ubyte* prev_block = state_ptr();
		
		if (blocks)
		{
			for (size_t i = 0; i != blocks; ++i)
			{
				xor_buf(&buf[BS*i], prev_block, BS);
				cipher().encrypt(&buf[BS*i]);
				prev_block = &buf[BS*i];
			}
			
			state().assign(&buf[BS*(blocks-1)], &buf[BS*blocks]);
		}
	}


	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		
		const size_t BS = cipher().block_size();
		
		const size_t bytes_in_final_block = (buffer.size()-offset) % BS;
		
		padding().add_padding(buffer, bytes_in_final_block, BS);
		
		if ((buffer.size()-offset) % BS)
			throw new Exception("Did not pad to full block size in " ~ name());
		
		update(buffer, offset);
	}

	override size_t output_length(size_t input_length) const
	{
		return round_up(input_length, cipher().block_size());
	}

	override size_t minimum_final_size() const
	{
		return 0;
	}
};

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Encryption : CBC_Encryption
{
public:
	this(BlockCipher cipher)
	{
		super(cipher, null);
	}

	override size_t output_length(size_t input_length) const
	{
		return input_length; // no ciphertext expansion in CTS
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		ubyte* buf = &buffer[offset];
		const size_t sz = buffer.size() - offset;
		
		const size_t BS = cipher().block_size();
		
		if (sz < BS + 1)
			throw new Encoding_Error(name() ~ ": insufficient data to encrypt");
		
		if (sz % BS == 0)
		{
			update(buffer, offset);
			
			// swap last two blocks
			for (size_t i = 0; i != BS; ++i)
				std.algorithm.swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);
		}
		else
		{
			const size_t full_blocks = ((sz / BS) - 1) * BS;
			const size_t final_bytes = sz - full_blocks;
			BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
			
			SafeVector!ubyte last = SafeVector!ubyte(buf + full_blocks, buf + full_blocks + final_bytes);
			buffer.resize(full_blocks + offset);
			update(buffer, offset);
			
			xor_buf(&last[0], state_ptr(), BS);
			cipher().encrypt(&last[0]);
			
			for (size_t i = 0; i != final_bytes - BS; ++i)
			{
				last[i] ^= last[i + BS];
				last[i + BS] ^= last[i];
			}
			
			cipher().encrypt(&last[0]);
			
			buffer += last;
		}
	}

	override size_t minimum_final_size() const
	{
		return cipher().block_size() + 1;
	}

	bool valid_nonce_length(size_t n) const
	{
		return (n == cipher().block_size());
	}

};

/**
* CBC Decryption
*/
class CBC_Decryption : CBC_Mode
{
public:
	this(BlockCipher cipher, BlockCipherModePaddingMethod padding)  
	{
		super(cipher, padding);
		m_tempbuf = update_granularity();
	}

	override void update(SafeVector!ubyte buffer, size_t offset)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		const size_t sz = buffer.size() - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size();
		
		BOTAN_ASSERT(sz % BS == 0, "Input is full blocks");
		size_t blocks = sz / BS;
		
		while(blocks)
		{
			const size_t to_proc = std.algorithm.min(BS * blocks, m_tempbuf.size());
			
			cipher().decrypt_n(buf, &m_tempbuf[0], to_proc / BS);
			
			xor_buf(&m_tempbuf[0], state_ptr(), BS);
			xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
			copy_mem(state_ptr(), buf + (to_proc - BS), BS);
			
			copy_mem(buf, &m_tempbuf[0], to_proc);
			
			buf += to_proc;
			blocks -= to_proc / BS;
		}
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		const size_t sz = buffer.size() - offset;
		
		const size_t BS = cipher().block_size();
		
		if (sz == 0 || sz % BS)
			throw new Decoding_Error(name() ~ ": Ciphertext not a multiple of block size");
		
		update(buffer, offset);
		
		const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.size()-BS], BS);
		buffer.resize(buffer.size() - pad_bytes); // remove padding
	}

	override size_t output_length(size_t input_length) const
	{
		return input_length; // precise for CTS, worst case otherwise
	}

	override size_t minimum_final_size() const
	{
		return cipher().block_size();
	}	 
private:
	SafeVector!ubyte m_tempbuf;
};

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
class CTS_Decryption : CBC_Decryption
{
public:
	this(BlockCipher cipher)
	{
		super(cipher, null)
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.size() >= offset, "Offset is sane");
		const size_t sz = buffer.size() - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size();
		
		if (sz < BS + 1)
			throw new Encoding_Error(name() ~ ": insufficient data to decrypt");
		
		if (sz % BS == 0)
		{
			// swap last two blocks
			
			for (size_t i = 0; i != BS; ++i)
				std.algorithm.swap(buffer[buffer.size()-BS+i], buffer[buffer.size()-2*BS+i]);
			
			update(buffer, offset);
		}
		else
		{
			const size_t full_blocks = ((sz / BS) - 1) * BS;
			const size_t final_bytes = sz - full_blocks;
			BOTAN_ASSERT(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
			
			SafeVector!ubyte last = SafeVector!ubyte(buf + full_blocks, buf + full_blocks + final_bytes);
			buffer.resize(full_blocks + offset);
			update(buffer, offset);
			
			cipher().decrypt(&last[0]);
			
			xor_buf(&last[0], &last[BS], final_bytes - BS);
			
			for (size_t i = 0; i != final_bytes - BS; ++i)
				std.algorithm.swap(last[i], last[i + BS]);
			
			cipher().decrypt(&last[0]);
			xor_buf(&last[0], state_ptr(), BS);
			
			buffer += last;
		}
	}


	override size_t minimum_final_size() const
	{
		return cipher().block_size() + 1;
	}

	bool valid_nonce_length(size_t n) const
	{
		return (n == cipher().block_size());
	}
};