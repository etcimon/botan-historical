/*
* XTS mode, from IEEE P1619
* (C) 2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.xts;

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.xts;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;
/**
* IEEE P1619 XTS Mode
*/
class XTS_Mode : Cipher_Mode
{
public:
	final override @property string name() const
	{
		return cipher().name ~ "/XTS";
	}

	final override Secure_Vector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name, nonce_len);
		
		copy_mem(&m_tweak[0], nonce, nonce_len);
		m_tweak_cipher.encrypt(&m_tweak[0]);
		
		update_tweak(0);
		
		return Secure_Vector!ubyte();
	}

	final override size_t update_granularity() const
	{
		return cipher().parallel_bytes();
	}

	final override size_t minimum_final_size() const
	{
		return cipher().block_size + 1;
	}

	final override Key_Length_Specification key_spec() const
	{
		return cipher().key_spec().multiple(2);
	}

	final override size_t default_nonce_length() const
	{
		return cipher().block_size;
	}

	final override bool valid_nonce_length(size_t n) const
	{
		return cipher().block_size == n;
	}

	final override void clear()
	{
		m_cipher.clear();
		m_tweak_cipher.clear();
		zeroise(m_tweak);
	}
protected:
	this(BlockCipher cipher) 
	{
		m_cipher = cipher;
		if (m_cipher.block_size != 8 && m_cipher.block_size != 16)
			throw new Invalid_Argument("Bad cipher for XTS: " ~ cipher.name);
		
		m_tweak_cipher = m_cipher.clone();
		m_tweak.resize(update_granularity());
	}

	final const ubyte* tweak() const { return &m_tweak[0]; }

	final const BlockCipher cipher() const { return *m_cipher; }

	final void update_tweak(size_t which)
	{
		const size_t BS = m_tweak_cipher.block_size;
		
		if (which > 0)
			poly_double(&m_tweak[0], &m_tweak[(which-1)*BS], BS);
		
		const size_t blocks_in_tweak = update_granularity() / BS;
		
		for (size_t i = 1; i < blocks_in_tweak; ++i)
			poly_double(&m_tweak[i*BS], &m_tweak[(i-1)*BS], BS);
	}

private:
	final override void key_schedule(in ubyte* key, size_t length)
	{
		const size_t key_half = length / 2;
		
		if (length % 2 == 1 || !m_cipher.valid_keylength(key_half))
			throw new Invalid_Key_Length(name, length);
		
		m_cipher.set_key(&key[0], key_half);
		m_tweak_cipher.set_key(&key[key_half], key_half);
	}

	Unique!BlockCipher m_cipher, m_tweak_cipher;
	Secure_Vector!ubyte m_tweak;
};

/**
* IEEE P1619 XTS Encryption
*/
final class XTS_Encryption : XTS_Mode
{
public:
	this(BlockCipher cipher) 
	{
		super(cipher);
	}

	override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size;
		
		assert(sz % BS == 0, "Input is full blocks");
		size_t blocks = sz / BS;
		
		const size_t blocks_in_tweak = update_granularity() / BS;
		
		while(blocks)
		{
			const size_t to_proc = std.algorithm.min(blocks, blocks_in_tweak);
			const size_t to_proc_bytes = to_proc * BS;
			
			xor_buf(buf, tweak(), to_proc_bytes);
			cipher().encrypt_n(buf, buf, to_proc);
			xor_buf(buf, tweak(), to_proc_bytes);
			
			buf += to_proc * BS;
			blocks -= to_proc;
			
			update_tweak(to_proc);
		}
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz >= minimum_final_size(), "Have sufficient final input");
		
		const size_t BS = cipher().block_size;
		
		if (sz % BS == 0)
		{
			update(buffer, offset);
		}
		else
		{
			// steal ciphertext
			const size_t full_blocks = ((sz / BS) - 1) * BS;
			const size_t final_bytes = sz - full_blocks;
			assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
			
			Secure_Vector!ubyte last(buf + full_blocks, buf + full_blocks + final_bytes);
			buffer.resize(full_blocks + offset);
			update(buffer, offset);
			
			xor_buf(last, tweak(), BS);
			cipher().encrypt(last);
			xor_buf(last, tweak(), BS);
			
			for (size_t i = 0; i != final_bytes - BS; ++i)
			{
				last[i] ^= last[i + BS];
				last[i + BS] ^= last[i];
				last[i] ^= last[i + BS];
			}
			
			xor_buf(last, tweak() + BS, BS);
			cipher().encrypt(last);
			xor_buf(last, tweak() + BS, BS);
			
			buffer += last;
		}
	}

	override size_t output_length(size_t input_length) const
	{
		return round_up(input_length, cipher().block_size);
	}
};

/**
* IEEE P1619 XTS Decryption
*/
final class XTS_Decryption : XTS_Mode
{
public:
	this(BlockCipher cipher)
	{
		super(cipher);
	}

	override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size;
		
		assert(sz % BS == 0, "Input is full blocks");
		size_t blocks = sz / BS;
		
		const size_t blocks_in_tweak = update_granularity() / BS;
		
		while(blocks)
		{
			const size_t to_proc = std.algorithm.min(blocks, blocks_in_tweak);
			const size_t to_proc_bytes = to_proc * BS;
			
			xor_buf(buf, tweak(), to_proc_bytes);
			cipher().decrypt_n(buf, buf, to_proc);
			xor_buf(buf, tweak(), to_proc_bytes);
			
			buf += to_proc * BS;
			blocks -= to_proc;
			
			update_tweak(to_proc);
		}
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz >= minimum_final_size(), "Have sufficient final input");
		
		const size_t BS = cipher().block_size;
		
		if (sz % BS == 0)
		{
			update(buffer, offset);
		}
		else
		{
			// steal ciphertext
			const size_t full_blocks = ((sz / BS) - 1) * BS;
			const size_t final_bytes = sz - full_blocks;
			assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
			
			Secure_Vector!ubyte last(buf + full_blocks, buf + full_blocks + final_bytes);
			buffer.resize(full_blocks + offset);
			update(buffer, offset);
			
			xor_buf(last, tweak() + BS, BS);
			cipher().decrypt(last);
			xor_buf(last, tweak() + BS, BS);
			
			for (size_t i = 0; i != final_bytes - BS; ++i)
			{
				last[i] ^= last[i + BS];
				last[i + BS] ^= last[i];
				last[i] ^= last[i + BS];
			}
			
			xor_buf(last, tweak(), BS);
			cipher().decrypt(last);
			xor_buf(last, tweak(), BS);
			
			buffer += last;
		}
	}

	override size_t output_length(size_t input_length) const
	{
		// might be less
		return input_length;
	}
};


private:

void poly_double_128(ubyte* output, in ubyte* input) pure
{
	ulong X0 = load_le!ulong(input, 0);
	ulong X1 = load_le!ulong(input, 1);
	
	const bool carry = (X1 >> 63);
	
	X1 = (X1 << 1) | (X0 >> 63);
	X0 = (X0 << 1);
	
	if (carry)
		X0 ^= 0x87;
	
	store_le(output, X0, X1);
}

void poly_double_64(ubyte* output, in ubyte* input) pure
{
	ulong X = load_le!ulong(input, 0);
	const bool carry = (X >> 63);
	X <<= 1;
	if (carry)
		X ^= 0x1B;
	store_le(X, output);
}

void poly_double(ubyte* output, in ubyte* input) pure
{
	if (size == 8)
		poly_double_64(output, input);
	else
		poly_double_128(output, input);
}