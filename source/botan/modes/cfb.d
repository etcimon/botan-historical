/*
* CFB mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cfb;

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.parsing;
import botan.utils.xor_buf;
/**
* CFB Mode
*/
class CFB_Mode : Cipher_Mode
{
public:
	override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		m_shift_register.assign(nonce, nonce + nonce_len);
		m_keystream_buf.resize(m_shift_register.length);
		cipher().encrypt(m_shift_register, m_keystream_buf);
		
		return SafeVector!ubyte();
	}

	override @property string name() const
	{
		if (feedback() == cipher().block_size)
			return cipher().name ~ "/CFB";
		else
			return cipher().name ~ "/CFB(" ~ std.conv.to!string(feedback()*8) ~ ")";
	}

	override size_t update_granularity() const
	{
		return feedback();
	}

	override size_t minimum_final_size() const
	{
		return 0;
	}

	override Key_Length_Specification key_spec() const
	{
		return cipher().key_spec();
	}

	override size_t output_length(size_t input_length) const
	{
		return input_length;
	}

	override size_t default_nonce_length() const
	{
		return cipher().block_size;
	}

	override bool valid_nonce_length(size_t n) const
	{
		return (n == cipher().block_size);
	}

	override void clear()
	{
		m_cipher.clear();
		m_shift_register.clear();
	}
package:
	this(BlockCipher cipher, size_t feedback_bits)
	{ 
		m_cipher = cipher;
		m_feedback_bytes = feedback_bits ? feedback_bits / 8 : cipher.block_size;
		if (feedback_bits % 8 || feedback() > cipher.block_size)
			throw new Invalid_Argument(name() ~ ": feedback bits " ~
			                           std.conv.to!string(feedback_bits) ~ " not supported");
	}

	const BlockCipher cipher() const { return *m_cipher; }

	size_t feedback() const { return m_feedback_bytes; }

	SafeVector!ubyte shift_register() { return m_shift_register; }

	SafeVector!ubyte keystream_buf() { return m_keystream_buf; }

private:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
	}

	Unique!BlockCipher m_cipher;
	SafeVector!ubyte m_shift_register;
	SafeVector!ubyte m_keystream_buf;
	size_t m_feedback_bytes;
};

/**
* CFB Encryption
*/
class CFB_Encryption : CFB_Mode
{
public:
	this(BlockCipher cipher, size_t feedback_bits)
	{
		super(cipher, feedback_bits) 
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size;
		
		SafeVector!ubyte state = shift_register();
		const size_t shift = feedback();
		
		while(sz)
		{
			const size_t took = std.algorithm.min(shift, sz);
			xor_buf(&buf[0], &keystream_buf()[0], took);
			
			// Assumes feedback-sized block except for last input
			copy_mem(&state[0], &state[shift], BS - shift);
			copy_mem(&state[BS-shift], &buf[0], took);
			cipher().encrypt(state, keystream_buf());
			
			buf += took;
			sz -= took;
		}
	}


	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		update(buffer, offset);
	}
};

/**
* CFB Decryption
*/
class CFB_Decryption : CFB_Mode
{
public:
	this(BlockCipher cipher, size_t feedback_bits) 
	{
		super(cipher, feedback_bits);
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const size_t BS = cipher().block_size;
		
		SafeVector!ubyte state = shift_register();
		const size_t shift = feedback();
		
		while(sz)
		{
			const size_t took = std.algorithm.min(shift, sz);
			
			// first update shift register with ciphertext
			copy_mem(&state[0], &state[shift], BS - shift);
			copy_mem(&state[BS-shift], &buf[0], took);
			
			// then decrypt
			xor_buf(&buf[0], &keystream_buf()[0], took);
			
			// then update keystream
			cipher().encrypt(state, keystream_buf());
			
			buf += took;
			sz -= took;
		}
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		update(buffer, offset);
	}

};