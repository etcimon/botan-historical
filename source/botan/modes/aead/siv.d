/*
* SIV Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.siv;

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.mac.mac;
import botan.cmac.cmac;
import botan.stream.ctr;
import botan.utils.parsing;
import botan.utils.xor_buf;
import std.algorithm;

/**
* Base class for SIV encryption and decryption (@see RFC 5297)
*/
class SIV_Mode : AEAD_Mode
{
public:
	final override Secure_Vector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name, nonce_len);
		
		if (nonce_len)
			m_nonce = m_cmac.process(nonce, nonce_len);
		else
			m_nonce.clear();
		
		m_msg_buf.clear();
		
		return Secure_Vector!ubyte();
	}

	final override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
		buffer.resize(offset); // truncate msg
	}

	final void set_associated_data_n(size_t n, in ubyte* ad, size_t length)
	{
		if (n >= m_ad_macs.length)
			m_ad_macs.resize(n+1);
		
		m_ad_macs[n] = m_cmac.process(ad, length);
	}

	final override void set_associated_data(in ubyte* ad, size_t ad_len)
	{
		set_associated_data_n(0, ad, ad_len);
	}

	final override @property string name() const
	{
		return m_name;
	}

	final override size_t update_granularity() const
	{
		/*
		This value does not particularly matter as regardless update
		buffers all input, so in theory this could be 1. However as for instance
		Transformation_Filter creates update_granularity() ubyte buffers, use a
		somewhat large size to avoid bouncing on a tiny buffer.
		*/
		return 128;
	}

	final override Key_Length_Specification key_spec() const
	{
		return m_cmac.key_spec().multiple(2);
	}

	final override bool valid_nonce_length(size_t) const
	{
		return true;
	}

	final override void clear()
	{
		m_ctr.clear();
		m_nonce.clear();
		m_msg_buf.clear();
		m_ad_macs.clear();
	}

	final override size_t tag_size() const { return 16; }

protected:
	this(BlockCipher cipher) 
	{
		m_name = cipher.name ~ "/SIV";
		m_ctr = new CTR_BE(cipher.clone());
		m_cmac = new CMAC(cipher);
	}

	final StreamCipher ctr() { return *m_ctr; }

	final void set_ctr_iv(Secure_Vector!ubyte V)
	{
		V[8] &= 0x7F;
		V[12] &= 0x7F;
		
		ctr().set_iv(V.ptr, V.length);
	}

	final Secure_Vector!ubyte msg_buf() { return m_msg_buf; }

	final Secure_Vector!ubyte S2V(in ubyte* text, size_t text_len)
	{
		const ubyte[16] zero;
		
		Secure_Vector!ubyte V = cmac().process(zero, 16);
		
		for (size_t i = 0; i != m_ad_macs.length; ++i)
		{
			V = CMAC.poly_double(V);
			V ^= m_ad_macs[i];
		}
		
		if (m_nonce.length)
		{
			V = CMAC.poly_double(V);
			V ^= m_nonce;
		}
		
		if (text_len < 16)
		{
			V = CMAC.poly_double(V);
			xor_buf(V.ptr, text, text_len);
			V[text_len] ^= 0x80;
			return cmac().process(V);
		}
		
		cmac().update(text, text_len - 16);
		xor_buf(V.ptr, &text[text_len - 16], 16);
		cmac().update(V);
		
		return cmac().flush();
	}
private:
	final MessageAuthenticationCode cmac() { return *m_cmac; }

	final override void key_schedule(in ubyte* key, size_t length)
	{
		const size_t keylen = length / 2;
		m_cmac.set_key(key, keylen);
		m_ctr.set_key(key + keylen, keylen);
		m_ad_macs.clear();
	}

	const string m_name;

	Unique!StreamCipher m_ctr;
	Unique!MessageAuthenticationCode m_cmac;
	Secure_Vector!ubyte m_nonce, m_msg_buf;
	Vector!( Secure_Vector!ubyte ) m_ad_macs;
}

/**
* SIV Encryption
*/
final class SIV_Encryption : SIV_Mode
{
public:
	/**
	* @param cipher a block cipher
	*/
	this(BlockCipher cipher)
	{
		super(cipher);
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		
		buffer.insert(buffer.ptr + offset, msg_buf().ptr, msg_buf().end());
		
		Secure_Vector!ubyte V = S2V(&buffer[offset], buffer.length - offset);
		
		buffer.insert(buffer.ptr + offset, V.ptr, V.end());
		
		set_ctr_iv(V);
		ctr().cipher1(&buffer[offset + V.length], buffer.length - offset - V.length);
	}

	override size_t output_length(size_t input_length) const
	{ return input_length + tag_size(); }

	override size_t minimum_final_size() const { return 0; }
}

/**
* SIV Decryption
*/
final class SIV_Decryption : SIV_Mode
{
public:
	/**
	* @param cipher a 128-bit block cipher
	*/
	this(BlockCipher cipher)
	{
		super(cipher);
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset)
	{
		assert(buffer.length >= offset, "Offset is sane");
		
		buffer.insert(buffer.ptr + offset, msg_buf().ptr, msg_buf().end());
		
		const size_t sz = buffer.length - offset;
		
		assert(sz >= tag_size(), "We have the tag");

		Secure_Vector!ubyte V = Secure_Vector!ubyte(buffer.ptr[offset .. offset + 16]);
		
		set_ctr_iv(V);
		
		ctr().cipher(&buffer[offset + V.length], &buffer[offset], buffer.length - offset - V.length);
		
		Secure_Vector!ubyte T = S2V(&buffer[offset], buffer.length - offset - V.length);
		
		if (T != V)
			throw new Integrity_Failure("SIV tag check failed");
		
		buffer.resize(buffer.length - tag_size());
	}

	override size_t output_length(size_t input_length) const
	{
		assert(input_length > tag_size(), "Sufficient input");
		return input_length - tag_size();
	}

	override size_t minimum_final_size() const { return tag_size(); }
}