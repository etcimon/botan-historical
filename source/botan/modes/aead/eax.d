/*
* EAX Mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.eax;

import botan.constants;
static if (BOTAN_HAS_AEAD_EAX):

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
* EAX base class
*/
class EAX_Mode : AEAD_Mode
{
public:
	final override Secure_Vector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name, nonce_len);
		
		m_nonce_mac = eax_prf(0, this.block_size, *m_cmac, nonce, nonce_len);
		
		m_ctr.set_iv(m_nonce_mac.ptr, m_nonce_mac.length);
		
		for (size_t i = 0; i != this.block_size - 1; ++i)
			m_cmac.update(0);
		m_cmac.update(2);
		
		return Secure_Vector!ubyte();
	}


	final override void set_associated_data(in ubyte* ad, size_t length)
	{
		m_ad_mac = eax_prf(1, this.block_size, *m_cmac, ad, length);
	}

	final override @property string name() const
	{
		return (m_cipher.name ~ "/EAX");
	}

	final override size_t update_granularity() const
	{
		return 8 * m_cipher.parallel_bytes();
	}

	final override Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	// EAX supports arbitrary nonce lengths
	final override bool valid_nonce_length(size_t) const { return true; }

	final override size_t tag_size() const { return m_tag_size; }

	final override void clear()
	{
		m_cipher.clear();
		m_ctr.clear();
		m_cmac.clear();
		zeroise(m_ad_mac);
		zeroise(m_nonce_mac);
	}

protected:
	final override void key_schedule(in ubyte* key, size_t length)
	{
		/*
		* These could share the key schedule, which is one nice part of EAX,
		* but it's much easier to ignore that here...
		*/
		m_ctr.set_key(key, length);
		m_cmac.set_key(key, length);
		
		m_ad_mac = eax_prf(1, this.block_size, *m_cmac, null, 0);
	}

	/**
	* @param cipher the cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size) 
	{
		m_tag_size = tag_size ? tag_size : cipher.block_size;
		m_cipher = cipher;
		m_ctr = new CTR_BE(m_cipher.clone());
		m_cmac = new CMAC(m_cipher.clone());
		if (m_tag_size < 8 || m_tag_size > m_cmac.output_length)
			throw new Invalid_Argument(name ~ ": Bad tag size " ~ to!string(tag_size));
	}

	final @property size_t block_size() const { return m_cipher.block_size; }

	size_t m_tag_size;

	Unique!BlockCipher m_cipher;
	Unique!StreamCipher m_ctr;
	Unique!MessageAuthenticationCode m_cmac;

	Secure_Vector!ubyte m_ad_mac;

	Secure_Vector!ubyte m_nonce_mac;
}

/**
* EAX Encryption
*/
final class EAX_Encryption : EAX_Mode
{
public:
	/**
	* @param cipher a 128-bit block cipher
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size = 0) 
	{
		super(cipher, tag_size);
	}

	override size_t output_length(size_t input_length) const
	{ return input_length + tag_size(); }

	override size_t minimum_final_size() const { return 0; }

	override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_ctr.cipher(buf, buf, sz);
		m_cmac.update(buf, sz);
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset)
	{
		update(buffer, offset);
		
		Secure_Vector!ubyte data_mac = m_cmac.flush();
		xor_buf(data_mac, m_nonce_mac, data_mac.length);
		xor_buf(data_mac, m_ad_mac, data_mac.length);
		
		buffer += Pair(data_mac.ptr, tag_size());
	}
}

/**
* EAX Decryption
*/
final class EAX_Decryption : EAX_Mode
{
public:
	/**
	* @param cipher a 128-bit block cipher
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size = 0) 
	{
		super(cipher, tag_size); 
	}

	override size_t output_length(size_t input_length) const
	{
		assert(input_length > tag_size(), "Sufficient input");
		return input_length - tag_size();
	}

	override size_t minimum_final_size() const { return tag_size(); }

	override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_cmac.update(buf, sz);
		m_ctr.cipher(buf, buf, sz);
	}

	override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz >= tag_size(), "Have the tag as part of final input");
		
		const size_t remaining = sz - tag_size();
		
		if (remaining)
		{
			m_cmac.update(buf, remaining);
			m_ctr.cipher(buf, buf, remaining);
		}
		
		const ubyte* included_tag = &buf[remaining];
		
		Secure_Vector!ubyte mac = m_cmac.flush();
		mac ^= m_nonce_mac;
		mac ^= m_ad_mac;
		
		if (!same_mem(mac.ptr, included_tag, tag_size()))
			throw new Integrity_Failure("EAX tag check failed");
		
		buffer.resize(offset + remaining);
	}
}


/*
* EAX MAC-based PRF
*/
Secure_Vector!ubyte eax_prf(ubyte tag, size_t block_size,
                         MessageAuthenticationCode mac,
                         in ubyte* input,
                         size_t length) pure
{
	foreach (size_t i; 0 .. (block_size - 1))
		mac.update(0);
	mac.update(tag);
	mac.update(input, length);
	return mac.flush();
}