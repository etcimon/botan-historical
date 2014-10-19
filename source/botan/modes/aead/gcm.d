/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.gcm;

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.ctr;
import botan.internal.xor_buf;
import botan.utils.loadstor;

import botan.utils.simd.immintrin;
import botan.utils.simd.wmmintrin;


static if (BOTAN_HAS_GCM_CLMUL) {
	import botan.internal.clmul;
	import botan.utils.cpuid;
}

class GHASH;

/**
* GCM Mode
*/
class GCM_Mode : AEAD_Mode
{
public:
	override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		SafeVector!ubyte y0(BS);
		
		if (nonce_len == 12)
		{
			copy_mem(&y0[0], nonce, nonce_len);
			y0[15] = 1;
		}
		else
		{
			y0 = m_ghash.nonce_hash(nonce, nonce_len);
		}
		
		m_ctr.set_iv(&y0[0], y0.length);
		
		SafeVector!ubyte m_enc_y0(BS);
		m_ctr.encipher(m_enc_y0);
		
		m_ghash.start(&m_enc_y0[0], m_enc_y0.length);
		
		return SafeVector!ubyte();
	}

	override void set_associated_data(in ubyte* ad, size_t ad_len)
	{
		m_ghash.set_associated_data(ad, ad_len);
	}

	override string name() const
	{
		return (m_cipher_name ~ "/GCM");
	}

	override size_t update_granularity() const
	{
		return 4096; // CTR-BE's internal block size
	}

	override Key_Length_Specification key_spec() const
	{
		return m_ctr.key_spec();
	}

	// GCM supports arbitrary nonce lengths
	override bool valid_nonce_length(size_t) const { return true; }

	override size_t tag_size() const { return m_tag_size; }

	override void clear()
	{
		m_ctr.clear();
		m_ghash.clear();
	}
package:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_ctr.set_key(key, keylen);
		
		const Vector!ubyte zeros(BS);
		m_ctr.set_iv(&zeros[0], zeros.length);
		
		SafeVector!ubyte H(BS);
		m_ctr.encipher(H);
		m_ghash.set_key(H);
	}

	/*
	* GCM_Mode Constructor
	*/
	this(BlockCipher cipher, size_t tag_size)
	{ 
		m_tag_size = tag_size;
		m_cipher_name = cipher.name();
		if (cipher.block_size() != BS)
			throw new Invalid_Argument("GCM requires a 128 bit cipher so cannot be used with " ~
			                           cipher.name());
		
		m_ghash.reset(new GHASH);
		
		m_ctr.reset(new CTR_BE(cipher)); // CTR_BE takes ownership of cipher
		
		if (m_tag_size != 8 && m_tag_size != 16)
			throw new Invalid_Argument(name() ~ ": Bad tag size " ~ std.conv.to!string(m_tag_size));
	}

	const size_t BS = 16;

	const size_t m_tag_size;
	const string m_cipher_name;

	Unique!StreamCipher m_ctr;
	Unique!GHASH m_ghash;
};

/**
* GCM Encryption
*/
class GCM_Encryption : GCM_Mode
{
public:
	/**
	* @param cipher the 128 bit block cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	GCM_Encryption(BlockCipher cipher, size_t tag_size = 16) :
		GCM_Mode(cipher, tag_size) {}

	override size_t output_length(size_t input_length) const
	{ return input_length + tag_size(); }

	override size_t minimum_final_size() const { return 0; }

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_ctr.cipher(buf, buf, sz);
		m_ghash.update(buf, sz);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		update(buffer, offset);
		auto mac = m_ghash.flush();
		buffer += Pair(&mac[0], tag_size());
	}
};

/**
* GCM Decryption
*/
class GCM_Decryption : GCM_Mode
{
public:
	/**
	* @param cipher the 128 bit block cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size = 16)
	{
		super(cipher, tag_size);
	}

	override size_t output_length(size_t input_length) const
	{
		BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
		return input_length - tag_size();
	}

	override size_t minimum_final_size() const { return tag_size(); }

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_ghash.update(buf, sz);
		m_ctr.cipher(buf, buf, sz);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		BOTAN_ASSERT(sz >= tag_size(), "Have the tag as part of final input");
		
		const size_t remaining = sz - tag_size();
		
		// handle any final input before the tag
		if (remaining)
		{
			m_ghash.update(buf, remaining);
			m_ctr.cipher(buf, buf, remaining);
		}
		
		auto mac = m_ghash.flush();
		
		const ubyte* included_tag = &buffer[remaining];
		
		if (!same_mem(&mac[0], included_tag, tag_size()))
			throw new Integrity_Failure("GCM tag check failed");
		
		buffer.resize(offset + remaining);
	}
};

/**
* GCM's GHASH
* Maybe a Transform?
*/
class GHASH : SymmetricAlgorithm
{
public:
	void set_associated_data(in ubyte* input, size_t length)
	{
		zeroise(m_H_ad);
		
		ghash_update(m_H_ad, input, length);
		m_ad_len = length;
	}

	SafeVector!ubyte nonce_hash(in ubyte* nonce, size_t nonce_len)
	{
		BOTAN_ASSERT(m_ghash.length == 0, "nonce_hash called during wrong time");
		SafeVector!ubyte y0(16);
		
		ghash_update(y0, nonce, nonce_len);
		add_final_block(y0, 0, nonce_len);
		
		return y0;
	}

	void start(in ubyte* nonce, size_t len)
	{
		m_nonce.assign(nonce, nonce + len);
		m_ghash = m_H_ad;
	}

	/*
	* Assumes input len is multiple of 16
	*/
	void update(in ubyte* input, size_t length)
	{
		BOTAN_ASSERT(m_ghash.length == 16, "Key was set");
		
		m_text_len += length;
		
		ghash_update(m_ghash, input, length);
	}

	SafeVector!ubyte flush()
	{
		add_final_block(m_ghash, m_ad_len, m_text_len);
		
		SafeVector!ubyte mac;
		mac.swap(m_ghash);
		
		mac ^= m_nonce;
		m_text_len = 0;
		return mac;
	}

	Key_Length_Specification key_spec() const { return Key_Length_Specification(16); }

	override void clear()
	{
		zeroise(m_H);
		zeroise(m_H_ad);
		m_ghash.clear();
		m_text_len = m_ad_len = 0;
	}

	string name() const { return "GHASH"; }
private:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_H.assign(key, key+length);
		m_H_ad.resize(16);
		m_ad_len = 0;
		m_text_len = 0;
	}


	void gcm_multiply(SafeVector!ubyte x) const
	{
		static if (BOTAN_HAS_GCM_CLMUL) {
			if (CPUID.has_clmul())
				return gcm_multiply_clmul(&x[0], &m_H[0]);
		}
		
		static const ulong R = 0xE100000000000000;
		
		ulong[2] H = {
			load_be!ulong(&m_H[0], 0),
				load_be!ulong(&m_H[0], 1)
		};
		
		ulong[2] Z = { 0, 0 };
		
		// SSE2 might be useful here
		
		for (size_t i = 0; i != 2; ++i)
		{
			const ulong X = load_be!ulong(&x[0], i);
			
			for (size_t j = 0; j != 64; ++j)
			{
				if ((X >> (63-j)) & 1)
				{
					Z[0] ^= H[0];
					Z[1] ^= H[1];
				}
				
				const ulong r = (H[1] & 1) ? R : 0;
				
				H[1] = (H[0] << 63) | (H[1] >> 1);
				H[0] = (H[0] >> 1) ^ r;
			}
		}
		
		store_be!ulong(&x[0], Z[0], Z[1]);
	}

	void ghash_update(SafeVector!ubyte ghash,
	                  in ubyte* input, size_t length)
	{
		const size_t BS = 16;
		
		/*
		This assumes if less than block size input then we're just on the
		final block and should pad with zeros
		*/
		while(length)
		{
			const size_t to_proc = std.algorithm.min(length, BS);
			
			xor_buf(&ghash[0], &input[0], to_proc);
			
			gcm_multiply(ghash);
			
			input += to_proc;
			length -= to_proc;
		}
	}

	void add_final_block(SafeVector!ubyte hash,
	                     size_t ad_len, size_t text_len)
	{
		SafeVector!ubyte final_block(16);
		store_be!ulong(&final_block[0], 8*ad_len, 8*text_len);
		ghash_update(hash, &final_block[0], final_block.length);
	}

	SafeVector!ubyte m_H;
	SafeVector!ubyte m_H_ad;
	SafeVector!ubyte m_nonce;
	SafeVector!ubyte m_ghash;
	size_t m_ad_len = 0, m_text_len = 0;
};

void gcm_multiply_clmul(ubyte[16]* x, in ubyte[16]* H)
{
	/*
	* Algorithms 1 and 5 from Intel's CLMUL guide
	*/
	const __m128i BSWAP_MASK = _mm_set_epi8(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15);
	
	__m128i a = _mm_loadu_si128(cast(const __m128i*)(x[0]));
	__m128i b = _mm_loadu_si128(cast(const __m128i*)(H[0]));
	
	a = _mm_shuffle_epi8(a, BSWAP_MASK);
	b = _mm_shuffle_epi8(b, BSWAP_MASK);
	
	__m128i T0, T1, T2, T3, T4, T5;
	
	T0 = _mm_clmulepi64_si128(a, b, 0x00);
	T1 = _mm_clmulepi64_si128(a, b, 0x01);
	T2 = _mm_clmulepi64_si128(a, b, 0x10);
	T3 = _mm_clmulepi64_si128(a, b, 0x11);
	
	T1 = _mm_xor_si128(T1, T2);
	T2 = _mm_slli_si128(T1, 8);
	T1 = _mm_srli_si128(T1, 8);
	T0 = _mm_xor_si128(T0, T2);
	T3 = _mm_xor_si128(T3, T1);
	
	T4 = _mm_srli_epi32(T0, 31);
	T0 = _mm_slli_epi32(T0, 1);
	
	T5 = _mm_srli_epi32(T3, 31);
	T3 = _mm_slli_epi32(T3, 1);
	
	T2 = _mm_srli_si128(T4, 12);
	T5 = _mm_slli_si128(T5, 4);
	T4 = _mm_slli_si128(T4, 4);
	T0 = _mm_or_si128(T0, T4);
	T3 = _mm_or_si128(T3, T5);
	T3 = _mm_or_si128(T3, T2);
	
	T4 = _mm_slli_epi32(T0, 31);
	T5 = _mm_slli_epi32(T0, 30);
	T2 = _mm_slli_epi32(T0, 25);
	
	T4 = _mm_xor_si128(T4, T5);
	T4 = _mm_xor_si128(T4, T2);
	T5 = _mm_srli_si128(T4, 4);
	T3 = _mm_xor_si128(T3, T5);
	T4 = _mm_slli_si128(T4, 12);
	T0 = _mm_xor_si128(T0, T4);
	T3 = _mm_xor_si128(T3, T0);
	
	T4 = _mm_srli_epi32(T0, 1);
	T1 = _mm_srli_epi32(T0, 2);
	T2 = _mm_srli_epi32(T0, 7);
	T3 = _mm_xor_si128(T3, T1);
	T3 = _mm_xor_si128(T3, T2);
	T3 = _mm_xor_si128(T3, T4);
	
	T3 = _mm_shuffle_epi8(T3, BSWAP_MASK);
	
	_mm_storeu_si128(cast(__m128i*)(&x[0]), T3);
}