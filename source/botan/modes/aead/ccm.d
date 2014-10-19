/*
* CCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.ccm;
import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.mac.mac;
import botan.utils.parsing;
import botan.internal.xor_buf;
import std.algorithm;

/**
* Base class for CCM encryption and decryption
* @see RFC 3610
*/
class CCM_Mode : AEAD_Mode
{
public:
	override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		m_nonce.assign(nonce, nonce + nonce_len);
		m_msg_buf.clear();
		
		return SafeVector!ubyte();
	}

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
		buffer.resize(offset); // truncate msg
	}

	override void set_associated_data(in ubyte* ad, size_t length)
	{
		m_ad_buf.clear();
		
		if (length)
		{
			// FIXME: support larger AD using length encoding rules
			BOTAN_ASSERT(length < (0xFFFF - 0xFF), "Supported CCM AD length");
			
			m_ad_buf.push_back(get_byte<ushort>(0, length));
			m_ad_buf.push_back(get_byte<ushort>(1, length));
			m_ad_buf += Pair(ad, length);
			while(m_ad_buf.length % BS)
				m_ad_buf.push_back(0); // pad with zeros to full block size
		}
	}

	override string name() const
	{
		return (m_cipher.name() ~ "/CCM(" ~ std.conv.to!string(tag_size()) ~ "," ~ std.conv.to!string(L())) ~ ")";
	}

	size_t update_granularity() const
	{
		/*
		This value does not particularly matter as regardless update
		buffers all input, so in theory this could be 1. However as for instance
		Transformation_Filter creates update_granularity() ubyte buffers, use a
		somewhat large size to avoid bouncing on a tiny buffer.
		*/
		return m_cipher.parallel_bytes();
	}


	override Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	override bool valid_nonce_length(size_t n) const
	{
		return (n == (15-L()));
	}

	override size_t default_nonce_length() const
	{
		return (15-L());
	}

	override void clear()
	{
		m_cipher.reset();
		m_msg_buf.clear();
		m_ad_buf.clear();
	}

	size_t tag_size() const { return m_tag_size; }

package:
	const size_t BS = 16; // intrinsic to CCM definition

	/*
	* CCM_Mode Constructor
	*/
	this(BlockCipher cipher, size_t tag_size, size_t L)
	{ 
		m_tag_size = tag_size;
		m_L = L;
		m_cipher = cipher;
		if (m_cipher.block_size() != BS)
			throw new Invalid_Argument(m_cipher.name() ~ " cannot be used with CCM mode");
		
		if (L < 2 || L > 8)
			throw new Invalid_Argument("Invalid CCM L value " ~ std.conv.to!string(L));
		
		if (tag_size < 4 || tag_size > 16 || tag_size % 2 != 0)
			throw new Invalid_Argument("invalid CCM tag length " ~ std.conv.to!string(tag_size));
	}

	size_t L() const { return m_L; }

	const ref BlockCipher cipher() const { return *m_cipher; }

	void encode_length(size_t len, ubyte* output)
	{
		const size_t len_bytes = L();
		
		BOTAN_ASSERT(len_bytes < sizeof(size_t), "Length field fits");
		
		for (size_t i = 0; i != len_bytes; ++i)
			output[len_bytes-1-i] = get_byte(sizeof(size_t)-1-i, len);
		
		BOTAN_ASSERT((len >> (len_bytes*8)) == 0, "Message length fits in field");
	}

	void inc(SafeVector!ubyte C)
	{
		for (size_t i = 0; i != C.length; ++i)
			if (++C[C.length-i-1])
				break;
	}

	const SafeVector!ubyte ad_buf() const { return m_ad_buf; }

	SafeVector!ubyte msg_buf() { return m_msg_buf; }

	SafeVector!ubyte format_b0(size_t sz)
	{
		SafeVector!ubyte B0(BS);
		
		const ubyte b_flags = (m_ad_buf.length ? 64 : 0) + (((tag_size()/2)-1) << 3) + (L()-1);
		
		B0[0] = b_flags;
		copy_mem(&B0[1], &m_nonce[0], m_nonce.length);
		encode_length(sz, &B0[m_nonce.length+1]);
		
		return B0;
	}

	SafeVector!ubyte format_c0()
	{
		SafeVector!ubyte C(BS);
		
		const ubyte a_flags = L()-1;
		
		C[0] = a_flags;
		copy_mem(&C[1], &m_nonce[0], m_nonce.length);
		
		return C;
	}
private:
	override void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
	}

	const size_t m_tag_size;
	const size_t m_L;

	Unique!BlockCipher m_cipher;
	SafeVector!ubyte m_nonce, m_msg_buf, m_ad_buf;
};

/**
* CCM Encryption
*/
class CCM_Encryption : CCM_Mode
{
public:
	/**
	* @param cipher a 128-bit block cipher
	* @param tag_size is how big the auth tag will be (even values
	*					  between 4 and 16 are accepted)
	* @param L length of L parameter. The total message length
	*			  must be less than 2**L bytes, and the nonce is 15-L bytes.
	*/
	this(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) 
	{
		super(cipher, tag_size, L);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		
		buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
		
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		BOTAN_ASSERT(sz >= tag_size(), "We have the tag");
		
		const SafeVector!ubyte ad = ad_buf();
		BOTAN_ASSERT(ad.length % BS == 0, "AD is block size multiple");
		
		const BlockCipher E = cipher();
		
		SafeVector!ubyte T(BS);
		E.encrypt(format_b0(sz - tag_size()), T);
		
		for (size_t i = 0; i != ad.length; i += BS)
		{
			xor_buf(&T[0], &ad[i], BS);
			E.encrypt(T);
		}
		
		SafeVector!ubyte C = format_c0();
		
		SafeVector!ubyte S0(BS);
		E.encrypt(C, S0);
		inc(C);
		
		SafeVector!ubyte X = SafeVector!ubyte(BS);
		
		const ubyte* buf_end = &buf[sz - tag_size()];
		
		while(buf != buf_end)
		{
			const size_t to_proc = std.algorithm.min(BS, buf_end - buf);
			
			E.encrypt(C, X);
			xor_buf(buf, &X[0], to_proc);
			inc(C);
			
			xor_buf(&T[0], buf, to_proc);
			E.encrypt(T);
			
			buf += to_proc;
		}
		
		T ^= S0;
		
		if (!same_mem(&T[0], buf_end, tag_size()))
			throw new Integrity_Failure("CCM tag check failed");
		
		buffer.resize(buffer.length - tag_size());
	}

	override size_t output_length(size_t input_length) const
	{ return input_length + tag_size(); }

	override size_t minimum_final_size() const { return 0; }
};

/**
* CCM Decryption
*/
class CCM_Decryption : CCM_Mode
{
public:
	/**
	* @param cipher a 128-bit block cipher
	* @param tag_size is how big the auth tag will be (even values
	*					  between 4 and 16 are accepted)
	* @param L length of L parameter. The total message length
	*			  must be less than 2**L bytes, and the nonce is 15-L bytes.
	*/
	this(BlockCipher cipher, size_t tag_size = 16, size_t L = 3) 
	{
		super(cipher, tag_size, L);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset)
	{
		BOTAN_ASSERT(buffer.length >= offset, "Offset is sane");
		
		buffer.insert(buffer.begin() + offset, msg_buf().begin(), msg_buf().end());
		
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		const SafeVector!ubyte ad = ad_buf();
		BOTAN_ASSERT(ad.length % BS == 0, "AD is block size multiple");
		
		const BlockCipher E = cipher();
		
		SafeVector!ubyte T(BS);
		E.encrypt(format_b0(sz), T);
		
		for (size_t i = 0; i != ad.length; i += BS)
		{
			xor_buf(&T[0], &ad[i], BS);
			E.encrypt(T);
		}
		
		SafeVector!ubyte C = format_c0();
		SafeVector!ubyte S0(BS);
		E.encrypt(C, S0);
		inc(C);
		
		SafeVector!ubyte X = SafeVector!ubyte(BS);
		
		const ubyte* buf_end = &buf[sz];
		
		while(buf != buf_end)
		{
			const size_t to_proc = std.algorithm.min(BS, buf_end - buf);
			
			xor_buf(&T[0], buf, to_proc);
			E.encrypt(T);
			
			E.encrypt(C, X);
			xor_buf(buf, &X[0], to_proc);
			inc(C);
			
			buf += to_proc;
		}
		
		T ^= S0;
		
		buffer += Pair(&T[0], tag_size());
	}

	override size_t output_length(size_t input_length) const
	{
		BOTAN_ASSERT(input_length > tag_size(), "Sufficient input");
		return input_length - tag_size();
	}

	override size_t minimum_final_size() const { return tag_size(); }
};