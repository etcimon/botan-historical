/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.ocb;

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.filters.buf_filt;

import botan.cmac.cmac;
import botan.utils.xor_buf;
import botan.utils.bit_ops;
import std.algorithm;

class L_computer;

/**
* OCB Mode (base class for OCB_Encryption and OCB_Decryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
		  http://tools.ietf.org/html/draft-irtf-cfrg-ocb-03
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class OCB_Mode : AEAD_Mode
{
public:
	override SafeVector!ubyte start(in ubyte* nonce, size_t nonce_len)
	{
		if (!valid_nonce_length(nonce_len))
			throw new Invalid_IV_Length(name(), nonce_len);
		
		assert(m_L, "A key was set");
		
		m_offset = update_nonce(nonce, nonce_len);
		zeroise(m_checksum);
		m_block_index = 0;
		
		return SafeVector!ubyte();
	}

	override void set_associated_data(in ubyte* ad, size_t ad_len)
	{
		assert(m_L, "A key was set");
		m_ad_hash = ocb_hash(*m_L, *m_cipher, &ad[0], ad_len);
	}

	override string name() const
	{
		return m_cipher.name() ~ "/OCB"; // include tag size
	}

	override size_t update_granularity() const
	{
		return m_cipher.parallel_bytes();
	}

	override Key_Length_Specification key_spec() const
	{
		return m_cipher.key_spec();
	}

	override bool valid_nonce_length(size_t length) const
	{
		return (length > 0 && length < 16);
	}

	override size_t tag_size() const { return m_tag_size; }

	override void clear()
	{
		m_cipher.clear();
		m_L.clear();
		
		zeroise(m_ad_hash);
		zeroise(m_offset);
		zeroise(m_checksum);
	}

	~this() { /* for unique_ptr destructor */ }
package:
	/**
	* @param cipher the 128-bit block cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size)
	{ 	m_cipher = cipher;
		m_checksum = m_cipher.parallel_bytes();
		m_offset = BS;
		m_ad_hash = BS;
		m_tag_size = tag_size;
		if (m_cipher.block_size() != BS)
			throw new Invalid_Argument("OCB requires a 128 bit cipher so cannot be used with " ~
			                           m_cipher.name());
		
		if (m_tag_size != 8 && m_tag_size != 12 && m_tag_size != 16)
			throw new Invalid_Argument("OCB cannot produce a " ~ std.conv.to!string(m_tag_size) +
			                           " ubyte tag");
		
	}

	override void key_schedule(in ubyte* key, size_t length)
	{
		m_cipher.set_key(key, length);
		m_L = new L_computer(*m_cipher);
	}

	// fixme make these private
	Unique!BlockCipher m_cipher;
	Unique!L_computer m_L;

	size_t m_block_index = 0;

	SafeVector!ubyte m_checksum;
	SafeVector!ubyte m_offset;
	SafeVector!ubyte m_ad_hash;
private:
	SafeVector!ubyte
		update_nonce(in ubyte* nonce, size_t nonce_len)
	{
		assert(nonce_len < BS, "Nonce is less than 128 bits");
		
		SafeVector!ubyte nonce_buf(BS);
		
		copy_mem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
		nonce_buf[0] = ((tag_size() * 8) % 128) << 1;
		nonce_buf[BS - nonce_len - 1] = 1;
		
		const ubyte bottom = nonce_buf[15] & 0x3F;
		nonce_buf[15] &= 0xC0;
		
		const bool need_new_stretch = (m_last_nonce != nonce_buf);
		
		if (need_new_stretch)
		{
			m_last_nonce = nonce_buf;
			
			m_cipher.encrypt(nonce_buf);
			
			for (size_t i = 0; i != 8; ++i)
				nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+1]);
			
			m_stretch = nonce_buf;
		}
		
		// now set the offset from stretch and bottom
		
		const size_t shift_bytes = bottom / 8;
		const size_t shift_bits  = bottom % 8;
		
		SafeVector!ubyte offset(BS);
		for (size_t i = 0; i != BS; ++i)
		{
			offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
			offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
		}
		
		return offset;
	}


	size_t m_tag_size = 0;
	SafeVector!ubyte m_last_nonce;
	SafeVector!ubyte m_stretch;
};

class OCB_Encryption : OCB_Mode
{
public:
	/**
	* @param cipher the 128-bit block cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size = 16)
	{
		super(cipher, tag_size);
	}

	override size_t output_length(size_t input_length) const
	{ return input_length + tag_size(); }

	override size_t minimum_final_size() const { return 0; }

	override void update(SafeVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz % BS == 0, "Input length is an even number of blocks");
		
		encrypt(buf, sz / BS);
	}


	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		if (sz)
		{
			const size_t final_full_blocks = sz / BS;
			const size_t remainder_bytes = sz - (final_full_blocks * BS);
			
			encrypt(buf, final_full_blocks);
			
			if (remainder_bytes)
			{
				assert(remainder_bytes < BS, "Only a partial block left");
				ubyte* remainder = &buf[sz - remainder_bytes];
				
				xor_buf(&m_checksum[0], &remainder[0], remainder_bytes);
				m_checksum[remainder_bytes] ^= 0x80;
				
				m_offset ^= m_L.star(); // Offset_*
				
				SafeVector!ubyte buf(BS);
				m_cipher.encrypt(m_offset, buf);
				xor_buf(&remainder[0], &buf[0], remainder_bytes);
			}
		}
		
		SafeVector!ubyte checksum(BS);
		
		// fold checksum
		for (size_t i = 0; i != m_checksum.length; ++i)
			checksum[i % checksum.length] ^= m_checksum[i];
		
		// now compute the tag
		SafeVector!ubyte mac = m_offset;
		mac ^= checksum;
		mac ^= m_L.dollar();
		
		m_cipher.encrypt(mac);
		
		mac ^= m_ad_hash;
		
		buffer += Pair(&mac[0], tag_size());
		
		zeroise(m_checksum);
		zeroise(m_offset);
		m_block_index = 0;
	}

private:
	void encrypt(ubyte* buffer, size_t blocks)
	{
		const L_computer L = *m_L; // convenient name
		
		const size_t par_blocks = m_checksum.length / BS;
		
		while(blocks)
		{
			const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
			const size_t proc_bytes = proc_blocks * BS;
			
			const auto& offsets = L.compute_offsets(m_offset, m_block_index, proc_blocks);
			
			xor_buf(&m_checksum[0], &buffer[0], proc_bytes);
			
			xor_buf(&buffer[0], &offsets[0], proc_bytes);
			m_cipher.encrypt_n(&buffer[0], &buffer[0], proc_blocks);
			xor_buf(&buffer[0], &offsets[0], proc_bytes);
			
			buffer += proc_bytes;
			blocks -= proc_blocks;
			m_block_index += proc_blocks;
		}
	}
};

class OCB_Decryption : OCB_Mode
{
public:
	/**
	* @param cipher the 128-bit block cipher to use
	* @param tag_size is how big the auth tag will be
	*/
	this(BlockCipher cipher, size_t tag_size = 16)
	{
		super(cipher, tag_size);
	}

	override size_t output_length(size_t input_length) const
	{
		assert(input_length > tag_size(), "Sufficient input");
		return input_length - tag_size();
	}

	override size_t minimum_final_size() const { return tag_size(); }

	override void update(SafeVector!ubyte buffer, size_t offset)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz % BS == 0, "Input length is an even number of blocks");
		
		decrypt(buf, sz / BS);
	}

	override void finish(SafeVector!ubyte buffer, size_t offset = 0)
	{
		assert(buffer.length >= offset, "Offset is sane");
		const size_t sz = buffer.length - offset;
		ubyte* buf = &buffer[offset];
		
		assert(sz >= tag_size(), "We have the tag");
		
		const size_t remaining = sz - tag_size();
		
		if (remaining)
		{
			const size_t final_full_blocks = remaining / BS;
			const size_t final_bytes = remaining - (final_full_blocks * BS);
			
			decrypt(&buf[0], final_full_blocks);
			
			if (final_bytes)
			{
				assert(final_bytes < BS, "Only a partial block left");
				
				ubyte* remainder = &buf[remaining - final_bytes];
				
				m_offset ^= m_L.star(); // Offset_*
				
				SafeVector!ubyte pad(BS);
				m_cipher.encrypt(m_offset, pad); // P_*
				
				xor_buf(&remainder[0], &pad[0], final_bytes);
				
				xor_buf(&m_checksum[0], &remainder[0], final_bytes);
				m_checksum[final_bytes] ^= 0x80;
			}
		}
		
		SafeVector!ubyte checksum(BS);
		
		// fold checksum
		for (size_t i = 0; i != m_checksum.length; ++i)
			checksum[i % checksum.length] ^= m_checksum[i];
		
		// compute the mac
		SafeVector!ubyte mac = m_offset;
		mac ^= checksum;
		mac ^= m_L.dollar();
		
		m_cipher.encrypt(mac);
		
		mac ^= m_ad_hash;
		
		// reset state
		zeroise(m_checksum);
		zeroise(m_offset);
		m_block_index = 0;
		
		// compare mac
		const ubyte* included_tag = &buf[remaining];
		
		if (!same_mem(&mac[0], included_tag, tag_size()))
			throw new Integrity_Failure("OCB tag check failed");
		
		// remove tag from end of message
		buffer.resize(remaining + offset);
	}

private:
	void decrypt(ubyte* buffer, size_t blocks)
	{
		const L_computer L = *m_L; // convenient name
		
		const size_t par_bytes = m_cipher.parallel_bytes();
		
		assert(par_bytes % BS == 0, "Cipher is parallel in full blocks");
		
		const size_t par_blocks = par_bytes / BS;
		
		while(blocks)
		{
			const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
			const size_t proc_bytes = proc_blocks * BS;
			
			const auto& offsets = L.compute_offsets(m_offset, m_block_index, proc_blocks);
			
			xor_buf(&buffer[0], &offsets[0], proc_bytes);
			m_cipher.decrypt_n(&buffer[0], &buffer[0], proc_blocks);
			xor_buf(&buffer[0], &offsets[0], proc_bytes);
			
			xor_buf(&m_checksum[0], &buffer[0], proc_bytes);
			
			buffer += proc_bytes;
			blocks -= proc_blocks;
			m_block_index += proc_blocks;
		}
	}

};

private:

const size_t BS = 16; // intrinsic to OCB definition

// Has to be in Botan namespace so unique_ptr can reference it
class L_computer
{
public:
	this(in BlockCipher cipher)
	{
		m_L_star.resize(cipher.block_size());
		cipher.encrypt(m_L_star);
		m_L_dollar = poly_double(star());
		m_L.push_back(poly_double(dollar()));
	}
	
	const SafeVector!ubyte star() const { return m_L_star; }
	
	const SafeVector!ubyte dollar() const { return m_L_dollar; }
	
	const SafeVector!ubyte opCall(size_t i) { return get(i); }
	
	const SafeVector!ubyte compute_offsets(SafeVector!ubyte offset,
	                                    size_t block_index,
	                                    size_t blocks)
	{
		m_offset_buf.resize(blocks*BS);
		
		for (size_t i = 0; i != blocks; ++i)
		{ // could be done in parallel
			offset ^= get(ctz(block_index + 1 + i));
			copy_mem(&m_offset_buf[BS*i], &offset[0], BS);
		}
		
		return m_offset_buf;
	}
	
private:
	const SafeVector!ubyte get(size_t i)
	{
		while(m_L.length <= i)
			m_L.push_back(poly_double(m_L.back()));
		
		return m_L.at(i);
	}
	
	SafeVector!ubyte poly_double(in SafeVector!ubyte input) const
	{
		return CMAC.poly_double(input);
	}
	
	SafeVector!ubyte m_L_dollar, m_L_star;
	Vector!( SafeVector!ubyte ) m_L;
	SafeVector!ubyte m_offset_buf;
};

/*
* OCB's HASH
*/
SafeVector!ubyte ocb_hash(in L_computer L,
                          const BlockCipher cipher,
                          in ubyte* ad, size_t ad_len)
{
	SafeVector!ubyte sum(BS);
	SafeVector!ubyte offset(BS);
	
	SafeVector!ubyte buf(BS);
	
	const size_t ad_blocks = (ad_len / BS);
	const size_t ad_remainder = (ad_len % BS);
	
	for (size_t i = 0; i != ad_blocks; ++i)
	{
		// this loop could run in parallel
		offset ^= L(ctz(i+1));
		
		buf = offset;
		xor_buf(&buf[0], &ad[BS*i], BS);
		
		cipher.encrypt(buf);
		
		sum ^= buf;
	}
	
	if (ad_remainder)
	{
		offset ^= L.star();
		
		buf = offset;
		xor_buf(&buf[0], &ad[BS*ad_blocks], ad_remainder);
		buf[ad_len % BS] ^= 0x80;
		
		cipher.encrypt(buf);
		
		sum ^= buf;
	}
	
	return sum;
}
