/*
* OCB Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.ocb;

import botan.constants;
static if (BOTAN_HAS_AEAD_OCB):

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.filters.buf_filt;

import botan.cmac.cmac;
import botan.utils.xor_buf;
import botan.utils.bit_ops;
import botan.utils.types;
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
    final override Secure_Vector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!valid_nonce_length(nonce_len))
            throw new Invalid_IV_Length(name, nonce_len);
        
        assert(m_L, "A key was set");
        
        m_offset = update_nonce(nonce, nonce_len);
        zeroise(m_checksum);
        m_block_index = 0;
        
        return Secure_Vector!ubyte();
    }

    final override void set_associated_data(in ubyte* ad, size_t ad_len)
    {
        assert(m_L, "A key was set");
        m_ad_hash = ocb_hash(*m_L, *m_cipher, ad.ptr, ad_len);
    }

    final override @property string name() const
    {
        return m_cipher.name ~ "/OCB"; // include tag size
    }

    final override size_t update_granularity() const
    {
        return m_cipher.parallel_bytes();
    }

    final override Key_Length_Specification key_spec() const
    {
        return m_cipher.key_spec();
    }

    final override bool valid_nonce_length(size_t length) const
    {
        return (length > 0 && length < 16);
    }

    final override size_t tag_size() const { return m_tag_size; }

    final override void clear()
    {
        m_cipher.clear();
        m_L.clear();
        
        zeroise(m_ad_hash);
        zeroise(m_offset);
        zeroise(m_checksum);
    }

    ~this() { /* for unique_ptr destructor */ }
protected:
    /**
    * @param cipher the 128-bit block cipher to use
    * @param tag_size is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size)
    {     m_cipher = cipher;
        m_checksum = m_cipher.parallel_bytes();
        m_offset = BS;
        m_ad_hash = BS;
        m_tag_size = tag_size;
        if (m_cipher.block_size != BS)
            throw new Invalid_Argument("OCB requires a 128 bit cipher so cannot be used with " ~ m_cipher.name);
        
        if (m_tag_size != 8 && m_tag_size != 12 && m_tag_size != 16)
            throw new Invalid_Argument("OCB cannot produce a " ~ to!string(m_tag_size) ~ " ubyte tag");
        
    }

    final override void key_schedule(in ubyte* key, size_t length)
    {
        m_cipher.set_key(key, length);
        m_L = new L_computer(*m_cipher);
    }

    // fixme make these private
    Unique!BlockCipher m_cipher;
    Unique!L_computer m_L;

    size_t m_block_index = 0;

    Secure_Vector!ubyte m_checksum;
    Secure_Vector!ubyte m_offset;
    Secure_Vector!ubyte m_ad_hash;
private:
    final Secure_Vector!ubyte
            update_nonce(in ubyte* nonce, size_t nonce_len)
    {
        assert(nonce_len < BS, "Nonce is less than 128 bits");
        
        Secure_Vector!ubyte nonce_buf = Secure_Vector!ubyte(BS);
        
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
            
            foreach (size_t i; 0 .. 8)
                nonce_buf.push_back(nonce_buf[i] ^ nonce_buf[i+1]);
            
            m_stretch = nonce_buf;
        }
        
        // now set the offset from stretch and bottom
        
        const size_t shift_bytes = bottom / 8;
        const size_t shift_bits  = bottom % 8;
        
        Secure_Vector!ubyte offset = Secure_Vector!ubyte(BS);
        foreach (size_t i; 0 .. BS)
        {
            offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
            offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
        }
        
        return offset;
    }


    size_t m_tag_size = 0;
    Secure_Vector!ubyte m_last_nonce;
    Secure_Vector!ubyte m_stretch;
}

final class OCB_Encryption : OCB_Mode
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

    override void update(Secure_Vector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        encrypt(buf, sz / BS);
    }


    override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
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
                
                xor_buf(m_checksum.ptr, remainder.ptr, remainder_bytes);
                m_checksum[remainder_bytes] ^= 0x80;
                
                m_offset ^= m_L.star(); // Offset_*
                
                Secure_Vector!ubyte buf = Secure_Vector!ubyte(BS);
                m_cipher.encrypt(m_offset, buf);
                xor_buf(remainder.ptr, buf.ptr, remainder_bytes);
            }
        }
        
        Secure_Vector!ubyte checksum = Secure_Vector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // now compute the tag
        Secure_Vector!ubyte mac = m_offset;
        mac ^= checksum;
        mac ^= m_L.dollar();
        
        m_cipher.encrypt(mac);
        
        mac ^= m_ad_hash;
        
        buffer += Pair(mac.ptr, tag_size());
        
        zeroise(m_checksum);
        zeroise(m_offset);
        m_block_index = 0;
    }

private:
    void encrypt(ubyte* buffer, size_t blocks)
    {
        const L_computer L = *m_L; // convenient name
        
        const size_t par_blocks = m_checksum.length / BS;
        
        while (blocks)
        {
            const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
            const size_t proc_bytes = proc_blocks * BS;
            
            const offsets = L.compute_offsets(m_offset, m_block_index, proc_blocks);
            
            xor_buf(m_checksum.ptr, buffer.ptr, proc_bytes);
            
            xor_buf(buffer.ptr, offsets.ptr, proc_bytes);
            m_cipher.encrypt_n(buffer.ptr, buffer.ptr, proc_blocks);
            xor_buf(buffer.ptr, offsets.ptr, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }
}

final class OCB_Decryption : OCB_Mode
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

    override void update(Secure_Vector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        decrypt(buf, sz / BS);
    }

    override void finish(Secure_Vector!ubyte buffer, size_t offset = 0)
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
            
            decrypt(buf.ptr, final_full_blocks);
            
            if (final_bytes)
            {
                assert(final_bytes < BS, "Only a partial block left");
                
                ubyte* remainder = &buf[remaining - final_bytes];
                
                m_offset ^= m_L.star(); // Offset_*
                
                Secure_Vector!ubyte pad = Secure_Vector!ubyte(BS);
                m_cipher.encrypt(m_offset, pad); // P_*
                
                xor_buf(remainder.ptr, pad.ptr, final_bytes);
                
                xor_buf(m_checksum.ptr, remainder.ptr, final_bytes);
                m_checksum[final_bytes] ^= 0x80;
            }
        }
        
        Secure_Vector!ubyte checksum = Secure_Vector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // compute the mac
        Secure_Vector!ubyte mac = m_offset;
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
        
        if (!same_mem(mac.ptr, included_tag, tag_size()))
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
        
        while (blocks)
        {
            const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
            const size_t proc_bytes = proc_blocks * BS;
            
            const offsets = L.compute_offsets(m_offset, m_block_index, proc_blocks);
            
            xor_buf(buffer.ptr, offsets.ptr, proc_bytes);
            m_cipher.decrypt_n(buffer.ptr, buffer.ptr, proc_blocks);
            xor_buf(buffer.ptr, offsets.ptr, proc_bytes);
            
            xor_buf(m_checksum.ptr, buffer.ptr, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }

}

private:

__gshared immutable size_t BS = 16; // intrinsic to OCB definition

// Has to be in Botan namespace so unique_ptr can reference it
final class L_computer
{
public:
    this(in BlockCipher cipher)
    {
        m_L_star.resize(cipher.block_size);
        cipher.encrypt(m_L_star);
        m_L_dollar = poly_double(star());
        m_L.push_back(poly_double(dollar()));
    }
    
    const Secure_Vector!ubyte star() const { return m_L_star; }
    
    const Secure_Vector!ubyte dollar() const { return m_L_dollar; }
    
    const Secure_Vector!ubyte opCall(size_t i) { return get(i); }
    
    const Secure_Vector!ubyte compute_offsets(Secure_Vector!ubyte offset,
                                        size_t block_index,
                                        size_t blocks)
    {
        m_offset_buf.resize(blocks*BS);
        
        foreach (size_t i; 0 .. blocks)
        { // could be done in parallel
            offset ^= get(ctz(block_index + 1 + i));
            copy_mem(&m_offset_buf[BS*i], offset.ptr, BS);
        }
        
        return m_offset_buf;
    }
    
private:
    const Secure_Vector!ubyte get(size_t i)
    {
        while (m_L.length <= i)
            m_L.push_back(poly_double(m_L.back()));
        
        return m_L[i];
    }
    
    Secure_Vector!ubyte poly_double(in Secure_Vector!ubyte input) const
    {
        return CMAC.poly_double(input);
    }
    
    Secure_Vector!ubyte m_L_dollar, m_L_star;
    Vector!( Secure_Vector!ubyte ) m_L;
    Secure_Vector!ubyte m_offset_buf;
}

/*
* OCB's HASH
*/
Secure_Vector!ubyte ocb_hash(in L_computer L,
                          const BlockCipher cipher,
                          in ubyte* ad, size_t ad_len)
{
    Secure_Vector!ubyte sum = Secure_Vector!ubyte(BS);
    Secure_Vector!ubyte offset = Secure_Vector!ubyte(BS);
    
    Secure_Vector!ubyte buf = Secure_Vector!ubyte(BS);
    
    const size_t ad_blocks = (ad_len / BS);
    const size_t ad_remainder = (ad_len % BS);
    
    foreach (size_t i; 0 .. ad_blocks)
    {
        // this loop could run in parallel
        offset ^= L(ctz(i+1));
        
        buf = offset;
        xor_buf(buf.ptr, &ad[BS*i], BS);
        
        cipher.encrypt(buf);
        
        sum ^= buf;
    }
    
    if (ad_remainder)
    {
        offset ^= L.star();
        
        buf = offset;
        xor_buf(buf.ptr, &ad[BS*ad_blocks], ad_remainder);
        buf[ad_len % BS] ^= 0x80;
        
        cipher.encrypt(buf);
        
        sum ^= buf;
    }
    
    return sum;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.hash.sha2_32;
import botan.block.aes;

Vector!ubyte ocb_decrypt(in SymmetricKey key,
                         in Vector!ubyte nonce,
                         in ubyte* ct, size_t ct_len,
                         in ubyte* ad, size_t ad_len)
{
    auto ocb = scoped!OCB_Decryption(new AES_128);
    
    ocb.set_key(key);
    ocb.set_associated_data(ad, ad_len);
    
    ocb.start(&nonce[0], nonce.length);
    
    Secure_Vector!ubyte buf = Secure_Vector!ubyte(ct[0 .. ct+ct_len]);
    ocb.finish(buf, 0);
    
    return unlock(buf);
}

Vector!ubyte ocb_encrypt(in SymmetricKey key,
                         in Vector!ubyte nonce,
                         in ubyte* pt, size_t pt_len,
                         in ubyte* ad, size_t ad_len)
{
    auto ocb = scoped!OCB_Encryption(new AES_128);
    
    ocb.set_key(key);
    ocb.set_associated_data(ad, ad_len);
    
    ocb.start(&nonce[0], nonce.length);
    
    Secure_Vector!ubyte buf = Secure_Vector!ubyte(pt[0 .. pt+pt_len]);
    ocb.finish(buf, 0);
    
    try
    {
        Vector!ubyte pt2 = ocb_decrypt(key, nonce, &buf[0], buf.length, ad, ad_len);
        if (pt_len != pt2.length || !same_mem(pt, &pt2[0], pt_len))
            writeln("OCB failed to decrypt correctly");
    }
    catch(Exception e)
    {
        writeln("OCB round trip error - " ~ e.msg);
    }
    
    return unlock(buf);
}

Vector!ubyte ocb_encrypt(Alloc, Alloc2)(in SymmetricKey key,
                                        in Vector!ubyte nonce,
                                        in Vector!(ubyte, Alloc) pt,
                                        in Vector!(ubyte, Alloc2) ad)
{
    return ocb_encrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocb_decrypt(Alloc, Alloc2)(in SymmetricKey key,
                                        in Vector!ubyte nonce,
                                        in Vector!(ubyte, Alloc) pt,
                                        in Vector!(ubyte, Alloc2) ad)
{
    return ocb_decrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocb_encrypt(OCB_Encryption ocb,
                         in Vector!ubyte nonce,
                         in Vector!ubyte pt,
                         in Vector!ubyte ad)
{
    ocb.set_associated_data(&ad[0], ad.length);
    
    ocb.start(&nonce[0], nonce.length);
    
    Secure_Vector!ubyte buf(pt.begin(), pt.end());
    ocb.finish(buf, 0);
    
    return unlock(buf);
}

size_t test_ocb_long(size_t taglen, in string expected)
{
    auto ocb = scoped!OCB_Encryption(new AES_128, taglen/8);
    
    ocb.set_key(SymmetricKey("00000000000000000000000000000000"));
    
    const Vector!ubyte empty;
    Vector!ubyte N = Vector!ubyte(12);
    Vector!ubyte C;
    
    for(size_t i = 0; i != 128; ++i)
    {
        const Vector!ubyte S = Vector!ubyte(i);
        N[11] = i;
        
        C ~= ocb_encrypt(ocb, N, S, S);
        C ~= ocb_encrypt(ocb, N, S, empty);
        C ~= ocb_encrypt(ocb, N, empty, S);
    }
    
    N[11] = 0;
    const Vector!ubyte cipher = ocb_encrypt(ocb, N, empty, C);
    
    const string cipher_hex = hex_encode(cipher);
    
    if (cipher_hex != expected)
    {
        writeln("OCB AES-128 long test mistmatch " ~ cipher_hex ~ " != " ~ expected);
        return 1;
    }
    
    return 0;
}

unittest
{
    size_t fails = 0;
    
    fails += test_ocb_long(128, "B2B41CBF9B05037DA7F16C24A35C1C94");
    fails += test_ocb_long(96, "1A4F0654277709A5BDA0D380");
    fails += test_ocb_long(64, "B7ECE9D381FE437F");
    
    test_report("OCB long", 3, fails);
}