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
import botan.utils.xorBuf;
import botan.utils.bit_ops;
import botan.utils.types;
import std.algorithm;

class Lcomputer;

/**
* OCB Mode (base class for OCBEncryption and OCBDecryption). Note
* that OCB is patented, but is freely licensed in some circumstances.
*
* @see "The OCB Authenticated-Encryption Algorithm" internet draft
          http://tools.ietf.org/html/draft-irtf-cfrg-ocb-03
* @see Free Licenses http://www.cs.ucdavis.edu/~rogaway/ocb/license.htm
* @see OCB home page http://www.cs.ucdavis.edu/~rogaway/ocb
*/
class OCBMode : AEADMode
{
public:
    final override SecureVector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        assert(m_L, "A key was set");
        
        m_offset = updateNonce(nonce, nonce_len);
        zeroise(m_checksum);
        m_block_index = 0;
        
        return SecureVector!ubyte();
    }

    final override void setAssociatedData(in ubyte* ad, size_t ad_len)
    {
        assert(m_L, "A key was set");
        m_ad_hash = ocbHash(*m_L, *m_cipher, ad.ptr, ad_len);
    }

    final override @property string name() const
    {
        return m_cipher.name ~ "/OCB"; // include tag size
    }

    final override size_t updateGranularity() const
    {
        return m_cipher.parallelBytes();
    }

    final override KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    final override bool validNonceLength(size_t length) const
    {
        return (length > 0 && length < 16);
    }

    final override size_t tagSize() const { return m_tag_size; }

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
    * @param cipher = the 128-bit block cipher to use
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size)
    {     m_cipher = cipher;
        m_checksum = m_cipher.parallelBytes();
        m_offset = BS;
        m_ad_hash = BS;
        m_tag_size = tag_size;
        if (m_cipher.blockSize() != BS)
            throw new InvalidArgument("OCB requires a 128 bit cipher so cannot be used with " ~ m_cipher.name);
        
        if (m_tag_size != 8 && m_tag_size != 12 && m_tag_size != 16)
            throw new InvalidArgument("OCB cannot produce a " ~ to!string(m_tag_size) ~ " ubyte tag");
        
    }

    final override void keySchedule(in ubyte* key, size_t length)
    {
        m_cipher.setKey(key, length);
        m_L = new Lcomputer(*m_cipher);
    }

    // fixme make these private
    Unique!BlockCipher m_cipher;
    Unique!L_computer m_L;

    size_t m_block_index = 0;

    SecureVector!ubyte m_checksum;
    SecureVector!ubyte m_offset;
    SecureVector!ubyte m_ad_hash;
private:
    final SecureVector!ubyte
            updateNonce(in ubyte* nonce, size_t nonce_len)
    {
        assert(nonce_len < BS, "Nonce is less than 128 bits");
        
        SecureVector!ubyte nonce_buf = SecureVector!ubyte(BS);
        
        copyMem(&nonce_buf[BS - nonce_len], nonce, nonce_len);
        nonce_buf[0] = ((tagSize() * 8) % 128) << 1;
        nonce_buf[BS - nonce_len - 1] = 1;
        
        const ubyte bottom = nonce_buf[15] & 0x3F;
        nonce_buf[15] &= 0xC0;
        
        const bool need_new_stretch = (m_last_nonce != nonce_buf);
        
        if (need_new_stretch)
        {
            m_last_nonce = nonce_buf;
            
            m_cipher.encrypt(nonce_buf);
            
            foreach (size_t i; 0 .. 8)
                nonce_buf.pushBack(nonce_buf[i] ^ nonce_buf[i+1]);
            
            m_stretch = nonce_buf;
        }
        
        // now set the offset from stretch and bottom
        
        const size_t shift_bytes = bottom / 8;
        const size_t shift_bits  = bottom % 8;
        
        SecureVector!ubyte offset = SecureVector!ubyte(BS);
        foreach (size_t i; 0 .. BS)
        {
            offset[i]  = (m_stretch[i+shift_bytes] << shift_bits);
            offset[i] |= (m_stretch[i+shift_bytes+1] >> (8-shift_bits));
        }
        
        return offset;
    }


    size_t m_tag_size = 0;
    SecureVector!ubyte m_last_nonce;
    SecureVector!ubyte m_stretch;
}

final class OCBEncryption : OCBMode
{
public:
    /**
    * @param cipher = the 128-bit block cipher to use
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 16)
    {
        super(cipher, tag_size);
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        encrypt(buf, sz / BS);
    }


    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
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
                
                xorBuf(m_checksum.ptr, remainder.ptr, remainder_bytes);
                m_checksum[remainder_bytes] ^= 0x80;
                
                m_offset ^= m_L.star(); // Offset_*
                
                SecureVector!ubyte buf = SecureVector!ubyte(BS);
                m_cipher.encrypt(m_offset, buf);
                xorBuf(remainder.ptr, buf.ptr, remainder_bytes);
            }
        }
        
        SecureVector!ubyte checksum = SecureVector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // now compute the tag
        SecureVector!ubyte mac = m_offset;
        mac ^= checksum;
        mac ^= m_L.dollar();
        
        m_cipher.encrypt(mac);
        
        mac ^= m_ad_hash;
        
        buffer += Pair(mac.ptr, tagSize());
        
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
            
            const offsets = L.computeOffsets(m_offset, m_block_index, proc_blocks);
            
            xorBuf(m_checksum.ptr, buffer.ptr, proc_bytes);
            
            xorBuf(buffer.ptr, offsets.ptr, proc_bytes);
            m_cipher.encryptN(buffer.ptr, buffer.ptr, proc_blocks);
            xorBuf(buffer.ptr, offsets.ptr, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }
}

final class OCBDecryption : OCBMode
{
public:
    /**
    * @param cipher = the 128-bit block cipher to use
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 16)
    {
        super(cipher, tag_size);
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length > tagSize(), "Sufficient input");
        return input_length - tagSize();
    }

    override size_t minimumFinalSize() const { return tagSize(); }

    override void update(SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz % BS == 0, "Input length is an even number of blocks");
        
        decrypt(buf, sz / BS);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz >= tagSize(), "We have the tag");
        
        const size_t remaining = sz - tagSize();
        
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
                
                SecureVector!ubyte pad = SecureVector!ubyte(BS);
                m_cipher.encrypt(m_offset, pad); // P_*
                
                xorBuf(remainder.ptr, pad.ptr, final_bytes);
                
                xorBuf(m_checksum.ptr, remainder.ptr, final_bytes);
                m_checksum[final_bytes] ^= 0x80;
            }
        }
        
        SecureVector!ubyte checksum = SecureVector!ubyte(BS);
        
        // fold checksum
        for (size_t i = 0; i != m_checksum.length; ++i)
            checksum[i % checksum.length] ^= m_checksum[i];
        
        // compute the mac
        SecureVector!ubyte mac = m_offset;
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
        
        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("OCB tag check failed");
        
        // remove tag from end of message
        buffer.resize(remaining + offset);
    }

private:
    void decrypt(ubyte* buffer, size_t blocks)
    {
        const L_computer L = *m_L; // convenient name
        
        const size_t par_bytes = m_cipher.parallelBytes();
        
        assert(par_bytes % BS == 0, "Cipher is parallel in full blocks");
        
        const size_t par_blocks = par_bytes / BS;
        
        while (blocks)
        {
            const size_t proc_blocks = std.algorithm.min(blocks, par_blocks);
            const size_t proc_bytes = proc_blocks * BS;
            
            const offsets = L.computeOffsets(m_offset, m_block_index, proc_blocks);
            
            xorBuf(buffer.ptr, offsets.ptr, proc_bytes);
            m_cipher.decryptN(buffer.ptr, buffer.ptr, proc_blocks);
            xorBuf(buffer.ptr, offsets.ptr, proc_bytes);
            
            xorBuf(m_checksum.ptr, buffer.ptr, proc_bytes);
            
            buffer += proc_bytes;
            blocks -= proc_blocks;
            m_block_index += proc_blocks;
        }
    }

}

private:

__gshared immutable size_t BS = 16; // intrinsic to OCB definition

// Has to be in Botan namespace so unique_ptr can reference it
final class Lcomputer
{
public:
    this(in BlockCipher cipher)
    {
        m_L_star.resize(cipher.blockSize());
        cipher.encrypt(m_L_star);
        m_L_dollar = polyDouble(star());
        m_L.pushBack(polyDouble(dollar()));
    }
    
    SecureVector!ubyte star() const { return m_L_star; }
    
    SecureVector!ubyte dollar() const { return m_L_dollar; }
    
    SecureVector!ubyte opCall(size_t i) const { return get(i); }
    
    SecureVector!ubyte computeOffsets(SecureVector!ubyte offset,
                                        size_t block_index,
                                        size_t blocks) const
    {
        m_offset_buf.resize(blocks*BS);
        
        foreach (size_t i; 0 .. blocks)
        { // could be done in parallel
            offset ^= get(ctz(block_index + 1 + i));
            copyMem(&m_offset_buf[BS*i], offset.ptr, BS);
        }
        
        return m_offset_buf;
    }
    
private:
    SecureVector!ubyte get(size_t i) const
    {
        while (m_L.length <= i)
            m_L.pushBack(polyDouble(m_L.back()));
        
        return m_L[i];
    }
    
    SecureVector!ubyte polyDouble(in SecureVector!ubyte input) const
    {
        return CMAC.polyDouble(input);
    }
    
    SecureVector!ubyte m_L_dollar, m_L_star;
    Vector!( SecureVector!ubyte ) m_L;
    SecureVector!ubyte m_offset_buf;
}

/*
* OCB's HASH
*/
SecureVector!ubyte ocbHash(in Lcomputer L,
                          const BlockCipher cipher,
                          in ubyte* ad, size_t ad_len)
{
    SecureVector!ubyte sum = SecureVector!ubyte(BS);
    SecureVector!ubyte offset = SecureVector!ubyte(BS);
    
    SecureVector!ubyte buf = SecureVector!ubyte(BS);
    
    const size_t ad_blocks = (ad_len / BS);
    const size_t ad_remainder = (ad_len % BS);
    
    foreach (size_t i; 0 .. ad_blocks)
    {
        // this loop could run in parallel
        offset ^= L(ctz(i+1));
        
        buf = offset;
        xorBuf(buf.ptr, &ad[BS*i], BS);
        
        cipher.encrypt(buf);
        
        sum ^= buf;
    }
    
    if (ad_remainder)
    {
        offset ^= L.star();
        
        buf = offset;
        xorBuf(buf.ptr, &ad[BS*ad_blocks], ad_remainder);
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

Vector!ubyte ocbDecrypt(in SymmetricKey key,
                         in Vector!ubyte nonce,
                         in ubyte* ct, size_t ct_len,
                         in ubyte* ad, size_t ad_len)
{
    auto ocb = scoped!OCBDecryption(new AES128);
    
    ocb.setKey(key);
    ocb.setAssociatedData(ad, ad_len);
    
    ocb.start(&nonce[0], nonce.length);
    
    SecureVector!ubyte buf = SecureVector!ubyte(ct[0 .. ct+ct_len]);
    ocb.finish(buf, 0);
    
    return unlock(buf);
}

Vector!ubyte ocbEncrypt(in SymmetricKey key,
                         in Vector!ubyte nonce,
                         in ubyte* pt, size_t pt_len,
                         in ubyte* ad, size_t ad_len)
{
    auto ocb = scoped!OCBEncryption(new AES128);
    
    ocb.setKey(key);
    ocb.setAssociatedData(ad, ad_len);
    
    ocb.start(&nonce[0], nonce.length);
    
    SecureVector!ubyte buf = SecureVector!ubyte(pt[0 .. pt+pt_len]);
    ocb.finish(buf, 0);
    
    try
    {
        Vector!ubyte pt2 = ocbDecrypt(key, nonce, &buf[0], buf.length, ad, ad_len);
        if (pt_len != pt2.length || !sameMem(pt, &pt2[0], pt_len))
            writeln("OCB failed to decrypt correctly");
    }
    catch(Exception e)
    {
        writeln("OCB round trip error - " ~ e.msg);
    }
    
    return unlock(buf);
}

Vector!ubyte ocbEncrypt(Alloc, Alloc2)(in SymmetricKey key,
                                        in Vector!ubyte nonce,
                                        in Vector!(ubyte, Alloc) pt,
                                        in Vector!(ubyte, Alloc2) ad)
{
    return ocbEncrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocbDecrypt(Alloc, Alloc2)(in SymmetricKey key,
                                        in Vector!ubyte nonce,
                                        in Vector!(ubyte, Alloc) pt,
                                        in Vector!(ubyte, Alloc2) ad)
{
    return ocbDecrypt(key, nonce, &pt[0], pt.length, &ad[0], ad.length);
}

Vector!ubyte ocbEncrypt(OCBEncryption ocb,
                         in Vector!ubyte nonce,
                         in Vector!ubyte pt,
                         in Vector!ubyte ad)
{
    ocb.setAssociatedData(&ad[0], ad.length);
    
    ocb.start(&nonce[0], nonce.length);
    
    SecureVector!ubyte buf = SecureVector!ubyte(pt.ptr[0 .. $]);
    ocb.finish(buf, 0);
    
    return unlock(buf);
}

size_t testOcbLong(size_t taglen, in string expected)
{
    auto ocb = scoped!OCBEncryption(new AES128, taglen/8);
    
    ocb.setKey(SymmetricKey("00000000000000000000000000000000"));
    
    const Vector!ubyte empty;
    Vector!ubyte N = Vector!ubyte(12);
    Vector!ubyte C;
    
    for(size_t i = 0; i != 128; ++i)
    {
        const Vector!ubyte S = Vector!ubyte(i);
        N[11] = i;
        
        C ~= ocbEncrypt(ocb, N, S, S);
        C ~= ocbEncrypt(ocb, N, S, empty);
        C ~= ocbEncrypt(ocb, N, empty, S);
    }
    
    N[11] = 0;
    const Vector!ubyte cipher = ocbEncrypt(ocb, N, empty, C);
    
    const string cipher_hex = hexEncode(cipher);
    
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
    
    fails += testOcbLong(128, "B2B41CBF9B05037DA7F16C24A35C1C94");
    fails += testOcbLong(96, "1A4F0654277709A5BDA0D380");
    fails += testOcbLong(64, "B7ECE9D381FE437F");
    
    testReport("OCB long", 3, fails);
}