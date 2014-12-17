/*
* GCM Mode
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.gcm;

import botan.constants;

static if (BOTAN_HAS_AEAD_GCM):

import botan.modes.aead.aead;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.stream.ctr;
import botan.utils.xor_buf;
import botan.utils.loadstor;
import botan.utils.mem_ops;

import botan.utils.simd.immintrin;
import botan.utils.simd.wmmintrin;

import botan.utils.types;

import std.conv : to;

static if (BOTAN_HAS_GCM_CLMUL) {
    import botan.utils.simd.wmmintrin;
    import botan.utils.cpuid;
}

/**
* GCM Mode
*/
class GCMMode : AEADMode, Transformation
{
public:
    final override SecureVector!ubyte start(const(ubyte)* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        SecureVector!ubyte y0 = SecureVector!ubyte(BS);
        
        if (nonce_len == 12)
        {
            copyMem(y0.ptr, nonce, nonce_len);
            y0[15] = 1;
        }
        else
        {
            y0 = m_ghash.nonceHash(nonce, nonce_len);
        }
        
        m_ctr.setIv(y0.ptr, y0.length);
        
        SecureVector!ubyte m_enc_y0 = SecureVector!ubyte(BS);
        m_ctr.encipher(m_enc_y0);
        
        m_ghash.start(m_enc_y0.ptr, m_enc_y0.length);
        
        return SecureVector!ubyte();
    }

    final override void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        m_ghash.setAssociatedData(ad, ad_len);
    }

    final override @property string name() const
    {
        return (m_cipher_name ~ "/GCM");
    }

    final override size_t updateGranularity() const
    {
        return 4096; // CTR-BE's internal block size
    }

    final override KeyLengthSpecification keySpec() const
    {
        return m_ctr.keySpec();
    }

    // GCM supports arbitrary nonce lengths
    final override bool validNonceLength(size_t) const { return true; }

    final override size_t tagSize() const { return m_tag_size; }

    final override void clear()
    {
        m_ctr.clear();
        m_ghash.clear();
    }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_ctr.setKey(key, length);
        
        const Vector!ubyte zeros = Vector!ubyte(BS);
        m_ctr.setIv(zeros.ptr, zeros.length);
        
        SecureVector!ubyte H = SecureVector!ubyte(BS);
        m_ctr.encipher(H);
        m_ghash.setKey(H);
    }

    /*
    * GCMMode Constructor
    */
    this(BlockCipher cipher, size_t tag_size)
    { 
        m_tag_size = tag_size;
        m_cipher_name = cipher.name;
        if (cipher.blockSize() != BS)
            throw new InvalidArgument("GCM requires a 128 bit cipher so cannot be used with " ~ cipher.name);
        
        m_ghash = new GHASH;

        m_ctr = new CTRBE(cipher); // CTR_BE takes ownership of cipher
        
        if (m_tag_size != 8 && m_tag_size != 16)
            throw new InvalidArgument(name ~ ": Bad tag size " ~ to!string(m_tag_size));
    }

    __gshared immutable size_t BS = 16;

    const size_t m_tag_size;
    const string m_cipher_name;

    Unique!StreamCipher m_ctr;
    Unique!GHASH m_ghash;
}

/**
* GCM Encryption
*/
final class GCMEncryption : GCMMode, Transformation
{
public:
    /**
    * @param cipher = the 128 bit block cipher to use
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
        
        m_ctr.cipher(buf, buf, sz);
        m_ghash.update(buf, sz);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
        auto mac = m_ghash.finished();
        buffer.resize(offset + tagSize());
        buffer.ptr[offset .. offset + tagSize()] = mac.ptr[0 .. tagSize()];
    }
}

/**
* GCM Decryption
*/
final class GCMDecryption : GCMMode, Transformation
{
public:
    /**
    * @param cipher = the 128 bit block cipher to use
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

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        m_ghash.update(buf, sz);
        m_ctr.cipher(buf, buf, sz);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        assert(sz >= tagSize(), "Have the tag as part of final input");
        
        const size_t remaining = sz - tagSize();
        
        // handle any final input before the tag
        if (remaining)
        {
            m_ghash.update(buf, remaining);
            m_ctr.cipher(buf, buf, remaining);
        }
        
        auto mac = m_ghash.finished();
        
        const(ubyte)* included_tag = &buffer[remaining];
        
        if (!sameMem(mac.ptr, included_tag, tagSize()))
            throw new IntegrityFailure("GCM tag check failed");
        
        buffer.resize(offset + remaining);
    }
}

/**
* GCM's GHASH
* Maybe a Transform?
*/
final class GHASH : SymmetricAlgorithm
{
public:
    void setAssociatedData(const(ubyte)* input, size_t length)
    {
        zeroise(m_H_ad);
        
        ghashUpdate(m_H_ad, input, length);
        m_ad_len = length;
    }

    SecureVector!ubyte nonceHash(const(ubyte)* nonce, size_t nonce_len)
    {
        assert(m_ghash.length == 0, "nonceHash called during wrong time");
        SecureVector!ubyte y0 = SecureVector!ubyte(16);
        
        ghashUpdate(y0, nonce, nonce_len);
        addFinalBlock(y0, 0, nonce_len);
        
        return y0;
    }

    void start(const(ubyte)* nonce, size_t len)
    {
        m_nonce[] = nonce[0 .. len];
        m_ghash = m_H_ad;
    }

    /*
    * Assumes input len is multiple of 16
    */
    void update(const(ubyte)* input, size_t length)
    {
        assert(m_ghash.length == 16, "Key was set");
        
        m_text_len += length;
        
        ghashUpdate(m_ghash, input, length);
    }

    SecureVector!ubyte finished()
    {
        addFinalBlock(m_ghash, m_ad_len, m_text_len);
        
        SecureVector!ubyte mac;
        mac.swap(m_ghash);
        mac.ptr[0 .. mac.length] ^= m_nonce.ptr[0 .. mac.length];
        m_text_len = 0;
        return mac;
    }

    KeyLengthSpecification keySpec() const { return KeyLengthSpecification(16); }

    override void clear()
    {
        zeroise(m_H);
        zeroise(m_H_ad);
        m_ghash.clear();
        m_text_len = m_ad_len = 0;
    }

    @property string name() const { return "GHASH"; }

    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_H[] = key[0 .. length];
        m_H_ad.resize(16);
        m_ad_len = 0;
        m_text_len = 0;
    }

private:
    void gcmMultiply(SecureVector!ubyte x) const
    {
        static if (BOTAN_HAS_GCM_CLMUL) {
            if (CPUID.hasClmul())
                return gcmMultiplyClmul(*cast(ubyte[16]*) x.ptr, *cast(ubyte[16]*) m_H.ptr);
        }
        
        __gshared immutable ulong R = 0xE100000000000000;

        ulong[2] H = [ loadBigEndian!ulong(m_H.ptr, 0), loadBigEndian!ulong(m_H.ptr, 1) ];
        
        ulong[2] Z = [ 0, 0 ];
        
        // SSE2 might be useful here
        
        foreach (size_t i; 0 .. 2)
        {
            const ulong X = loadBigEndian!ulong(x.ptr, i);
            
            foreach (size_t j; 0 .. 64)
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
        
        storeBigEndian!ulong(x.ptr, Z[0], Z[1]);
    }

    void ghashUpdate(SecureVector!ubyte ghash, const(ubyte)* input, size_t length)
    {
        __gshared immutable size_t BS = 16;
        
        /*
        This assumes if less than block size input then we're just on the
        final block and should pad with zeros
        */
        while (length)
        {
            const size_t to_proc = std.algorithm.min(length, BS);
            
            xorBuf(ghash.ptr, input, to_proc);
            
            gcmMultiply(ghash);
            
            input += to_proc;
            length -= to_proc;
        }
    }

    void addFinalBlock(SecureVector!ubyte hash,
                         size_t ad_len, size_t text_len)
    {
        SecureVector!ubyte final_block = SecureVector!ubyte(16);
        storeBigEndian!ulong(final_block.ptr, 8*ad_len, 8*text_len);
        ghashUpdate(hash, final_block.ptr, final_block.length);
    }

    SecureVector!ubyte m_H;
    SecureVector!ubyte m_H_ad;
    SecureVector!ubyte m_nonce;
    SecureVector!ubyte m_ghash;
    size_t m_ad_len = 0, m_text_len = 0;
}

void gcmMultiplyClmul(ref ubyte[16] x, in ubyte[16] H) pure
{
    /*
    * Algorithms 1 and 5 from Intel's CLMUL guide
    */
    __gshared immutable(__m128i) BSWAP_MASK = _mm_set1_epi8!([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])();

    __m128i a = _mm_loadu_si128(cast(const(__m128i)*) x);
    __m128i b = _mm_loadu_si128(cast(const(__m128i)*) H);
    
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
    
    _mm_storeu_si128(cast(__m128i*) x, T3);
}