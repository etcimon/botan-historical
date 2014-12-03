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
class EAXMode : AEAD_Mode
{
public:
    final override SecureVector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        m_nonce_mac = eax_prf(0, this.block_size, *m_cmac, nonce, nonce_len);
        
        m_ctr.setIv(m_nonce_mac.ptr, m_nonce_mac.length);
        
        for (size_t i = 0; i != this.block_size - 1; ++i)
            m_cmac.update(0);
        m_cmac.update(2);
        
        return SecureVector!ubyte();
    }


    final override void setAssociatedData(in ubyte* ad, size_t length)
    {
        m_ad_mac = eax_prf(1, this.block_size, *m_cmac, ad, length);
    }

    final override @property string name() const
    {
        return (m_cipher.name ~ "/EAX");
    }

    final override size_t updateGranularity() const
    {
        return 8 * m_cipher.parallelBytes();
    }

    final override KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    // EAX supports arbitrary nonce lengths
    final override bool validNonceLength(size_t) const { return true; }

    final override size_t tagSize() const { return m_tag_size; }

    final override void clear()
    {
        m_cipher.clear();
        m_ctr.clear();
        m_cmac.clear();
        zeroise(m_ad_mac);
        zeroise(m_nonce_mac);
    }

protected:
    final override void keySchedule(in ubyte* key, size_t length)
    {
        /*
        * These could share the key schedule, which is one nice part of EAX,
        * but it's much easier to ignore that here...
        */
        m_ctr.setKey(key, length);
        m_cmac.setKey(key, length);
        
        m_ad_mac = eax_prf(1, this.block_size, *m_cmac, null, 0);
    }

    /**
    * @param cipher = the cipher to use
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size) 
    {
        m_tag_size = tag_size ? tag_size : cipher.block_size;
        m_cipher = cipher;
        m_ctr = new CTRBE(m_cipher.clone());
        m_cmac = new CMAC(m_cipher.clone());
        if (m_tag_size < 8 || m_tag_size > m_cmac.output_length)
            throw new InvalidArgument(name ~ ": Bad tag size " ~ to!string(tag_size));
    }

    final @property size_t blockSize() const { return m_cipher.block_size; }

    size_t m_tag_size;

    Unique!BlockCipher m_cipher;
    Unique!StreamCipher m_ctr;
    Unique!MessageAuthenticationCode m_cmac;

    SecureVector!ubyte m_ad_mac;

    SecureVector!ubyte m_nonce_mac;
}

/**
* EAX Encryption
*/
final class EAXEncryption : EAX_Mode
{
public:
    /**
    * @param cipher = a 128-bit block cipher
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 0) 
    {
        super(cipher, tag_size);
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tag_size(); }

    override size_t minimumFinalSize() const { return 0; }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        m_ctr.cipher(buf, buf, sz);
        m_cmac.update(buf, sz);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset)
    {
        update(buffer, offset);
        
        SecureVector!ubyte data_mac = m_cmac.finished();
        xor_buf(data_mac, m_nonce_mac, data_mac.length);
        xor_buf(data_mac, m_ad_mac, data_mac.length);
        
        buffer += Pair(data_mac.ptr, tag_size());
    }
}

/**
* EAX Decryption
*/
final class EAXDecryption : EAX_Mode
{
public:
    /**
    * @param cipher = a 128-bit block cipher
    * @param tag_size = is how big the auth tag will be
    */
    this(BlockCipher cipher, size_t tag_size = 0) 
    {
        super(cipher, tag_size); 
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length > tag_size(), "Sufficient input");
        return input_length - tag_size();
    }

    override size_t minimumFinalSize() const { return tag_size(); }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        m_cmac.update(buf, sz);
        m_ctr.cipher(buf, buf, sz);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
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
        
        SecureVector!ubyte mac = m_cmac.finished();
        mac ^= m_nonce_mac;
        mac ^= m_ad_mac;
        
        if (!same_mem(mac.ptr, included_tag, tag_size()))
            throw new IntegrityFailure("EAX tag check failed");
        
        buffer.resize(offset + remaining);
    }
}


/*
* EAX MAC-based PRF
*/
SecureVector!ubyte eaxPrf(ubyte tag, size_t block_size,
                         MessageAuthenticationCode mac,
                         in ubyte* input,
                         size_t length) pure
{
    foreach (size_t i; 0 .. (block_size - 1))
        mac.update(0);
    mac.update(tag);
    mac.update(input, length);
    return mac.finished();
}