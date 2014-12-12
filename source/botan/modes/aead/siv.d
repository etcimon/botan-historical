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
class SIVMode : AEADMode, Transformation
{
public:
    final override SecureVector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        if (nonce_len)
            m_nonce = m_cmac.process(nonce, nonce_len);
        else
            m_nonce.clear();
        
        m_msg_buf.clear();
        
        return SecureVector!ubyte();
    }

    final override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        m_msg_buf.insert(m_msg_buf.end(), buf, buf + sz);
        buffer.reserve(offset); // truncate msg
    }

    final void setAssociatedDataN(size_t n, in ubyte* ad, size_t length)
    {
        if (n >= m_ad_macs.length)
            m_ad_macs.reserve(n+1);
        
        m_ad_macs[n] = m_cmac.process(ad, length);
    }

    final override void setAssociatedData(in ubyte* ad, size_t ad_len)
    {
        setAssociatedDataN(0, ad, ad_len);
    }

    final override @property string name() const
    {
        return m_name;
    }

    final override size_t updateGranularity() const
    {
        /*
        This value does not particularly matter as regardless update
        buffers all input, so in theory this could be 1. However as for instance
        TransformationFilter creates updateGranularity() ubyte buffers, use a
        somewhat large size to avoid bouncing on a tiny buffer.
        */
        return 128;
    }

    final override KeyLengthSpecification keySpec() const
    {
        return m_cmac.keySpec().multiple(2);
    }

    final override bool validNonceLength(size_t) const
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

    final override size_t tagSize() const { return 16; }

protected:
    this(BlockCipher cipher) 
    {
        m_name = cipher.name ~ "/SIV";
        m_ctr = new CTRBE(cipher.clone());
        m_cmac = new CMAC(cipher);
    }

    final StreamCipher ctr() { return *m_ctr; }

    final void setCtrIv(SecureVector!ubyte V)
    {
        V[8] &= 0x7F;
        V[12] &= 0x7F;
        
        ctr().setIv(V.ptr, V.length);
    }

    final SecureVector!ubyte msgBuf() { return m_msg_buf; }

    final SecureVector!ubyte S2V(in ubyte* text, size_t text_len)
    {
        const ubyte[16] zero;
        
        SecureVector!ubyte V = cmac().process(zero, 16);
        
        for (size_t i = 0; i != m_ad_macs.length; ++i)
        {
            V = CMAC.polyDouble(V);
            V ^= m_ad_macs[i];
        }
        
        if (m_nonce.length)
        {
            V = CMAC.polyDouble(V);
            V ^= m_nonce;
        }
        
        if (text_len < 16)
        {
            V = CMAC.polyDouble(V);
            xorBuf(V.ptr, text, text_len);
            V[text_len] ^= 0x80;
            return cmac().process(V);
        }
        
        cmac().update(text, text_len - 16);
        xorBuf(V.ptr, &text[text_len - 16], 16);
        cmac().update(V);
        
        return cmac().finished();
    }
protected:
    final MessageAuthenticationCode cmac() { return *m_cmac; }

    final override void keySchedule(in ubyte* key, size_t length)
    {
        const size_t keylen = length / 2;
        m_cmac.setKey(key, keylen);
        m_ctr.setKey(key + keylen, keylen);
        m_ad_macs.clear();
    }

private:

    const string m_name;

    Unique!StreamCipher m_ctr;
    Unique!MessageAuthenticationCode m_cmac;
    SecureVector!ubyte m_nonce, m_msg_buf;
    Vector!( SecureVector!ubyte ) m_ad_macs;
}

/**
* SIV Encryption
*/
final class SIVEncryption : SIVMode, Transformation
{
public:
    /**
    * @param cipher = a block cipher
    */
    this(BlockCipher cipher)
    {
        super(cipher);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        
        buffer.insert(buffer.ptr + offset, msgBuf().ptr, msgBuf().end());
        
        SecureVector!ubyte V = S2V(&buffer[offset], buffer.length - offset);
        
        buffer.insert(buffer.ptr + offset, V.ptr, V.end());
        
        setCtrIv(V);
        ctr().cipher1(&buffer[offset + V.length], buffer.length - offset - V.length);
    }

    override size_t outputLength(size_t input_length) const
    { return input_length + tagSize(); }

    override size_t minimumFinalSize() const { return 0; }
}

/**
* SIV Decryption
*/
final class SIVDecryption : SIVMode, Transformation
{
public:
    /**
    * @param cipher = a 128-bit block cipher
    */
    this(BlockCipher cipher)
    {
        super(cipher);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        
        buffer.insert(buffer.ptr + offset, msgBuf().ptr, msgBuf().end());
        
        const size_t sz = buffer.length - offset;
        
        assert(sz >= tagSize(), "We have the tag");

        SecureVector!ubyte V = SecureVector!ubyte(buffer.ptr[offset .. offset + 16]);
        
        setCtrIv(V);
        
        ctr().cipher(&buffer[offset + V.length], &buffer[offset], buffer.length - offset - V.length);
        
        SecureVector!ubyte T = S2V(&buffer[offset], buffer.length - offset - V.length);
        
        if (T != V)
            throw new IntegrityFailure("SIV tag check failed");
        
        buffer.reserve(buffer.length - tagSize());
    }

    override size_t outputLength(size_t input_length) const
    {
        assert(input_length > tagSize(), "Sufficient input");
        return input_length - tagSize();
    }

    override size_t minimumFinalSize() const { return tagSize(); }
}