/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.ofb;

import botan.constants;
static if (BOTAN_HAS_OFB):

import botan.stream.stream_cipher;
import botan.block.block_cipher;
import botan.utils.xor_buf;

/**
* Output Feedback Mode
*/
final class OFB : StreamCipher, SymmetricAlgorithm
{
public:
    override void cipher(const(ubyte)* input, ubyte* output, size_t length)
    {
        while (length >= m_buffer.length - m_buf_pos)
        {
            xorBuf(output, input, &m_buffer[m_buf_pos], m_buffer.length - m_buf_pos);
            length -= (m_buffer.length - m_buf_pos);
            input += (m_buffer.length - m_buf_pos);
            output += (m_buffer.length - m_buf_pos);
            m_cipher.encrypt(m_buffer);
            m_buf_pos = 0;
        }
        xorBuf(output, input, &m_buffer[m_buf_pos], length);
        m_buf_pos += length;
    }

    override void setIv(const(ubyte)* iv, size_t iv_len)
    {
        if (!validIvLength(iv_len))
            throw new InvalidIVLength(name, iv_len);
        
        zeroise(m_buffer);
        bufferInsert(m_buffer, 0, iv, iv_len);
        
        m_cipher.encrypt(m_buffer);
        m_buf_pos = 0;
    }

    override bool validIvLength(size_t iv_len) const
    { return (iv_len <= m_cipher.blockSize()); }

    KeyLengthSpecification keySpec() const
    {
        return m_cipher.keySpec();
    }

    @property string name() const
    {
        return "OFB(" ~ m_cipher.name ~ ")";
    }

    override OFB clone() const
    { return new OFB(m_cipher.clone()); }

    void clear()
    {
        m_cipher.clear();
        zeroise(m_buffer);
        m_buf_pos = 0;
    }

    /**
    * @param cipher = the underlying block cipher to use
    */
    this(BlockCipher cipher)
    {
        m_cipher = cipher;
        m_buffer = m_cipher.blockSize();
        m_buf_pos = 0;
    }
protected:
    override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, key_len);
        
        // Set a default all-zeros IV
        setIv(null, 0);
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_buffer;
    size_t m_buf_pos;
}