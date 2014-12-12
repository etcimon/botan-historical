/*
* CFB mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cfb;

import botan.constants;
static if (BOTAN_HAS_MODE_CFB):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.parsing;
import botan.utils.xor_buf;
import botan.utils.types;

/**
* CFB Mode
*/
class CFBMode : CipherMode, Transformation
{
public:
    final override SecureVector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name, nonce_len);
        
        m_shift_register[] = nonce[0 .. nonce_len];
        m_keystream_buf.reserve(m_shift_register.length);
        cipher().encrypt(m_shift_register, m_keystream_buf);
        
        return SecureVector!ubyte();
    }

    final override @property string name() const
    {
        if (feedback() == cipher().blockSize())
            return cipher().name ~ "/CFB";
        else
            return cipher().name ~ "/CFB(" ~ to!string(feedback()*8) ~ ")";
    }

    final override size_t updateGranularity() const
    {
        return feedback();
    }

    final override size_t minimumFinalSize() const
    {
        return 0;
    }

    final override KeyLengthSpecification keySpec() const
    {
        return cipher().keySpec();
    }

    final override size_t outputLength(size_t input_length) const
    {
        return input_length;
    }

    final override size_t defaultNonceLength() const
    {
        return cipher().blockSize();
    }

    final override bool validNonceLength(size_t n) const
    {
        return (n == cipher().blockSize());
    }

    final override void clear()
    {
        m_cipher.clear();
        m_shift_register.clear();
    }
protected:
    this(BlockCipher cipher, size_t feedback_bits)
    { 
        m_cipher = cipher;
        m_feedback_bytes = feedback_bits ? feedback_bits / 8 : cipher.blockSize();
        if (feedback_bits % 8 || feedback() > cipher.blockSize())
            throw new InvalidArgument(name() ~ ": feedback bits " ~
                                       to!string(feedback_bits) ~ " not supported");
    }

    final BlockCipher cipher() const { return *m_cipher; }

    final size_t feedback() const { return m_feedback_bytes; }

    final SecureVector!ubyte shiftRegister() { return m_shift_register; }

    final SecureVector!ubyte keystreamBuf() { return m_keystream_buf; }

protected:
    final override void keySchedule(in ubyte* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    SecureVector!ubyte m_shift_register;
    SecureVector!ubyte m_keystream_buf;
    size_t m_feedback_bytes;
}

/**
* CFB Encryption
*/
final class CFBEncryption : CFBMode, Transformation
{
public:
    this(BlockCipher cipher, size_t feedback_bits)
    {
        super(cipher, feedback_bits);
    }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().blockSize();
        
        SecureVector!ubyte state = shiftRegister();
        const size_t shift = feedback();
        
        while (sz)
        {
            const size_t took = std.algorithm.min(shift, sz);
            xorBuf(buf.ptr, &keystreamBuf()[0], took);
            
            // Assumes feedback-sized block except for last input
            copyMem(state.ptr, &state[shift], BS - shift);
            copyMem(&state[BS-shift], buf.ptr, took);
            cipher().encrypt(state, keystreamBuf());
            
            buf += took;
            sz -= took;
        }
    }


    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
    }
}

/**
* CFB Decryption
*/
final class CFBDecryption : CFBMode, Transformation
{
public:
    this(BlockCipher cipher, size_t feedback_bits) 
    {
        super(cipher, feedback_bits);
    }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().blockSize();
        
        SecureVector!ubyte state = shiftRegister();
        const size_t shift = feedback();
        
        while (sz)
        {
            const size_t took = std.algorithm.min(shift, sz);
            
            // first update shift register with ciphertext
            copyMem(state.ptr, &state[shift], BS - shift);
            copyMem(&state[BS-shift], buf.ptr, took);
            
            // then decrypt
            xorBuf(buf.ptr, &keystreamBuf()[0], took);
            
            // then update keystream
            cipher().encrypt(state, keystreamBuf());
            
            buf += took;
            sz -= took;
        }
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        update(buffer, offset);
    }

}