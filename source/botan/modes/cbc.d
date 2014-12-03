/*
* CBC mode
* (C) 1999-2007,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cbc;

import botan.constants;
static if (BOTAN_HAS_MODE_CBC):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;

/**
* CBC Mode
*/
class CBCMode : Cipher_Mode
{
public:
    final override SecureVector!ubyte start(in ubyte* nonce, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);
        
        /*
        * A nonce of zero length means carry the last ciphertext value over
        * as the new IV, as unfortunately some protocols require this. If
        * this is the first message then we use an IV of all zeros.
        */
        if (nonce_len)
            m_state.replace(nonce[0 .. nonce + nonce_len]);
        
        return SecureVector!ubyte();
    }

    final override @property string name() const
    {
        if (m_padding)
            return cipher().name ~ "/CBC/" ~ padding().name;
        else
            return cipher().name ~ "/CBC/CTS";
    }

    final override size_t updateGranularity() const
    {
        return cipher().parallelBytes();
    }

    final override KeyLengthSpecification keySpec() const
    {
        return cipher().keySpec();
    }

    final override size_t defaultNonceLength() const
    {
        return cipher().block_size;
    }

    final override bool validNonceLength(size_t n) const
    {
        return (n == 0 || n == cipher().block_size);
    }

    final override void clear()
    {
        m_cipher.clear();
        m_state.clear();
    }
protected:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
    {
        m_cipher = cipher;
        m_padding = padding;
        m_state = m_cipher.block_size;
        if (m_padding && !m_padding.validBlocksize(cipher.block_size))
            throw new InvalidArgument("Padding " ~ m_padding.name ~ " cannot be used with " ~ cipher.name ~ "/CBC");
    }

    final BlockCipher cipher() const { return *m_cipher; }

    final BlockCipherModePaddingMethod padding() const
    {
        assert(m_padding, "No padding defined");
        return *m_padding;
    }

    final SecureVector!ubyte state() { return m_state; }

    final ubyte* statePtr() { return m_state.ptr; }

private:
    final override void keySchedule(in ubyte* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    Unique!BlockCipherModePaddingMethod m_padding;
    SecureVector!ubyte m_state;
}

/**
* CBC Encryption
*/
class CBCEncryption : CBC_Mode
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
    {
        super(cipher, padding);
    }

    final override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().block_size;
        
        assert(sz % BS == 0, "CBC input is full blocks");
        const size_t blocks = sz / BS;
        
        const ubyte* prev_block = state_ptr();
        
        if (blocks)
        {
            foreach (size_t i; 0 .. blocks)
            {
                xor_buf(&buf[BS*i], prev_block, BS);
                cipher().encrypt(&buf[BS*i]);
                prev_block = &buf[BS*i];
            }
            
            state().replace(buf.ptr[BS*(blocks-1) .. BS*blocks]);
        }
    }


    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        
        const size_t BS = cipher().block_size;
        
        const size_t bytes_in_final_block = (buffer.length-offset) % BS;
        
        padding().addPadding(buffer, bytes_in_final_block, BS);
        
        if ((buffer.length-offset) % BS)
            throw new Exception("Did not pad to full block size in " ~ name);
        
        update(buffer, offset);
    }

    override size_t outputLength(size_t input_length) const
    {
        return round_up(input_length, cipher().block_size);
    }

    override size_t minimumFinalSize() const
    {
        return 0;
    }
}

/**
* CBC Encryption with ciphertext stealing (CBC-CS3 variant)
*/
final class CTSEncryption : CBC_Encryption
{
public:
    this(BlockCipher cipher)
    {
        super(cipher, null);
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length; // no ciphertext expansion in CTS
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        ubyte* buf = &buffer[offset];
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().block_size;
        
        if (sz < BS + 1)
            throw new EncodingError(name() ~ ": insufficient data to encrypt");
        
        if (sz % BS == 0)
        {
            update(buffer, offset);
            
            // swap last two blocks
            foreach (size_t i; 0 .. BS)
                std.algorithm.swap(buffer[buffer.length-BS+i], buffer[buffer.length-2*BS+i]);
        }
        else
        {
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            
            SecureVector!ubyte last = SecureVector!ubyte(buf + full_blocks, buf + full_blocks + final_bytes);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            xor_buf(last.ptr, state_ptr(), BS);
            cipher().encrypt(last.ptr);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
            {
                last[i] ^= last[i + BS];
                last[i + BS] ^= last[i];
            }
            
            cipher().encrypt(last.ptr);
            
            buffer += last;
        }
    }

    override size_t minimumFinalSize() const
    {
        return cipher().block_size + 1;
    }

    bool validNonceLength(size_t n) const
    {
        return (n == cipher().block_size);
    }

}

/**
* CBC Decryption
*/
class CBCDecryption : CBC_Mode
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)  
    {
        super(cipher, padding);
        m_tempbuf = updateGranularity();
    }

    final override void update(SecureVector!ubyte buffer, size_t offset)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().block_size;
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        while (blocks)
        {
            const size_t to_proc = std.algorithm.min(BS * blocks, m_tempbuf.length);
            
            cipher().decryptN(buf, m_tempbuf.ptr, to_proc / BS);
            
            xor_buf(m_tempbuf.ptr, state_ptr(), BS);
            xor_buf(&m_tempbuf[BS], buf, to_proc - BS);
            copyMem(state_ptr(), buf + (to_proc - BS), BS);
            
            copyMem(buf, m_tempbuf.ptr, to_proc);
            
            buf += to_proc;
            blocks -= to_proc / BS;
        }
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().block_size;
        
        if (sz == 0 || sz % BS)
            throw new DecodingError(name() ~ ": Ciphertext not a multiple of block size");
        
        update(buffer, offset);
        
        const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.length-BS], BS);
        buffer.resize(buffer.length - pad_bytes); // remove padding
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length; // precise for CTS, worst case otherwise
    }

    override size_t minimumFinalSize() const
    {
        return cipher().block_size;
    }     
private:
    SecureVector!ubyte m_tempbuf;
}

/**
* CBC Decryption with ciphertext stealing (CBC-CS3 variant)
*/
final class CTSDecryption : CBC_Decryption
{
public:
    this(BlockCipher cipher)
    {
        super(cipher, null);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().block_size;
        
        if (sz < BS + 1)
            throw new EncodingError(name() ~ ": insufficient data to decrypt");
        
        if (sz % BS == 0)
        {
            // swap last two blocks
            
            foreach (size_t i; 0 .. BS)
                std.algorithm.swap(buffer[buffer.length-BS+i], buffer[buffer.length-2*BS+i]);
            
            update(buffer, offset);
        }
        else
        {
            const size_t full_blocks = ((sz / BS) - 1) * BS;
            const size_t final_bytes = sz - full_blocks;
            assert(final_bytes > BS && final_bytes < 2*BS, "Left over size in expected range");
            
            SecureVector!ubyte last = SecureVector!ubyte(buf + full_blocks, buf + full_blocks + final_bytes);
            buffer.resize(full_blocks + offset);
            update(buffer, offset);
            
            cipher().decrypt(last.ptr);
            
            xor_buf(last.ptr, &last[BS], final_bytes - BS);
            
            foreach (size_t i; 0 .. (final_bytes - BS))
                std.algorithm.swap(last[i], last[i + BS]);
            
            cipher().decrypt(last.ptr);
            xor_buf(last.ptr, state_ptr(), BS);
            
            buffer += last;
        }
    }


    override size_t minimumFinalSize() const
    {
        return cipher().block_size + 1;
    }

    bool validNonceLength(size_t n) const
    {
        return (n == cipher().block_size);
    }
}