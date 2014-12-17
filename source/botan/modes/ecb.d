/*
* ECB Mode
* (C) 1999-2009,2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.ecb;

import botan.constants;
static if (BOTAN_HAS_MODE_ECB):

import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.modes.mode_pad;
import botan.utils.loadstor;
import botan.utils.xor_buf;
import botan.utils.rounding;
import botan.utils.types;

/**
* ECB mode
*/
class ECBMode : CipherMode, Transformation
{
public:
    final override SecureVector!ubyte start(const(ubyte)*, size_t nonce_len)
    {
        if (!validNonceLength(nonce_len))
            throw new InvalidIVLength(name(), nonce_len);
        
        return SecureVector!ubyte();
    }

    final override @property string name() const
    {
        return cipher().name ~ "/ECB/" ~ padding().name;
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
        return 0;
    }

    final override bool validNonceLength(size_t n) const
    {
        return (n == 0);
    }

    final override void clear()
    {
        m_cipher.clear();
    }

    final override bool authenticated() const { return true; }
protected:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
    {
        m_cipher = cipher;
        m_padding = padding;
        if (!m_padding.validBlocksize(cipher.blockSize()))
            throw new InvalidArgument("Padding " ~ m_padding.name ~ " cannot be used with " ~ cipher.name ~ "/ECB");
    }

    final BlockCipher cipher() const { return *m_cipher; }

    final BlockCipherModePaddingMethod padding() const { return *m_padding; }

protected:
    final override void keySchedule(const(ubyte)* key, size_t length)
    {
        m_cipher.setKey(key, length);
    }

    Unique!BlockCipher m_cipher;
    Unique!BlockCipherModePaddingMethod m_padding;
}

/**
* ECB Encryption
*/
final class ECBEncryption : ECBMode, Transformation
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding) 
    {
        super(cipher, padding);
    }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "ECB input is full blocks");
        const size_t blocks = sz / BS;
        
        cipher().encryptN(buf, buf, blocks);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        const size_t bytes_in_final_block = sz % BS;
        
        padding().addPadding(buffer, bytes_in_final_block, BS);
        
        if (buffer.length % BS)
            throw new Exception("Did not pad to full block size in " ~ name);
        
        update(buffer, offset);
    }

    override size_t outputLength(size_t input_length) const
    {
        return roundUp(input_length, cipher().blockSize());
    }

    override size_t minimumFinalSize() const
    {
        return 0;
    }
}

/**
* ECB Decryption
*/
final class ECBDecryption : ECBMode, Transformation
{
public:
    this(BlockCipher cipher, BlockCipherModePaddingMethod padding)
    {
        super(cipher, padding);
    }

    override void update(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        ubyte* buf = &buffer[offset];
        
        const size_t BS = cipher().blockSize();
        
        assert(sz % BS == 0, "Input is full blocks");
        size_t blocks = sz / BS;
        
        cipher().decryptN(buf, buf, blocks);
    }

    override void finish(SecureVector!ubyte buffer, size_t offset = 0)
    {
        assert(buffer.length >= offset, "Offset is sane");
        const size_t sz = buffer.length - offset;
        
        const size_t BS = cipher().blockSize();
        
        if (sz == 0 || sz % BS)
            throw new DecodingError(name ~ ": Ciphertext not a multiple of block size");
        
        update(buffer, offset);
        
        const size_t pad_bytes = BS - padding().unpad(&buffer[buffer.length-BS], BS);
        buffer.resize(buffer.length - pad_bytes); // remove padding
    }

    override size_t outputLength(size_t input_length) const
    {
        return input_length;
    }

    override size_t minimumFinalSize() const
    {
        return cipher().blockSize();
    }
}