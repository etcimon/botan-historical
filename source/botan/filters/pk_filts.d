/*
* PK Filters
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.pk_filts;

import botan.filters.filter;
import botan.pubkey.pubkey;
import botan.rng.rng;

/**
* PKEncryptor Filter
*/
final class PKEncryptorFilter : Filter
{
public:
    /*
    * Append to the buffer
    */
    void write(in ubyte* input, size_t length)
    {
        m_buffer ~= input[0 .. length];
    }
    /*
    * Encrypt the message
    */
    void endMsg()
    {
        send(m_cipher.encrypt(buffer, m_rng));
        m_buffer.clear();
    }

    this(    PKEncryptor c,
            RandomNumberGenerator rng_ref) 
    {
        m_cipher = c;
        m_rng = rng_ref;
    }

    ~this() { delete cipher; }
private:
    PKEncryptor m_cipher;
    RandomNumberGenerator m_rng;
    SecureVector!ubyte m_buffer;
}

/**
* PKDecryptor Filter
*/
final class PKDecryptorFilter : Filter
{
public:
    /*
    * Append to the buffer
    */
    void write(in ubyte* input, size_t length)
    {
        m_buffer ~= input[0 .. length];
    }

    /*
    * Decrypt the message
    */
    void endMsg()
    {
        send(m_cipher.decrypt(m_buffer));
        m_buffer.clear();
    }

    this(PKDecryptor c) {  m_cipher = c; }
    ~this() { delete m_cipher; }
private:
    PKDecryptor m_cipher;
    SecureVector!ubyte m_buffer;
}

/**
* PKSigner Filter
*/
final class PKSignerFilter : Filter
{
public:
    /*
    * Add more data
    */
    void write(in ubyte* input, size_t length)
    {
        m_signer.update(input, length);
    }

    /*
    * Sign the message
    */
    void endMsg()
    {
        send(m_signer.signature(m_rng));
    }


    this(ref PKSigner s,
         RandomNumberGenerator rng_ref)
    {
        signer = &s;
        rng = rng_ref;
    }

    ~this() {  }
private:
    PKSigner* m_signer;
    RandomNumberGenerator m_rng;
}

/**
* PKVerifier Filter
*/
final class PKVerifierFilter : Filter
{
public:
    /*
    * Add more data
    */
    void write(in ubyte* input, size_t length)
    {
        m_verifier.update(input, length);
    }
    
    /*
    * Verify the message
    */
    void endMsg()
    {
        if (m_signature.empty)
            throw new InvalidState("PKVerifierFilter: No signature to check against");
        bool is_valid = verifier.checkSignature(m_signature);
        send((is_valid ? 1 : 0));
    }

    /*
    * Set the signature to check
    */
    void setSignature(in ubyte* sig, size_t length)
    {
        m_signature.replace(sig[0 .. sig + length]);
    }
    
    /*
    * Set the signature to check
    */
    void setSignature(in SecureVector!ubyte sig)
    {
        m_signature = sig;
    }
    


    this(ref PKVerifier v) { verifier = v; }
    /*
    * PKVerifierFilter Constructor
    */
    this(ref PKVerifier v, in ubyte* sig,
         size_t length)
    {
        verifier = v;
        m_signature = SecureVector!ubyte(sig, sig + length);
    }
    
    /*
    * PKVerifierFilter Constructor
    */
    this(ref PKVerifier v,
         in SecureVector!ubyte sig) 
    {
        m_verifier = &v;
        m_signature = sig;
    }

    ~this() {  }
private:
    PKVerifier m_verifier;
    SecureVector!ubyte m_signature;
}