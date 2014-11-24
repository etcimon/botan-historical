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
* PK_Encryptor Filter
*/
final class PK_Encryptor_Filter : Filter
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
    void end_msg()
    {
        send(m_cipher.encrypt(buffer, m_rng));
        m_buffer.clear();
    }

    this(    PK_Encryptor c,
            RandomNumberGenerator rng_ref) 
    {
        m_cipher = c;
        m_rng = rng_ref;
    }

    ~this() { delete cipher; }
private:
    PK_Encryptor m_cipher;
    RandomNumberGenerator m_rng;
    Secure_Vector!ubyte m_buffer;
}

/**
* PK_Decryptor Filter
*/
final class PK_Decryptor_Filter : Filter
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
    void end_msg()
    {
        send(m_cipher.decrypt(m_buffer));
        m_buffer.clear();
    }

    this(PK_Decryptor c) {  m_cipher = c; }
    ~this() { delete m_cipher; }
private:
    PK_Decryptor m_cipher;
    Secure_Vector!ubyte m_buffer;
}

/**
* PK_Signer Filter
*/
final class PK_Signer_Filter : Filter
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
    void end_msg()
    {
        send(m_signer.signature(m_rng));
    }


    this(ref PK_Signer s,
         RandomNumberGenerator rng_ref)
    {
        signer = &s;
        rng = rng_ref;
    }

    ~this() {  }
private:
    PK_Signer* m_signer;
    RandomNumberGenerator m_rng;
}

/**
* PK_Verifier Filter
*/
final class PK_Verifier_Filter : Filter
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
    void end_msg()
    {
        if (m_signature.empty)
            throw new Invalid_State("PK_Verifier_Filter: No signature to check against");
        bool is_valid = verifier.check_signature(m_signature);
        send((is_valid ? 1 : 0));
    }

    /*
    * Set the signature to check
    */
    void set_signature(in ubyte* sig, size_t length)
    {
        m_signature.replace(sig[0 .. sig + length]);
    }
    
    /*
    * Set the signature to check
    */
    void set_signature(in Secure_Vector!ubyte sig)
    {
        m_signature = sig;
    }
    


    this(ref PK_Verifier v) { verifier = v; }
    /*
    * PK_Verifier_Filter Constructor
    */
    this(ref PK_Verifier v, in ubyte* sig,
         size_t length)
    {
        verifier = v;
        m_signature = Secure_Vector!ubyte(sig, sig + length);
    }
    
    /*
    * PK_Verifier_Filter Constructor
    */
    this(ref PK_Verifier v,
         in Secure_Vector!ubyte sig) 
    {
        m_verifier = &v;
        m_signature = sig;
    }

    ~this() {  }
private:
    PK_Verifier m_verifier;
    Secure_Vector!ubyte m_signature;
}