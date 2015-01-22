/*
* PKCS #1 v1.5 signature padding
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pk_pad.emsa_pkcs1;

import botan.constants;
static if (BOTAN_HAS_EMSA_PKCS1):

import botan.pk_pad.emsa;
import botan.hash.hash;
import botan.pk_pad.emsa_pkcs1;
import botan.pk_pad.hash_id;
import botan.utils.types;
import botan.utils.mem_ops;
import std.algorithm : swap;

/**
* PKCS #1 v1.5 signature padding
* aka PKCS #1 block type 1
* aka EMSA3 from IEEE 1363
*/
final class EMSAPKCS1v15 : EMSA
{
public:
    /**
    * @param hash = the hash object to use
    */
    this(HashFunction hash)
    {
        m_hash = hash;
        m_hash_id = pkcsHashId(m_hash.name);
    }

    override void update(const(ubyte)* input, size_t length)
    {
        m_hash.update(input, length);
    }

    override SecureArray!ubyte rawData()
    {
        return m_hash.finished();
    }

    override SecureArray!ubyte
        encodingOf(const ref SecureArray!ubyte msg,
                    size_t output_bits,
                    RandomNumberGenerator)
    {
        if (msg.length != m_hash.outputLength)
            throw new EncodingError("encodingOf: Bad input length");
        
        return emsa3Encoding(msg, output_bits,
                              m_hash_id.ptr, m_hash_id.length);
    }

    override bool verify(const ref SecureArray!ubyte coded,
                         const ref SecureArray!ubyte raw,
                         size_t key_bits)
    {
        if (raw.length != m_hash.outputLength)
            return false;
        
        try
        {
            return (coded == emsa3Encoding(raw, key_bits,
                                            m_hash_id.ptr, m_hash_id.length));
        }
        catch (Throwable)
        {
            return false;
        }
    }
private:
    Unique!HashFunction m_hash;
    Vector!ubyte m_hash_id;
}

/**
* EMSA_PKCS1v15_Raw which is EMSA_PKCS1v15 without a hash or digest id
* (which according to QCA docs is "identical to PKCS#11's CKM_RSA_PKCS
* mechanism", something I have not confirmed)
*/
final class EMSAPKCS1v15Raw : EMSA
{
public:
    override void update(const(ubyte)* input, size_t length)
    {
        m_message ~= input[0 .. length];
    }

    override SecureArray!ubyte rawData()
    {
		return m_message;
    }

	override SecureArray!ubyte encodingOf(const ref SecureArray!ubyte msg,
                                          size_t output_bits,
                                          RandomNumberGenerator)
    {
        return emsa3Encoding(msg, output_bits, null, 0);
    }

	override bool verify(const ref SecureArray!ubyte coded,
						 const ref SecureArray!ubyte raw,
                         size_t key_bits)
    {
        try
        {
            return (coded == emsa3Encoding(raw, key_bits, null, 0));
        }
        catch (Throwable)
        {
            return false;
        }
    }

private:
	SecureArray!ubyte m_message;
}

private:

SecureArray!ubyte emsa3Encoding(const ref SecureArray!ubyte msg,
                                size_t output_bits,
                                const(ubyte)* hash_id,
                                size_t hash_id_length)
{
    size_t output_length = output_bits / 8;
    if (output_length < hash_id_length + msg.length + 10)
        throw new EncodingError("emsa3Encoding: Output length is too small");
    
    SecureArray!ubyte T = SecureArray!ubyte(output_length);
    const size_t P_LENGTH = output_length - msg.length - hash_id_length - 2;
    
    T[0] = 0x01;
    setMem(&T[1], P_LENGTH, 0xFF);
    T[P_LENGTH+1] = 0x00;
    bufferInsert(T, P_LENGTH+2, hash_id, hash_id_length);
    bufferInsert(T, output_length-msg.length, msg.ptr, msg.length);
    return T;
}