/*
* PKCS #5 v2.0 PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbe.pbes2;

import botan.constants;
static if (BOTAN_HAS_PBE_PKCS_V20):

import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.pbe.pbe;
import botan.block.block_cipher;
import botan.mac.mac;
import botan.filters.pipe;
import botan.pbkdf.pbkdf2;
import botan.algo_factory.algo_factory;
import botan.libstate.libstate;
import botan.libstate.lookup;
import botan.utils.parsing;
import botan.utils.types;
import std.datetime;
import std.algorithm;

/**
* PKCS #5 v2.0 PBE
*/
final class PBE_PKCS5v20 : PBE
{
public:
    /*
    * Return an OID for PBES2
    */
    OID get_oid() const
    {
        return OIDS.lookup("PBE-PKCS5v20");
    }

    /*
    * Encode PKCS#5 PBES2 parameters
    */
    Vector!ubyte encode_params() const
    {
        return DER_Encoder()
                   .start_cons(ASN1_Tag.SEQUENCE)
                .encode(Algorithm_Identifier("PKCS5.PBKDF2",
                        DER_Encoder()
                               .start_cons(ASN1_Tag.SEQUENCE)
                               .encode(salt, ASN1_Tag.OCTET_STRING)
                               .encode(m_iterations)
                             .encode(m_key_length)
                               .encode_if ( m_prf.name != "HMAC(SHA-160)",
                                            Algorithm_Identifier(m_prf.name,
                                                                   Algorithm_Identifier.USE_NULL_PARAM))
                              .end_cons()
                               .get_contents_unlocked()
                         )
                 )
                .encode(
                    Algorithm_Identifier(block_cipher.name ~ "/CBC",
                                         DER_Encoder().encode(m_iv, ASN1_Tag.OCTET_STRING).get_contents_unlocked())
                 )
                .end_cons()
                .get_contents_unlocked();
    }

    @property string name() const
    {
        return "PBE-PKCS5v20(" ~ m_block_cipher.name ~ "," ~ m_prf.name ~ ")";
    }

    /*
    * Encrypt some bytes using PBES2
    */
    void write(in ubyte* input, size_t length)
    {
        m_pipe.write(input, length);
        flush_pipe(true);
    }

    /*
    * Start encrypting with PBES2
    */
    void start_msg()
    {
        m_pipe.append(get_cipher(m_block_cipher.name ~ "/CBC/PKCS7",
                               m_key, m_iv, m_direction));
        
        m_pipe.start_msg();
        if (m_pipe.message_count() > 1)
            m_pipe.set_default_msg(m_pipe.default_msg() + 1);
    }

    /*
    * Finish encrypting with PBES2
    */
    void end_msg()
    {
        m_pipe.end_msg();
        flush_pipe(false);
        m_pipe.clear();
    }

    /**
    * Load a PKCS #5 v2.0 encrypted stream
    * @param params the PBES2 parameters
    * @param passphrase the passphrase to use for decryption
    */
    this(in Vector!ubyte params, in string passphrase) 
    {
        m_direction = DECRYPTION;
        m_block_cipher = null;
        m_prf = null;
        Algorithm_Identifier kdf_algo, enc_algo;
        
        BER_Decoder(params)
                .start_cons(ASN1_Tag.SEQUENCE)
                .decode(kdf_algo)
                .decode(enc_algo)
                .verify_end()
                .end_cons();
        
        Algorithm_Identifier prf_algo;
        
        if (kdf_algo.oid != OIDS.lookup("PKCS5.PBKDF2"))
            throw new Decoding_Error("PBE-PKCS5 v2.0: Unknown KDF algorithm " ~ kdf_algo.oid.toString());
        
        BER_Decoder(kdf_algo.parameters)
                .start_cons(ASN1_Tag.SEQUENCE)
                .decode(m_salt, ASN1_Tag.OCTET_STRING)
                .decode(m_iterations)
                .decode_optional(m_key_length, INTEGER, ASN1_Tag.UNIVERSAL)
                .decode_optional(prf_algo, ASN1_Tag.SEQUENCE, ASN1_Tag.CONSTRUCTED,
                                 Algorithm_Identifier("HMAC(SHA-160)",
                                 Algorithm_Identifier.USE_NULL_PARAM))
                .verify_end()
                .end_cons();
        
        Algorithm_Factory af = global_state().algorithm_factory();
        
        string cipher = OIDS.lookup(enc_algo.oid);
        Vector!string cipher_spec = splitter(cipher, '/');
        if (cipher_spec.length != 2)
            throw new Decoding_Error("PBE-PKCS5 v2.0: Invalid cipher spec " ~ cipher);
        
        if (cipher_spec[1] != "CBC")
            throw new Decoding_Error("PBE-PKCS5 v2.0: Don't know param format for " ~ cipher);
        
        BER_Decoder(enc_algo.parameters).decode(m_iv, ASN1_Tag.OCTET_STRING).verify_end();
        
        m_block_cipher = af.make_block_cipher(cipher_spec[0]);
        m_prf = af.make_mac(OIDS.lookup(prf_algo.oid));
        
        if (m_key_length == 0)
            m_key_length = m_block_cipher.maximum_keylength();
        
        if (m_salt.length < 8)
            throw new Decoding_Error("PBE-PKCS5 v2.0: Encoded salt is too small");
        
        PKCS5_PBKDF2 pbkdf(m_prf.clone());
        
        m_key = pbkdf.derive_key(m_key_length, passphrase,
                                    m_salt.ptr, m_salt.length,
                                 m_iterations).bits_of();
    }

    /**
    * @param cipher the block cipher to use
    * @param mac the MAC to use
    * @param passphrase the passphrase to use for encryption
    * @param msec how many milliseconds to run the PBKDF
    * @param rng a random number generator
    */
    this(BlockCipher cipher,
         MessageAuthenticationCode mac,
         in string passphrase,
         Duration msec,
         RandomNumberGenerator rng) 
    {
        m_direction = ENCRYPTION;
        m_block_cipher = cipher;
        m_prf = mac;
        m_salt = rng.random_vec(12);
        m_iv = rng.random_vec(m_block_cipher.block_size);
        m_iterations = 0;
        m_key_length = m_block_cipher.maximum_keylength();
        PKCS5_PBKDF2 pbkdf = PKCS5_PBKDF2(m_prf.clone());
        
        m_key = pbkdf.derive_key(m_key_length, passphrase,
                                   m_salt.ptr, m_salt.length,
                                 msec, m_iterations).bits_of();
    }

private:
    /*
    * Flush the pipe
    */
    void flush_pipe(bool safe_to_skip)
    {
        if (safe_to_skip && m_pipe.remaining() < 64)
            return;
        
        Secure_Vector!ubyte buffer = Secure_Vector!ubyte(DEFAULT_BUFFERSIZE);
        while (m_pipe.remaining())
        {
            const size_t got = m_pipe.read(buffer.ptr, buffer.length);
            send(buffer, got);
        }
    }

    Cipher_Dir m_direction;
    Unique!BlockCipher m_block_cipher;
    Unique!MessageAuthenticationCode m_prf;
    Secure_Vector!ubyte m_salt, m_key, m_iv;
    size_t m_iterations, m_key_length;
    Pipe m_pipe;
}