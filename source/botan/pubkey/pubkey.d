/*
* Public Key Interface
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pubkey;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.utils.types;
public import botan.pubkey.pk_keys;
public import botan.pubkey.pk_ops;
public import botan.algo_base.symkey;
public import botan.utils.types;
public import botan.rng.rng;
import botan.pk_pad.eme;
import botan.pk_pad.emsa;
import botan.kdf.kdf;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import botan.libstate.libstate;
import botan.engine.engine;
import botan.utils.bit_ops;
import botan.utils.exceptn;

alias SignatureFormat = bool;
/**
* The two types of signature format supported by Botan.
*/
enum : SignatureFormat { IEEE_1363, DER_SEQUENCE }

alias FaultProtection = bool;
/**
* Enum marking if protection against fault attacks should be used
*/
enum : FaultProtection {
    ENABLE_FAULT_PROTECTION,
    DISABLE_FAULT_PROTECTION
}

/**
* Public Key Encryptor
*/
class PKEncryptor
{
public:

    /**
    * Encrypt a message.
    * @param input = the message as a ubyte array
    * @param length = the length of the above ubyte array
    * @param rng = the random number source to use
    * @return encrypted message
    */
    Vector!ubyte encrypt(in ubyte* input, size_t length, RandomNumberGenerator rng) const
    {
        return enc(input, length, rng);
    }

    /**
    * Encrypt a message.
    * @param input = the message
    * @param rng = the random number source to use
    * @return encrypted message
    */
    Vector!ubyte encrypt(Alloc)(in Vector!( ubyte, Alloc ) input, RandomNumberGenerator rng) const
    {
        return enc(input.ptr, input.length, rng);
    }

    /**
    * Return the maximum allowed message size in bytes.
    * @return maximum message size in bytes
    */
    abstract size_t maximumInputSize() const;

    this() {}
    ~this() {}

protected:
    abstract Vector!ubyte enc(in ubyte*, size_t, RandomNumberGenerator) const;
}

/**
* Public Key Decryptor
*/
class PKDecryptor
{
public:
    /**
    * Decrypt a ciphertext.
    * @param input = the ciphertext as a ubyte array
    * @param length = the length of the above ubyte array
    * @return decrypted message
    */
    SecureVector!ubyte decrypt(in ubyte* input, size_t length) const
    {
        return dec(input, length);
    }

    /**
    * Decrypt a ciphertext.
    * @param input = the ciphertext
    * @return decrypted message
    */
    SecureVector!ubyte decrypt(Alloc)(in Vector!( ubyte, Alloc ) input) const
    {
        return dec(input.ptr, input.length);
    }

    this() {}
    ~this() {}

protected:
    abstract SecureVector!ubyte dec(in ubyte*, size_t) const;
}

/**
* Public Key Signer. Use the signMessage() functions for small
* messages. Use multiple calls update() to process large messages and
* generate the signature by finally calling signature().
*/
struct PKSigner
{
public:
    /**
    * Sign a message.
    * @param msg = the message to sign as a ubyte array
    * @param length = the length of the above ubyte array
    * @param rng = the rng to use
    * @return signature
    */
    Vector!ubyte signMessage(in ubyte* msg, size_t length, RandomNumberGenerator rng)
    {
        update(msg, length);
        return signature(rng);
    }

    /**
    * Sign a message.
    * @param input = the message to sign
    * @param rng = the rng to use
    * @return signature
    */
    Vector!ubyte signMessage(in Vector!ubyte input, RandomNumberGenerator rng)
    { return signMessage(input.ptr, input.length, rng); }

    Vector!ubyte signMessage(in SecureVector!ubyte input, RandomNumberGenerator rng)
    { return signMessage(input.ptr, input.length, rng); }

    /**
    * Add a message part (single ubyte).
    * @param input = the ubyte to add
    */
    void update(ubyte input) { update(&input, 1); }

    /**
    * Add a message part.
    * @param input = the message part to add as a ubyte array
    * @param length = the length of the above ubyte array
    */
    void update(in ubyte* input, size_t length)
    {
        m_emsa.update(input, length);
    }

    /**
    * Add a message part.
    * @param input = the message part to add
    */
    void update(in Vector!ubyte input) { update(input.ptr, input.length); }

    /**
    * Get the signature of the so far processed message (provided by the
    * calls to update()).
    * @param rng = the rng to use
    * @return signature of the total message
    */
    Vector!ubyte signature(RandomNumberGenerator rng)
    {
        Vector!ubyte encoded = unlock(m_emsa.encodingOf(m_emsa.rawData(), m_op.maxInputBits(), rng));
        
        Vector!ubyte plain_sig = unlock(m_op.sign(encoded.ptr, encoded.length, rng));
        
        assert(selfTestSignature(encoded, plain_sig), "Signature was consistent");
        
        if (m_op.messageParts() == 1 || m_sig_format == IEEE_1363)
            return plain_sig;
        
        if (m_sig_format == DER_SEQUENCE)
        {
            if (plain_sig.length % m_op.messageParts())
                throw new EncodingError("PKSigner: strange signature size found");
            const size_t SIZE_OF_PART = plain_sig.length / m_op.messageParts();

            Vector!BigInt sig_parts = Vector!BigInt(m_op.messageParts());
            for (size_t j = 0; j != sig_parts.length; ++j)
                sig_parts[j].binaryDecode(&plain_sig[SIZE_OF_PART*j], SIZE_OF_PART);
            
            return DEREncoder()
                    .startCons(ASN1Tag.SEQUENCE)
                    .encodeList(sig_parts)
                    .endCons()
                    .getContentsUnlocked();
        }
        else
            throw new EncodingError("PKSigner: Unknown signature format " ~
                                     to!string(m_sig_format));
    }

    /**
    * Set the output format of the signature.
    * @param format = the signature format to use
    */
    void setOutputFormat(SignatureFormat format) { m_sig_format = format; }

    /**
    * Construct a PK Signer.
    * @param key = the key to use inside this signer
    * @param emsa = the EMSA to use
    * An example would be "EMSA1(SHA-224)".
    * @param format = the signature format to use
    * @param prot = says if fault protection should be enabled
    */
    this(in PrivateKey key, in string emsa_name,
         SignatureFormat format = IEEE_1363,
         FaultProtection prot = ENABLE_FAULT_PROTECTION)
    {
        AlgorithmFactory af = globalState().algorithmFactory();

        RandomNumberGenerator rng = globalState().globalRng();
        
        m_op = null;
        m_verify_op = null;

        foreach (Engine engine; af.engines) {

            if (!m_op)
                m_op = engine.getSignatureOp(key, rng);
            
            if (!m_verify_op && prot == ENABLE_FAULT_PROTECTION)
                m_verify_op = engine.getVerifyOp(key, rng);
            
            if (m_op && (m_verify_op || prot == DISABLE_FAULT_PROTECTION))
                break;
        }
        
        if (!m_op || (!m_verify_op && prot == ENABLE_FAULT_PROTECTION))
            throw new LookupError("Signing with " ~ key.algoName ~ " not supported");
        
        m_emsa = getEmsa(emsa_name);
        m_sig_format = format;
    }
private:
    /*
    * Check the signature we just created, to help prevent fault attacks
    */
    bool selfTestSignature(in Vector!ubyte msg, in Vector!ubyte sig) const
    {
        if (!m_verify_op)
            return true; // checking disabled, assume ok
        
        if (m_verify_op.withRecovery())
        {
            Vector!ubyte recovered = unlock(m_verify_op.verifyMr(sig.ptr, sig.length));
            
            if (msg.length > recovered.length)
            {
                size_t extra_0s = msg.length - recovered.length;
                
                foreach (size_t i; 0 .. extra_0s)
                    if (msg[i] != 0)
                        return false;
                
                return sameMem(&msg[extra_0s], recovered.ptr, recovered.length);
            }
            
            return (recovered == msg);
        }
        else
            return m_verify_op.verify(msg.ptr, msg.length, sig.ptr, sig.length);
    }

    Unique!Signature m_op;
    Unique!Verification m_verify_op;
    Unique!EMSA m_emsa;
    SignatureFormat m_sig_format;
}

/**
* Public Key Verifier. Use the verifyMessage() functions for small
* messages. Use multiple calls update() to process large messages and
* verify the signature by finally calling checkSignature().
*/
struct PKVerifier
{
public:
    /**
    * Verify a signature.
    * @param msg = the message that the signature belongs to, as a ubyte array
    * @param msg_length = the length of the above ubyte array msg
    * @param sig = the signature as a ubyte array
    * @param sig_length = the length of the above ubyte array sig
    * @return true if the signature is valid
    */
    bool verifyMessage(in ubyte* msg, size_t msg_length,
                        in ubyte* sig, size_t sig_length)
    {
        update(msg, msg_length);
        return checkSignature(sig, sig_length);
    }

    /**
    * Verify a signature.
    * @param msg = the message that the signature belongs to
    * @param sig = the signature
    * @return true if the signature is valid
    */
    bool verifyMessage(Alloc, Alloc2)(in Vector!( ubyte, Alloc ) msg, 
                                       in Vector!( ubyte, Alloc2 ) sig)
    {
        return verifyMessage(msg.ptr, msg.length, sig.ptr, sig.length);
    }

    /**
    * Add a message part (single ubyte) of the message corresponding to the
    * signature to be verified.
    * @param input = the ubyte to add
    */
    void update(ubyte input) { update(&input, 1); }

    /**
    * Add a message part of the message corresponding to the
    * signature to be verified.
    * @param msg_part = the new message part as a ubyte array
    * @param length = the length of the above ubyte array
    */
    void update(in ubyte* input, size_t length)
    {
        m_emsa.update(input, length);
    }

    /**
    * Add a message part of the message corresponding to the
    * signature to be verified.
    * @param input = the new message part
    */
    void update(in Vector!ubyte input)
    { update(input.ptr, input.length); }

    /**
    * Check the signature of the buffered message, i.e. the one build
    * by successive calls to update.
    * @param sig = the signature to be verified as a ubyte array
    * @param length = the length of the above ubyte array
    * @return true if the signature is valid, false otherwise
    */
    bool checkSignature(in ubyte* sig, size_t length)
    {
        try {
            if (m_sig_format == IEEE_1363)
                return validateSignature(m_emsa.rawData(), sig, length);
            else if (m_sig_format == DER_SEQUENCE)
            {
                BERDecoder decoder = BERDecoder(sig, length);
                BERDecoder ber_sig = decoder.startCons(ASN1Tag.SEQUENCE);
                
                size_t count = 0;
                Vector!ubyte real_sig;
                while (ber_sig.moreItems())
                {
                    BigInt sig_part;
                    ber_sig.decode(sig_part);
                    real_sig ~= BigInt.encode1363(sig_part, m_op.messagePartSize());
                    ++count;
                }
                
                if (count != m_op.messageParts())
                    throw new DecodingError("PKVerifier: signature size invalid");
                
                return validateSignature(m_emsa.rawData(), real_sig.ptr, real_sig.length);
            }
            else
                throw new DecodingError("PKVerifier: Unknown signature format " ~ to!string(m_sig_format));
        }
        catch(InvalidArgument) { return false; }
    }

    /**
    * Check the signature of the buffered message, i.e. the one build
    * by successive calls to update.
    * @param sig = the signature to be verified
    * @return true if the signature is valid, false otherwise
    */
    bool checkSignature(Alloc)(in Vector!( ubyte, Alloc ) sig)
    {
        return checkSignature(sig.ptr, sig.length);
    }

    /**
    * Set the format of the signatures fed to this verifier.
    * @param format = the signature format to use
    */
    void setInputFormat(SignatureFormat format)
    {
        if (m_op.messageParts() == 1 && format != IEEE_1363)
            throw new InvalidState("PKVerifier: This algorithm always uses IEEE 1363");
        m_sig_format = format;
    }

    /**
    * Construct a PK Verifier.
    * @param pub_key = the public key to verify against
    * @param emsa = the EMSA to use (eg "EMSA3(SHA-1)")
    * @param format = the signature format to use
    */
    this(in PublicKey key, in string emsa_name, SignatureFormat format = IEEE_1363)
    {
        AlgorithmFactory af = globalState().algorithmFactory();

        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines) {
            m_op = engine.getVerifyOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Verification with " ~ key.algoName ~ " not supported");
        
        m_emsa = getEmsa(emsa_name);
        m_sig_format = format;
    }

private:
    bool validateSignature(in SecureVector!ubyte msg, in ubyte* sig, size_t sig_len)
    {
        if (m_op.withRecovery())
        {
            SecureVector!ubyte output_of_key = m_op.verifyMr(sig, sig_len);
            return m_emsa.verify(output_of_key, msg, m_op.maxInputBits());
        }
        else
        {
            RandomNumberGenerator rng = globalState().globalRng();
            
            SecureVector!ubyte encoded = m_emsa.encodingOf(msg, m_op.maxInputBits(), rng);
            
            return m_op.verify(encoded.ptr, encoded.length, sig, sig_len);
        }
    }

    Unique!Verification m_op;
    Unique!EMSA m_emsa;
    SignatureFormat m_sig_format;
}

/**
* Key used for key agreement
*/
class PKKeyAgreement
{
public:

    /*
    * Perform Key Agreement Operation
    * @param key_len = the desired key output size
    * @param input = the other parties key
    * @param in_len = the length of in in bytes
    * @param params = extra derivation params
    * @param params_len = the length of params in bytes
    */
    SymmetricKey deriveKey(size_t key_len, in ubyte* input,
                            size_t in_len, in ubyte* params,
                            size_t params_len) const
    {
        SecureVector!ubyte z = m_op.agree(input, in_len);
        
        if (!m_kdf)
            return z;
        
        return m_kdf.deriveKey(key_len, z, params, params_len);
    }

    /*
    * Perform Key Agreement Operation
    * @param key_len = the desired key output size
    * @param input = the other parties key
    * @param in_len = the length of in in bytes
    * @param params = extra derivation params
    * @param params_len = the length of params in bytes
    */
    SymmetricKey deriveKey(size_t key_len, in Vector!ubyte input, in ubyte* params, size_t params_len) const
    {
        return deriveKey(key_len, input.ptr, input.length, params, params_len);
    }

    /*
    * Perform Key Agreement Operation
    * @param key_len = the desired key output size
    * @param input = the other parties key
    * @param in_len = the length of in in bytes
    * @param params = extra derivation params
    */
    SymmetricKey deriveKey(size_t key_len, in ubyte* input, size_t in_len, in string params = "") const
    {
        return deriveKey(key_len, input, in_len, cast(const ubyte*)(params.ptr), params.length);
    }

    /*
    * Perform Key Agreement Operation
    * @param key_len = the desired key output size
    * @param input = the other parties key
    * @param params = extra derivation params
    */
    SymmetricKey deriveKey(size_t key_len,
                                    in Vector!ubyte input,
                                    in string params = "") const
    {
        return deriveKey(key_len, input.ptr, input.length,
                                cast(const ubyte*)(params.ptr),
                                params.length);
    }

    /**
    * Construct a PK Key Agreement.
    * @param key = the key to use
    * @param kdf_name = name of the KDF to use (or 'Raw' for no KDF)
    */
    this(in PKKeyAgreementKey key, in string kdf_name)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines)
        {
            m_op = engine.getKeyAgreementOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Key agreement with " ~ key.algoName ~ " not supported");
        
        m_kdf = getKdf(kdf_name);
    }
private:
    Unique!KeyAgreement m_op;
    Unique!KDF m_kdf;
}

/**
* Encryption with an MR algorithm and an EME.
*/
class PKEncryptorEME : PKEncryptor
{
public:
    /*
    * Return the max size, in bytes, of a message
    */
    override size_t maximumInputSize() const
    {
        if (!m_eme)
            return (m_op.maxInputBits() / 8);
        else
            return m_eme.maximumInputSize(m_op.maxInputBits());
    }

    /**
    * Construct an instance.
    * @param key = the key to use inside the decryptor
    * @param eme = the EME to use
    */
    this(in PublicKey key, in string eme_name)
    {
        
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines) {
            m_op = engine.getEncryptionOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Encryption with " ~ key.algoName ~ " not supported");
        
        m_eme = getEme(eme_name);
    }

private:
    Vector!ubyte enc(in ubyte* input, size_t length, RandomNumberGenerator rng) const
    {
        if (m_eme)
        {
            SecureVector!ubyte encoded = m_eme.encode(input, length, m_op.maxInputBits(), rng);
            
            if (8*(encoded.length - 1) + highBit(encoded[0]) > m_op.maxInputBits())
                throw new InvalidArgument("PKEncryptorEME: Input is too large");
            
            return unlock(m_op.encrypt(encoded.ptr, encoded.length, rng));
        }
        else
        {
            if (8*(length - 1) + highBit(input[0]) > m_op.maxInputBits())
                throw new InvalidArgument("PKEncryptorEME: Input is too large");
            
            return unlock(m_op.encrypt(input.ptr, length, rng));
        }
    }

    Unique!Encryption m_op;
    Unique!EME m_eme;
}

/**
* Decryption with an MR algorithm and an EME.
*/
class PKDecryptorEME : PKDecryptor
{
public:
  /**
    * Construct an instance.
    * @param key = the key to use inside the encryptor
    * @param eme = the EME to use
    */
    this(in PrivateKey key, in string eme_name)
    {
        AlgorithmFactory af = globalState().algorithmFactory();
        RandomNumberGenerator rng = globalState().globalRng();

        foreach (Engine engine; af.engines)
        {
            m_op = engine.getDecryptionOp(key, rng);
            if (m_op)
                break;
        }
        
        if (!m_op)
            throw new LookupError("Decryption with " ~ key.algoName ~ " not supported");
        
        m_eme = getEme(eme_name);
    }

private:
    /*
    * Decrypt a message
    */
    SecureVector!ubyte dec(in ubyte* msg, size_t length) const
    {
        try {
            SecureVector!ubyte decrypted = m_op.decrypt(msg, length);
            if (m_eme)
                return m_eme.decode(decrypted, m_op.maxInputBits());
            else
                return decrypted;
        }
        catch(InvalidArgument)
        {
            throw new DecodingError("PKDecryptorEME: Input is invalid");
        }
    }

    Unique!Decryption m_op;
    Unique!EME m_eme;
}