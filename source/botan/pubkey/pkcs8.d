/*
* PKCS #8
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.pkcs8;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

alias pkcs8 = botan.pubkey.pkcs8;

public import botan.rng.rng;
public import botan.pubkey.pubkey;
import botan.pubkey.x509_key;
import std.datetime;
import botan.filters.pipe;
import botan.pbe.factory;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.alg_id;
import botan.asn1.oids;
import botan.codec.pem;
import botan.pubkey.pk_algs;
import botan.utils.types;
import botan.pbe.pbe;

/**
* PKCS #8 General Exception
*/
final class PKCS8Exception : DecodingError
{
    this(in string error)
    {
        super("PKCS #8: " ~ error);
    }
}

/**
* BER encode a private key
* @param key = the private key to encode
* @return BER encoded key
*/
SecureVector!ubyte BER_encode(in PrivateKey key)
{
    __gshared immutable size_t PKCS8_VERSION = 0;
    
    return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
            .encode(PKCS8_VERSION)
            .encode(key.pkcs8AlgorithmIdentifier())
            .encode(key.pkcs8PrivateKey(), ASN1Tag.OCTET_STRING)
            .endCons()
            .getContents();
}

/**
* Get a string containing a PEM encoded private key.
* @param key = the key to encode
* @return encoded key
*/
string PEM_encode(in PrivateKey key)
{
    return PEM.encode(BER_encode(key), "PRIVATE KEY");
}

/**
* Encrypt a key using PKCS #8 encryption
* @param key = the key to encode
* @param rng = the rng to use
* @param pass = the password to use for encryption
* @param dur = number of time to run the password derivation
* @param pbe_algo = the name of the desired password-based encryption
            algorithm; if empty ("") a reasonable (portable/secure)
            default will be chosen.
* @return encrypted key in binary BER form
*/
Vector!ubyte BER_encode(in PrivateKey key,
                        RandomNumberGenerator rng,
                        in string pass,
                        Duration dur = 300.msecs,
                        in string pbe_algo = "")
{
    const string DEFAULT_PBE = "PBE-PKCS5v20(SHA-1,AES-256/CBC)";
    
    Unique!PBE pbe = getPbe(((pbe_algo != "") ? pbe_algo : DEFAULT_PBE), pass, dur, rng);
    
    AlgorithmIdentifier pbe_algid = AlgorithmIdentifier(pbe.getOid(), pbe.encodeParams());
    
    Pipe key_encrytor = Pipe(*pbe);
    key_encrytor.processMsg(BER_encode(key));
    
    return DEREncoder()
            .startCons(ASN1Tag.SEQUENCE)
            .encode(pbe_algid)
            .encode(key_encrytor.readAll(), ASN1Tag.OCTET_STRING)
            .endCons()
            .getContentsUnlocked();
}

/**
* Get a string containing a PEM encoded private key, encrypting it with a
* password.
* @param key = the key to encode
* @param rng = the rng to use
* @param pass = the password to use for encryption
* @param msec = number of milliseconds to run the password derivation
* @param pbe_algo = the name of the desired password-based encryption
            algorithm; if empty ("") a reasonable (portable/secure)
            default will be chosen.
* @return encrypted key in PEM form
*/
string PEM_encode(in PrivateKey key,
                  RandomNumberGenerator rng,
                  in string pass,
                  Duration dur = 300.msecs,
                  in string pbe_algo = "")
{
    if (pass == "")
        return PEM_encode(key);

    return PEM.encode(BER_encode(key, rng, pass, dur, pbe_algo), "ENCRYPTED PRIVATE KEY");
}

/**
* Load a key from a data source.
* @param source = the data source providing the encoded key
* @param rng = the rng to use
* @param getPassphrase = a function that returns passphrases
* @return loaded private key object
*/
PrivateKey loadKey(DataSource source,
                     RandomNumberGenerator rng,
                     SingleShotPassphrase get_pass)
{
    AlgorithmIdentifier alg_id;
    SecureVector!ubyte pkcs8_key = PKCS8_decode(source, get_pass, alg_id);
    
    const string alg_name = OIDS.lookup(alg_id.oid);
    if (alg_name == "" || alg_name == alg_id.oid.toString())
        throw new PKCS8Exception("Unknown algorithm OID: " ~
                                  alg_id.oid.toString());
    
    return makePrivateKey(alg_id, pkcs8_key, rng);
}

/** Load a key from a data source.
* @param source = the data source providing the encoded key
* @param rng = the rng to use
* @param pass = the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
PrivateKey loadKey(DataSource source,
                   RandomNumberGenerator rng,
                     in string pass = "")
{
    return loadKey(source, rng, SingleShotPassphrase(pass));
}

/**
* Load a key from a file.
* @param filename = the path to the file containing the encoded key
* @param rng = the rng to use
* @param getPassphrase = a function that returns passphrases
* @return loaded private key object
*/
PrivateKey loadKey(in string filename,
                     RandomNumberGenerator rng,
                     SingleShotPassphrase get_pass)
{
    auto source = scoped!DataSourceStream(filename, true);
    return loadKey(source, rng, get_pass);
}

/** Load a key from a file.
* @param filename = the path to the file containing the encoded key
* @param rng = the rng to use
* @param pass = the passphrase to decrypt the key. Provide an empty
* string if the key is not encrypted
* @return loaded private key object
*/
PrivateKey loadKey(in string filename,
                     RandomNumberGenerator rng,
                     in string pass = "")
{
    return loadKey(filename, rng, SingleShotPassphrase(pass));
}


/**
* Copy an existing encoded key object.
* @param key = the key to copy
* @param rng = the rng to use
* @return new copy of the key
*/
PrivateKey copyKey(in PrivateKey key,
                   RandomNumberGenerator rng)
{
    auto source = scoped!DataSourceMemory(PEM_encode(key));
    return loadKey(source, rng);
}

/*
* Get info from an EncryptedPrivateKeyInfo
*/
SecureVector!ubyte PKCS8_extract(DataSource source,
                                 AlgorithmIdentifier pbe_alg_id)
{
    SecureVector!ubyte key_data;
    
    BERDecoder(source)
            .startCons(ASN1Tag.SEQUENCE)
            .decode(pbe_alg_id)
            .decode(key_data, ASN1Tag.OCTET_STRING)
            .verifyEnd();
    
    return key_data;
}

/*
* PEM decode and/or decrypt a private key
*/
SecureVector!ubyte PKCS8_decode(DataSource source, SingleShotPassphrase getPassphrase, AlgorithmIdentifier pk_alg_id)
{
    AlgorithmIdentifier pbe_alg_id;
    SecureVector!ubyte key_data, key;
    bool is_encrypted = true;
    
    try {
        if (maybeBER(source) && !PEM.matches(source))
            key_data = PKCS8_extract(source, pbe_alg_id);
        else
        {
            string label;
            key_data = PEM.decode(source, label);
            if (label == "PRIVATE KEY")
                is_encrypted = false;
            else if (label == "ENCRYPTED PRIVATE KEY")
            {
                auto key_source = scoped!DataSourceMemory(key_data);
                key_data = PKCS8_extract(key_source, pbe_alg_id);
            }
            else
                throw new PKCS8Exception("Unknown PEM label " ~ label);
        }
        
        if (key_data.empty)
            throw new PKCS8Exception("No key data found");
    }
    catch(DecodingError e)
    {
        throw new DecodingError("PKCS #8 private key decoding failed: " ~ e.msg);
    }
    
    if (!is_encrypted)
        key = key_data;
    
    __gshared immutable size_t MAX_TRIES = 3;
    
    size_t tries = 0;
    while (true)
    {
        try {
            if (MAX_TRIES && tries >= MAX_TRIES)
                break;
            
            if (is_encrypted)
            {
                Pair!(bool, string) pass = getPassphrase();
                
                if (pass.first == false)
                    break;
                
                Pipe decryptor = Pipe(getPbe(pbe_alg_id.oid, pbe_alg_id.parameters, pass.second));
                
                decryptor.processMsg(key_data);
                key = decryptor.readAll();
            }
            
            BERDecoder(key)
                    .startCons(ASN1Tag.SEQUENCE)
                    .decodeAndCheck!size_t(0, "Unknown PKCS #8 version number")
                    .decode(pk_alg_id)
                    .decode(key, ASN1Tag.OCTET_STRING)
                    .discardRemaining()
                    .endCons();
            
            break;
        }
        catch(DecodingError)
        {
            ++tries;
        }
    }
    
    if (key.empty)
        throw new DecodingError("PKCS #8 private key decoding failed");
    return key;
}


private struct SingleShotPassphrase
{
public:
    this(in string pass) 
    {
        passphrase = pass;
        first = true;
    }
    
    Pair!(bool, string) opCall()
    {
        if (first)
        {
            first = false;
            return makePair(true, passphrase);
        }
        else
            return makePair(false, "");
    }
    
private:
    string passphrase;
    bool first;
}
