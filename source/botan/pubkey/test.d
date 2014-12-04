/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/
module botan.pubkey.test;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO && BOTAN_TEST):

import botan.test;
import botan.rng.test;
import botan.asn1.oids;
import botan.codec.hex;
import botan.pubkey.x509_key;
import botan.pubkey.pkcs8;
import botan.pubkey.pubkey;
import botan.rng.auto_rng;
import botan.filters.filters;
import botan.math.numbertheory.numthry;

void dumpData(in Vector!ubyte output, in Vector!ubyte expected)
{
    Pipe pipe = Pipe(new HexEncoder);
    
    pipe.processMsg(output);
    pipe.processMsg(expected);
    writeln("Got: " ~ pipe.readAllAsString(0));
    writeln("Exp: " ~ pipe.readAllAsString(1));
}

size_t validateSaveAndLoad(const PrivateKey priv_key, RandomNumberGenerator rng)
{
    string name = priv_key.algoName();
    
    size_t fails = 0;
    string pub_pem = x509_key.PEM_encode(priv_key);
    
    try
    {
        DataSourceMemory input_pub = scoped!DataSourceMemory(pub_pem);
        PublicKey restored_pub = x509_key.loadKey(input_pub);
        
        if (!restored_pub)
        {
            writeln("Could not recover " ~ name ~ " public key");
            ++fails;
        }
        else if (restored_pub.checkKey(rng, true) == false)
        {
            writeln("Restored pubkey failed self tests " ~ name);
            ++fails;
        }
    }
    catch(Exception e)
    {
        writeln("Exception during load of " ~ name ~ " key: " ~ e.msg);
        writeln("PEM for pubkey was: " ~ pub_pem);
        ++fails;
    }
    
    string priv_pem = pkcs8.PEM_encode(priv_key);
    
    try
    {
        auto input_priv = scoped!DataSourceMemory(priv_pem);
        Unique!PrivateKey restored_priv = pkcs8.loadKey(input_priv, rng);
        
        if (!restored_priv)
        {
            writeln("Could not recover " ~ name ~ " private key");
            ++fails;
        }
        else if (restored_priv.checkKey(rng, true) == false)
        {
            writeln("Restored privkey failed self tests " ~ name);
            ++fails;
        }
    }
    catch(Exception e)
    {
        writeln("Exception during load of " ~ name ~ " key: " ~ e.msg);
        writeln("PEM for privkey was: " ~ priv_pem);
        ++fails;
    }
    
    return fails;
}

ubyte nonzeroByte(RandomNumberGenerator rng)
{
    ubyte b = 0;
    while(b == 0)
        b = rng.nextByte();
    return b;
}

string pKTEST(string expr, string msg) 
{
    return `
        {
            const bool test_result = ` ~ expr ~ `;
            if (!test_result)
            {
                writeln("Test " ~ ` ~ expr ~ ` ~ " failed: " ~ msg);
                ++fails;
            }
        }
    `;
}

size_t validateEncryption(PKEncryptor e, PKDecryptor d,
                           string algo, string input,
                           string random, string exp)
{
    Vector!ubyte message = hexDecode(input);
    Vector!ubyte expected = hexDecode(exp);
    Fixed_Output_RNG rng = scoped!Fixed_Output_RNG(hexDecode(random));
    
    size_t fails = 0;
    
    const Vector!ubyte ctext = e.encrypt(message, rng);
    if (ctext != expected)
    {
        writeln("FAILED (encrypt): " ~ algo);
        dumpData(ctext, expected);
        ++fails;
    }
    
    Vector!ubyte decrypted = unlock(d.decrypt(ctext));
    
    if (decrypted != message)
    {
        writeln("FAILED (decrypt): " ~ algo);
        dumpData(decrypted, message);
        ++fails;
    }
    
    if (algo.canFind("/Raw") == -1)
    {
        AutoSeededRNG rng;
        
        for(size_t i = 0; i != ctext.length; ++i)
        {
            Vector!ubyte bad_ctext = ctext;
            
            bad_ctext[i] ^= nonzeroByte(rng);
            
            assert(bad_ctext != ctext, "Made them different");
            
            try
            {
                auto bad_ptext = unlock(d.decrypt(bad_ctext));
                writeln(algo ~ " failed - decrypted bad data");
                writeln(hexEncode(bad_ctext) ~ " . " ~ hexEncode(bad_ptext));
                writeln(hexEncode(ctext) ~ " . " ~ hexEncode(decrypted));
                ++fails;
            }
            catch (Throwable) {}
        }
    }
    
    return fails;
}

size_t validateSignature(PKVerifier v, PKSigner s, string algo,
                          string input,
                          RandomNumberGenerator rng,
                          string exp)
{
    return validateSignature(v, s, algo, input, rng, rng, exp);
}

size_t validateSignature(PKVerifier v, PKSigner s, string algo,
                          string input,
                          RandomNumberGenerator signer_rng,
                          RandomNumberGenerator test_rng,
                          string exp)    
{
    Vector!ubyte message = hexDecode(input);
    Vector!ubyte expected = hexDecode(exp);
    Vector!ubyte sig = s.signMessage(message, signer_rng);
    
    size_t fails = 0;
    
    if (sig != expected)
    {
        writeln("FAILED (sign): " ~ algo);
        dumpData(sig, expected);
        ++fails;
    }
    
    mixin( PKTEST(` v.verifyMessage(message, sig) `, "Correct signature is valid") );
    
    zeroMem(&sig[0], sig.length);
    
    mixin( PKTEST(` !v.verifyMessage(message, sig) `, "All-zero signature is invalid") );
    
    for(size_t i = 0; i != 3; ++i)
    {
        auto bad_sig = sig;
        
        const size_t idx = (test_rng.nextByte() * 256 + test_rng.nextByte()) % sig.length;
        bad_sig[idx] ^= nonzeroByte(test_rng);
        
        mixin( PKTEST(` !v.verifyMessage(message, bad_sig) `, "Incorrect signature is invalid") );
    }
    
    return fails;
}

size_t validateSignature(PKVerifier v, PKSigner s, string algo,
                          string input,
                          RandomNumberGenerator rng,
                          string random,
                          string exp)
{
    Fixed_Output_RNG fixed_rng = scoped!Fixed_Output_RNG(hexDecode(random));
    
    return validateSignature(v, s, algo, input, fixed_rng, rng, exp);
}

size_t validateKas(PKKeyAgreement kas, string algo,
                    const Vector!ubyte pubkey, string output,
                    size_t keylen)
{
    Vector!ubyte expected = hexDecode(output);
    
    Vector!ubyte got = unlock(kas.deriveKey(keylen, pubkey).bitsOf());
    
    size_t fails = 0;
    
    if (got != expected)
    {
        writeln("FAILED: " ~ algo);
        dumpData(got, expected);
        ++fails;
    }
    
    return fails;
}