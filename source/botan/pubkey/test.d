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

void dump_data(in Vector!ubyte output, in Vector!ubyte expected)
{
    Pipe pipe = Pipe(new Hex_Encoder);
    
    pipe.process_msg(output);
    pipe.process_msg(expected);
    writeln("Got: " ~ pipe.read_all_as_string(0));
    writeln("Exp: " ~ pipe.read_all_as_string(1));
}

size_t validate_save_and_load(const Private_Key priv_key, RandomNumberGenerator rng)
{
    string name = priv_key.algo_name();
    
    size_t fails = 0;
    string pub_pem = x509_key.PEM_encode(priv_key);
    
    try
    {
        DataSource_Memory input_pub = scoped!DataSource_Memory(pub_pem);
        Public_Key restored_pub = x509_key.load_key(input_pub);
        
        if (!restored_pub)
        {
            writeln("Could not recover " ~ name ~ " public key");
            ++fails;
        }
        else if (restored_pub.check_key(rng, true) == false)
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
        auto input_priv = scoped!DataSource_Memory(priv_pem);
        Unique!Private_Key restored_priv = pkcs8.load_key(input_priv, rng);
        
        if (!restored_priv)
        {
            writeln("Could not recover " ~ name ~ " private key");
            ++fails;
        }
        else if (restored_priv.check_key(rng, true) == false)
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

ubyte nonzero_byte(RandomNumberGenerator rng)
{
    ubyte b = 0;
    while(b == 0)
        b = rng.next_byte();
    return b;
}

string PK_TEST(string expr, string msg) 
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

size_t validate_encryption(PK_Encryptor e, PK_Decryptor d,
                           string algo, string input,
                           string random, string exp)
{
    Vector!ubyte message = hex_decode(input);
    Vector!ubyte expected = hex_decode(exp);
    Fixed_Output_RNG rng = scoped!Fixed_Output_RNG(hex_decode(random));
    
    size_t fails = 0;
    
    const Vector!ubyte ctext = e.encrypt(message, rng);
    if (ctext != expected)
    {
        writeln("FAILED (encrypt): " ~ algo);
        dump_data(ctext, expected);
        ++fails;
    }
    
    Vector!ubyte decrypted = unlock(d.decrypt(ctext));
    
    if (decrypted != message)
    {
        writeln("FAILED (decrypt): " ~ algo);
        dump_data(decrypted, message);
        ++fails;
    }
    
    if (algo.canFind("/Raw") == -1)
    {
        AutoSeeded_RNG rng;
        
        for(size_t i = 0; i != ctext.length; ++i)
        {
            Vector!ubyte bad_ctext = ctext;
            
            bad_ctext[i] ^= nonzero_byte(rng);
            
            assert(bad_ctext != ctext, "Made them different");
            
            try
            {
                auto bad_ptext = unlock(d.decrypt(bad_ctext));
                writeln(algo ~ " failed - decrypted bad data");
                writeln(hex_encode(bad_ctext) ~ " . " ~ hex_encode(bad_ptext));
                writeln(hex_encode(ctext) ~ " . " ~ hex_encode(decrypted));
                ++fails;
            }
            catch (Throwable) {}
        }
    }
    
    return fails;
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
                          string input,
                          RandomNumberGenerator rng,
                          string exp)
{
    return validate_signature(v, s, algo, input, rng, rng, exp);
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
                          string input,
                          RandomNumberGenerator signer_rng,
                          RandomNumberGenerator test_rng,
                          string exp)    
{
    Vector!ubyte message = hex_decode(input);
    Vector!ubyte expected = hex_decode(exp);
    Vector!ubyte sig = s.sign_message(message, signer_rng);
    
    size_t fails = 0;
    
    if (sig != expected)
    {
        writeln("FAILED (sign): " ~ algo);
        dump_data(sig, expected);
        ++fails;
    }
    
    mixin( PK_TEST(` v.verify_message(message, sig) `, "Correct signature is valid") );
    
    zero_mem(&sig[0], sig.length);
    
    mixin( PK_TEST(` !v.verify_message(message, sig) `, "All-zero signature is invalid") );
    
    for(size_t i = 0; i != 3; ++i)
    {
        auto bad_sig = sig;
        
        const size_t idx = (test_rng.next_byte() * 256 + test_rng.next_byte()) % sig.length;
        bad_sig[idx] ^= nonzero_byte(test_rng);
        
        mixin( PK_TEST(` !v.verify_message(message, bad_sig) `, "Incorrect signature is invalid") );
    }
    
    return fails;
}

size_t validate_signature(PK_Verifier v, PK_Signer s, string algo,
                          string input,
                          RandomNumberGenerator rng,
                          string random,
                          string exp)
{
    Fixed_Output_RNG fixed_rng = scoped!Fixed_Output_RNG(hex_decode(random));
    
    return validate_signature(v, s, algo, input, fixed_rng, rng, exp);
}

size_t validate_kas(PK_Key_Agreement kas, string algo,
                    const Vector!ubyte pubkey, string output,
                    size_t keylen)
{
    Vector!ubyte expected = hex_decode(output);
    
    Vector!ubyte got = unlock(kas.derive_key(keylen, pubkey).bits_of());
    
    size_t fails = 0;
    
    if (got != expected)
    {
        writeln("FAILED: " ~ algo);
        dump_data(got, expected);
        ++fails;
    }
    
    return fails;
}