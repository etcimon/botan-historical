/*
* AES Key Wrap (RFC 3394)
* (C) 2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.rfc3394;

import botan.constants;
static if (BOTAN_HAS_RFC3394_KEYWRAP):

import botan.algo_base.symkey;
import botan.algo_factory.algo_factory;
import botan.block.block_cipher;
import botan.utils.loadstor;
import botan.utils.exceptn;
import botan.utils.xor_buf;
import botan.algo_factory.algo_factory;
import botan.utils.types;

/**
* Encrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the plaintext key to encrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key encrypted under kek
*/
Secure_Vector!ubyte rfc3394_keywrap(in Secure_Vector!ubyte key,
                                    in SymmetricKey kek,
                                    Algorithm_Factory af)
{
    if (key.length % 8 != 0)
        throw new Invalid_Argument("Bad input key size for NIST key wrap");
    
    Unique!BlockCipher aes = make_aes(kek.length, af);
    aes.set_key(kek);
    
    const size_t n = key.length / 8;
    
    Secure_Vector!ubyte R = Secure_Vector!ubyte((n + 1) * 8);
    Secure_Vector!ubyte A = Secure_Vector!ubyte(16);
    
    foreach (size_t i; 0 .. 8)
        A[i] = 0xA6;
    
    copy_mem(&R[8], key.ptr, key.length);
    
    foreach (size_t j; 0 .. 5 + 1)
    {
        foreach (size_t i; 1 .. n + 1)
        {
            const uint t = (n * j) + i;
            
            copy_mem(&A[8], &R[8*i], 8);
            
            aes.encrypt(A.ptr);
            copy_mem(&R[8*i], &A[8], 8);
            
            ubyte[4] t_buf;
            store_bigEndian(t, t_buf.ptr);
            xor_buf(&A[4], t_buf.ptr, 4);
        }
    }
    
    copy_mem(R.ptr, A.ptr, 8);
    
    return R;
}

/**
* Decrypt a key under a key encryption key using the algorithm
* described in RFC 3394
*
* @param key the encrypted key to decrypt
* @param kek the key encryption key
* @param af an algorithm factory
* @return key decrypted under kek
*/
Secure_Vector!ubyte rfc3394_keyunwrap(in Secure_Vector!ubyte key,
                                      in SymmetricKey kek,
                                      Algorithm_Factory af)
{
    if (key.length < 16 || key.length % 8 != 0)
        throw new Invalid_Argument("Bad input key size for NIST key unwrap");
    
    Unique!BlockCipher aes = make_aes(kek.length, af);
    aes.set_key(kek);
    
    const size_t n = (key.length - 8) / 8;
    
    Secure_Vector!ubyte R = Secure_Vector!ubyte(n * 8);
    Secure_Vector!ubyte A = Secure_Vector!ubyte(16);
    
    foreach (size_t i; 0 .. 8)
        A[i] = key[i];
    
    copy_mem(R.ptr, &key[8], key.length - 8);
    
    foreach (size_t j; 0 .. 5 + 1)
    {
        for (size_t i = n; i != 0; --i)
        {
            const uint t = (5 - j) * n + i;
            
            ubyte[4] t_buf;
            store_bigEndian(t, t_buf);
            
            xor_buf(&A[4], t_buf.ptr, 4);
            
            copy_mem(&A[8], &R[8*(i-1)], 8);
            
            aes.decrypt(A.ptr);
            
            copy_mem(&R[8*(i-1)], &A[8], 8);
        }
    }
    
    if (load_bigEndian!ulong(A.ptr, 0) != 0xA6A6A6A6A6A6A6A6)
        throw new Integrity_Failure("NIST key unwrap failed");
    
    return R;
}

private:

BlockCipher make_aes(size_t keylength, Algorithm_Factory af)
{
    if (keylength == 16)
        return af.make_block_cipher("AES-128");
    else if (keylength == 24)
        return af.make_block_cipher("AES-192");
    else if (keylength == 32)
        return af.make_block_cipher("AES-256");
    else
        throw new Invalid_Argument("Bad KEK length for NIST keywrap");
}


static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.libstate;

size_t keywrap_test(const char* key_str,
                    const char* expected_str,
                    const char* kek_str)
{
    size_t fail = 0;
    
    try
    {
        SymmetricKey key = SymmetricKey(key_str);
        SymmetricKey expected = SymmetricKey(expected_str);
        SymmetricKey kek = SymmetricKey(kek_str);
        
        Algorithm_Factory af = global_state().algorithm_factory();
        
        Secure_Vector!ubyte enc = rfc3394_keywrap(key.bits_of(), kek, af);
        
        if (enc != expected.bits_of())
        {
            writeln("NIST key wrap encryption failure: "
                    << hex_encode(enc) ~ " != " ~ hex_encode(expected.bits_of()));
            fail++;
        }
        
        Secure_Vector!ubyte dec = rfc3394_keyunwrap(expected.bits_of(), kek, af);
        
        if (dec != key.bits_of())
        {
            writeln("NIST key wrap decryption failure: " ~ hex_encode(dec) ~ " != " ~ hex_encode(key.bits_of()));
            fail++;
        }
    }
    catch(Exception e)
    {
        writeln(e.msg);
        fail++;
    }
    
    return fail;
}

size_t test_keywrap()
{
    size_t fails = 0;
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                          "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
                          "000102030405060708090A0B0C0D0E0F");
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                          "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
                          "000102030405060708090A0B0C0D0E0F1011121314151617");
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF",
                          "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
                          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF0001020304050607",
                          "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
                          "000102030405060708090A0B0C0D0E0F1011121314151617");
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF0001020304050607",
                          "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
                          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    fails += keywrap_test("00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
                          "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
                          "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
    
    test_report("rfc3394", 6, fails);
}
