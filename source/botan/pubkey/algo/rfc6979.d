/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rfc6979;

import botan.constants;
static if (BOTAN_HAS_RFC6979_GENERATOR):

import botan.libstate.libstate;
import botan.math.bigint.bigint;
import botan.rng.hmac_drbg;
import botan.utils.types;

/**
* @param x = the secret (EC)DSA key
* @param q = the group order
* @param h = the message hash already reduced mod q
* @param hash = the hash function used to generate h
*/
BigInt generateRfc6979Nonce(in BigInt x, in BigInt q, in BigInt h, in string hash)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    auto rng = scoped!HMAC_DRBG(af.make_mac("HMAC(" ~ hash ~ ")"), null);

    const size_t qlen = q.bits();
    const size_t rlen = qlen / 8 + (qlen % 8 ? 1 : 0);
    
    SecureVector!ubyte input = BigInt.encode_1363(x, rlen);
    
    input ~= BigInt.encode1363(h, rlen);
    
    rng.addEntropy(input.ptr, input.length);
    
    BigInt k;
    
    SecureVector!ubyte kbits = SecureVector!ubyte(rlen);
    
    while (k == 0 || k >= q)
    {
        rng.randomize(kbits.ptr, kbits.length);
        k = BigInt.decode(kbits) >> (8*rlen - qlen);
    }
    
    return k;
}

static if (BOTAN_TEST):
import botan.test;
import botan.codec.hex;

size_t rfc6979Testcase(string q_str,
                        string x_str,
                        string h_str,
                        string exp_k_str,
                        string hash,
                        size_t testcase)
{
    const BigInt q = BigInt(q_str);
    const BigInt x = BigInt(x_str);
    const BigInt h = BigInt(h_str);
    const BigInt exp_k = BigInt(exp_k_str);
    
    const BigInt gen_k = generate_rfc6979_nonce(x, q, h, hash);
    
    if (gen_k != exp_k)
    {
        writeln("RFC 6979 test #", testcase, " failed; generated k=", gen_k);
        return 1;
    }
    
    return 0;
}

unittest
{
    
    size_t fails = 0;
    
    // From RFC 6979 A.1.1
    fails += rfc6979_testcase("0x4000000000000000000020108A2E0CC0D99F8A5EF",
                              "0x09A4D6792295A7F730FC3F2B49CBC0F62E862272F",
                              "0x01795EDF0D54DB760F156D0DAC04C0322B3A204224",
                              "0x23AF4074C90A02B3FE61D286D5C87F425E6BDD81B",
                              "SHA-256", 1);
    
    // DSA 1024 bits test #1
    fails += rfc6979_testcase("0x996F967F6C8E388D9E28D01E205FBA957A5698B1",
                              "0x411602CB19A6CCC34494D79D98EF1E7ED5AF25F7",
                              "0x8151325DCDBAE9E0FF95F9F9658432DBEDFDB209",
                              "0x7BDB6B0FF756E1BB5D53583EF979082F9AD5BD5B",
                              "SHA-1", 2);
    
    testReport("RFC 6979", 2, fails);
}