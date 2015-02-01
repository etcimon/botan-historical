/*
* Stream Cipher
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.stream_cipher;

import botan.constants;
public import botan.algo_base.sym_algo;
/**
* Base class for all stream ciphers
*/
interface StreamCipher : SymmetricAlgorithm
{
public:
    /**
    * Encrypt or decrypt a message
    * @param input = the plaintext
    * @param output = the ubyte array to hold the output, i.e. the ciphertext
    * @param len = the length of both in and out in bytes
    */
    abstract void cipher(const(ubyte)* input, ubyte* output, size_t len);

    /**
    * Encrypt or decrypt a message
    * @param buf = the plaintext / ciphertext
    * @param len = the length of buf in bytes
    */
    final void cipher1(const(ubyte)* buf, size_t len)
    { cipher(buf, cast(ubyte*)buf, len); }

    /**
    * Encrypt or decrypt a message
    * @param buf = the plaintext / ciphertext
    */
    final void cipher1(ref ubyte[] buf)
    { cipher(buf.ptr, buf.ptr, buf.length); }

    final void encipher(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
    { cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

    final void encrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
    { cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

    final void decrypt(Alloc)(ref Vector!( ubyte, Alloc ) inoutput)
    { cipher(inoutput.ptr, inoutput.ptr, inoutput.length); }

    /**
    * Resync the cipher using the IV
    * @param iv = the initialization vector
    * @param iv_len = the length of the IV in bytes
    */
    abstract void setIv(const(ubyte)*, size_t iv_len);
    // { if (iv_len) throw new InvalidArgument("The stream cipher " ~ name ~ " does not support resyncronization"); }

    /**
    * @param iv_len = the length of the IV in bytes
    * @return if the length is valid for this algorithm
    */
    abstract bool validIvLength(size_t iv_len) const;
    // { return (iv_len == 0); }

    /**
    * Get a new object representing the same algorithm as this
    */
    abstract StreamCipher clone() const;
}

static if (BOTAN_TEST):
import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;
import core.atomic;
import memutils.hashmap;
private shared size_t total_tests;

size_t streamTest(string algo,
                   string key_hex,
                   string in_hex,
                   string out_hex,
                   string nonce_hex)
{
    const SecureVector!ubyte key = hexDecodeLocked(key_hex);
    const SecureVector!ubyte pt = hexDecodeLocked(in_hex);
    const SecureVector!ubyte ct = hexDecodeLocked(out_hex);
    const SecureVector!ubyte nonce = hexDecodeLocked(nonce_hex);
    
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;
    
    if (providers.empty)
    {
        logTrace("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers[])
    {
        atomicOp!"+="(total_tests, 1);
        const StreamCipher proto = af.prototypeStreamCipher(algo, provider);
        
        if (!proto)
        {
            logTrace("Unable to get " ~ algo ~ " from provider '" ~ provider ~ "'");
            ++fails;
            continue;
        }
        
        Unique!StreamCipher cipher = proto.clone();
        cipher.setKey(key);

        if (nonce.length)
            cipher.setIv(&nonce[0], nonce.length);
        
        SecureVector!ubyte buf = pt.dup;
        
        cipher.encrypt(buf);
        
        if (buf != ct)
        {
            logTrace(algo ~ " " ~ provider ~ " enc " ~ hexEncode(buf) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

unittest
{
    logDebug("Testing stream_cipher.d ...");
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "StreamCipher", "Out", true,
                            (ref HashMap!(string, string) m) {
                                return streamTest(m["StreamCipher"], m["Key"], m["In"], m["Out"], m["Nonce"]);
                            });
    };
    
    size_t fails = runTestsInDir("../test_data/stream", test);
    
    testReport("stream", total_tests, fails);
}
