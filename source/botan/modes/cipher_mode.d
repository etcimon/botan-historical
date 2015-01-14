/*
* Cipher Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.cipher_mode;

public import botan.algo_base.transform;
import botan.constants; 
/**
* Interface for cipher modes
*/
class CipherMode : KeyedTransform, Transformation
{
public:
    /**
    * Returns true iff this mode provides authentication as well as
    * confidentiality.
    */
    abstract bool authenticated() const { return false; }
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import botan.libstate.lookup;
import botan.filters.filters;
import core.atomic;

private shared size_t total_tests;
SecureVector!ubyte runMode(string algo, CipherDir dir, 
                           in SecureVector!ubyte pt, 
                           in SecureVector!ubyte nonce, 
                           in SecureVector!ubyte key)
{
    /*
    Unique!CipherMode cipher = getCipher(algo, dir);

    cipher.setKey(key);
    cipher.startVec(nonce);

    SecureVector!ubyte ct = pt;
    cipher.finish(ct);
    */
    
    Pipe pipe = Pipe(getCipher(algo, SymmetricKey(key.dup), InitializationVector(nonce.dup), dir));
    
    pipe.processMsg(pt.ptr, pt.length);
    
    return pipe.readAll();
}

size_t modeTest(string algo, string pt, string ct, string key_hex, string nonce_hex)
{
    auto nonce = hexDecodeLocked(nonce_hex);
    auto key = hexDecodeLocked(key_hex);
    
    size_t fails = 0;
    
    const string ct2 = hexEncode(runMode(algo, ENCRYPTION, hexDecodeLocked(pt), nonce, key));
    atomicOp!"+="(total_tests, 1);
    if (ct != ct2)
    {
        logTrace(algo ~ " got ct " ~ ct2 ~ " expected " ~ ct);
        ++fails;
    }
    
    const string pt2 = hexEncode(runMode(algo, DECRYPTION, hexDecodeLocked(ct), nonce, key));
    atomicOp!"+="(total_tests, 1);
    if (pt != pt2)
    {
        logTrace(algo ~ " got pt " ~ pt2 ~ " expected " ~ pt);
        ++fails;
    }
    
    return fails;
}

unittest {
    logTrace("Testing cipher_mode.d ...");
    auto test = delegate(string input)
    {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mode", "Out", true,
                            (string[string] m) {
                                return modeTest(m["Mode"], m["In"], m["Out"], m["Key"], m["Nonce"]);
                            });
    };
    
    size_t fails = runTestsInDir("../test_data/modes", test);

    testReport("cipher_mode", total_tests, fails);
}
