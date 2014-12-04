/*
* Base class for message authentiction codes
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.mac.mac;
import botan.algo_base.buf_comp;
import botan.algo_base.sym_algo;
// import string;

import botan.utils.mem_ops;

/**
* This class represents Message Authentication Code (MAC) objects.
*/
class MessageAuthenticationCode : BufferedComputation, SymmetricAlgorithm
{
public:
    /**
    * Verify a MAC.
    * @param input = the MAC to verify as a ubyte array
    * @param length = the length of param in
    * @return true if the MAC is valid, false otherwise
    */
    final bool verifyMac(in ubyte* mac, size_t length)
    {
        SecureVector!ubyte our_mac = finished();
        
        if (our_mac.length != length)
            return false;
        
        return sameMem(our_mac.ptr, mac.ptr, length);
    }

    /**
    * Get a new object representing the same algorithm as this
    */
    abstract MessageAuthenticationCode clone() const;

    /**
    * Get the name of this algorithm.
    * @return name of this algorithm
    */
    abstract @property string name() const;
}

static if (BOTAN_TEST):

import botan.test;
import botan.libstate.libstate;
import botan.codec.hex;

private __gshared size_t total_tests;

size_t macTest(string algo, string key_hex, string in_hex, string out_hex)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providers_of(algo);
    size_t fails = 0;

    atomicOp!"+="(total_tests, 1);
    if(providers.empty)
    {
        writeln("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers)
    {
        atomicOp!"+="(total_tests, 1);
        auto proto = af.prototypeMac(algo, provider);
        
        if(!proto)
        {
            writeln("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!MessageAuthenticationCode mac = proto.clone();
        
        mac.setKey(hexDecode(key_hex));
        mac.update(hexDecode(in_hex));
        
        auto h = mac.finished();

        atomicOp!"+="(total_tests, 1);
        if(h != hexDecodeLocked(out_hex))
        {
            writeln(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

unittest {    
    auto test = (string input) {
        File vec = File(input, "r");
        
        return runTestsBb(vec, "Mac", "Out", true,
                            (string[string] m) {
                                return macTest(m["Mac"], m["Key"], m["In"], m["Out"]);
                            });
    };
    
    size_t fails = runTestsInDir("test_data/mac", test);

    testReport("mac", total_tests, fails);
}
