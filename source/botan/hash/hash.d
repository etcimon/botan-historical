/*
* Hash Function Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.hash.hash;
import botan.algo_base.buf_comp;
// import string;
/**
* This class represents hash function (message digest) objects
*/
class HashFunction : BufferedComputation
{
public:
    /**
    * @return new object representing the same algorithm as this
    */
    abstract HashFunction clone() const;

    abstract void clear();

    abstract @property string name() const;

    /**
    * @return hash block size as defined for this algorithm
    */
    abstract @property size_t hashBlockSize() const { return 0; }
}

static if (BOTAN_TEST):
import botan.test;

import botan.libstate.libstate;
import botan.codec.hex;
import core.atomic;

private __gshared size_t total_tests;

size_t hashTest(string algo, string in_hex, string out_hex)
{
    AlgorithmFactory af = globalState().algorithmFactory();
    
    const auto providers = af.providersOf(algo);
    size_t fails = 0;
    atomicOp!"+="(total_tests, 1);
    if (providers.empty)
    {
        writeln("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers[])
    {
        auto proto = af.prototypeHashFunction(algo, provider);

        atomicOp!"+="(total_tests, 1);

        if (!proto)
        {
            writeln("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!HashFunction hash(proto.clone());
        
        hash.update(hexDecode(in_hex));
        
        auto h = hash.finished();

        atomicOp!"+="(total_tests, 1);

        if (h != hexDecodeLocked(out_hex))
        {
            writeln(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
        
        // Test to make sure clear() resets what we need it to
        hash.update("some discarded input");
        hash.clear();
        
        hash.update(hexDecode(in_hex));
        
        h = hash.finished();

        atomicOp!"+="(total_tests, 1);

        if (h != hexDecodeLocked(out_hex))
        {
            writeln(algo ~ " " ~ provider ~ " got " ~ hexEncode(h) ~ " != " ~ out_hex);
            ++fails;
        }
    }
    
    return fails;
}

unittest
{
    auto test = (string input)
    {
        File vec = File(input, "r");

        return runTestsBb(vec, "Hash", "Out", true,
                            (string[string] m) {
                                return hashTest(m["Hash"], m["In"], m["Out"]);
                            });
    };
    
    size_t fails = runTestsInDir("test_data/hash", test);

    testReport("hash", total_tests, fails);
}
