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
class HashFunction : Buffered_Computation
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
    abstract @property size_t hash_block_size() const { return 0; }
}

static if (BOTAN_TEST):
import botan.test;

import botan.libstate.libstate;
import botan.codec.hex;
import core.atomic;

private __gshared size_t total_tests;

size_t hash_test(string algo, string in_hex, string out_hex)
{
    Algorithm_Factory af = global_state().algorithm_factory();
    
    const auto providers = af.providers_of(algo);
    size_t fails = 0;
    atomicOp!"+="(total_tests, 1);
    if (providers.empty)
    {
        writeln("Unknown algo " ~ algo);
        ++fails;
    }
    
    foreach (provider; providers[])
    {
        auto proto = af.prototype_hash_function(algo, provider);

        atomicOp!"+="(total_tests, 1);

        if (!proto)
        {
            writeln("Unable to get " ~ algo ~ " from " ~ provider);
            ++fails;
            continue;
        }
        
        Unique!HashFunction hash(proto.clone());
        
        hash.update(hex_decode(in_hex));
        
        auto h = hash.flush();

        atomicOp!"+="(total_tests, 1);

        if (h != hex_decode_locked(out_hex))
        {
            writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
            ++fails;
        }
        
        // Test to make sure clear() resets what we need it to
        hash.update("some discarded input");
        hash.clear();
        
        hash.update(hex_decode(in_hex));
        
        h = hash.flush();

        atomicOp!"+="(total_tests, 1);

        if (h != hex_decode_locked(out_hex))
        {
            writeln(algo ~ " " ~ provider ~ " got " ~ hex_encode(h) ~ " != " ~ out_hex);
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

        return run_tests_bb(vec, "Hash", "Out", true,
                            (string[string] m) {
                                return hash_test(m["Hash"], m["In"], m["Out"]);
                            });
    };
    
    size_t fails = run_tests_in_dir("test_data/hash", test);

    test_report("hash", total_tests, fails);
}
