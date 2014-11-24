/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.entropy.rdrand;

import botan.constants;
static if (BOTAN_HAS_ENTROPY_SRC_RDRAND):

import botan.entropy.entropy_src;
import botan.utils.cpuid;
import botan.utils.simd.immintrin;

/**
* Entropy source using the rdrand instruction first introduced on
* Intel's Ivy Bridge architecture.
*/
final class Intel_Rdrand : EntropySource
{
public:
    @property string name() const { return "Intel Rdrand"; }
    /*
    * Get the timestamp
    */
    void poll(ref Entropy_Accumulator accum)
    {
        if (!CPUID.has_rdrand())
            return;
        
        /*
        * Put an upper bound on the total entropy we're willing to claim
        * for any one polling of rdrand to prevent it from swamping our
        * poll. Internally, the rdrand system is a DRGB that reseeds at a
        * somewhat unpredictable rate (the current conditions are
        * documented, but that might not be true for different
        * implementations, eg on Haswell or a future AMD chip, so I don't
        * want to assume). This limit ensures we're going to poll at least
        * one other source so we have some diversity in our inputs.
        */

        __gshared immutable size_t POLL_UPPER_BOUND = 96;
        __gshared immutable size_t RDRAND_POLLS = 32;
        __gshared immutable double ENTROPY_PER_POLL = cast(double)(POLL_UPPER_BOUND) / (RDRAND_POLLS * 4);
        
        foreach (size_t i; 0 .. RDRAND_POLLS)
        {
            uint r = 0;

            int cf = _rdrand32_step(&r);


            if (cf == 1)
                accum.add(r, ENTROPY_PER_POLL);
        }
    }
}

