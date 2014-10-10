/*
* Entropy Source Using Intel's rdrand instruction
* (C) 2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy.entropy_src;
/**
* Entropy source using the rdrand instruction first introduced on
* Intel's Ivy Bridge architecture.
*/
class Intel_Rdrand : EntropySource
{
	public:
		string name() const { return "Intel Rdrand"; }
		void poll(ref Entropy_Accumulator accum);
};