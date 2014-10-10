/*
* High Resolution Timestamp Entropy Source
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy.entropy_src;
/**
* Entropy source using high resolution timers
*
* @note Any results from timers are marked as not contributing entropy
* to the poll, as a local attacker could observe them directly.
*/
class High_Resolution_Timestamp : EntropySource
{
	public:
		string name() const { return "High Resolution Timestamp"; }
		void poll(ref Entropy_Accumulator accum);
};