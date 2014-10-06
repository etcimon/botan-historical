/*
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
/**
* BeOS Entropy Source
*/
class BeOS_EntropySource : EntropySource
{
	private:
		string name() const { return "BeOS Statistics"; }

		void poll(Entropy_Accumulator& accum);
};