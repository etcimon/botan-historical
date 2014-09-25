/*
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/entropy_src.h>
/**
* BeOS Entropy Source
*/
class BeOS_EntropySource : public EntropySource
{
	private:
		string name() const { return "BeOS Statistics"; }

		void poll(Entropy_Accumulator& accum);
};