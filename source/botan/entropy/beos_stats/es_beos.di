/*
* BeOS EntropySource
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#define BOTAN_ENTROPY_SRC_BEOS_H__

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