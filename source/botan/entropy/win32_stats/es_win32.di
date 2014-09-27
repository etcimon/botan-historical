/*
* Win32 EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
/**
* Win32 Entropy Source
*/
class Win32_EntropySource : public EntropySource
{
	public:
		string name() const { return "Win32 Statistics"; }
		void poll(Entropy_Accumulator& accum);
};