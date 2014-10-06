/*
* /dev/random EntropySource
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.entropy_src;
import vector;
import string;
/**
* Entropy source reading from kernel devices like /dev/random
*/
class Device_EntropySource : EntropySource
{
	public:
		string name() const { return "RNG Device Reader"; }

		void poll(Entropy_Accumulator& accum);

		Device_EntropySource(in Vector!string fsnames);
		~this();
	private:
		typedef int fd_type;

		Vector!( fd_type ) m_devices;
};