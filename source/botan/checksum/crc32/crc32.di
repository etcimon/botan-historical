/*
* CRC32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
/**
* 32-bit cyclic redundancy check
*/
class CRC32 : public HashFunction
{
	public:
		string name() const { return "CRC32"; }
		size_t output_length() const { return 4; }
		HashFunction clone() const { return new CRC32; }

		void clear() { crc = 0xFFFFFFFF; }

		CRC32() { clear(); }
		~this() { clear(); }
	private:
		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);
		uint crc;
};