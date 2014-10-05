/*
* CRC24
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
/**
* 24-bit cyclic redundancy check
*/
class CRC24 : public HashFunction
{
	public:
		string name() const { return "CRC24"; }
		size_t output_length() const { return 3; }
		HashFunction clone() const { return new CRC24; }

		void clear() { crc = 0xB704CE; }

		CRC24() { clear(); }
		~this() { clear(); }
	private:
		void add_data(const ubyte[], size_t);
		void final_result(ubyte[]);
		uint crc;
};