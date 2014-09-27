/*
* Adler32
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.hash;
/**
* The Adler32 checksum, used in zlib
*/
class Adler32 : public HashFunction
{
	public:
		string name() const { return "Adler32"; }
		size_t output_length() const { return 4; }
		HashFunction* clone() const { return new Adler32; }

		void clear() { S1 = 1; S2 = 0; }

		Adler32() { clear(); }
		~Adler32() { clear(); }
	private:
		void add_data(const byte[], size_t);
		void final_result(byte[]);
		ushort S1, S2;
};