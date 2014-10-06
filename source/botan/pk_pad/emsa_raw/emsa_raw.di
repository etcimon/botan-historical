/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.emsa;
/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
class EMSA_Raw : EMSA
{
	private:
		void update(const ubyte[], size_t);
		SafeVector!ubyte raw_data();

		SafeVector!ubyte encoding_of(in SafeVector!ubyte, size_t,
												 RandomNumberGenerator);
		bool verify(in SafeVector!ubyte, in SafeVector!ubyte,
						size_t);

		SafeVector!ubyte message;
};