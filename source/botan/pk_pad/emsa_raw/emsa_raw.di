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
class EMSA_Raw : public EMSA
{
	private:
		void update(const byte[], size_t);
		SafeVector!byte raw_data();

		SafeVector!byte encoding_of(in SafeVector!byte, size_t,
												 RandomNumberGenerator);
		bool verify(in SafeVector!byte, in SafeVector!byte,
						size_t);

		SafeVector!byte message;
};