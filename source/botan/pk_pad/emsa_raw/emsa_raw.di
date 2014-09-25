/*
* EMSA-Raw
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/emsa.h>
/**
* EMSA-Raw - sign inputs directly
* Don't use this unless you know what you are doing.
*/
class EMSA_Raw : public EMSA
{
	private:
		void update(const byte[], size_t);
		SafeArray!byte raw_data();

		SafeArray!byte encoding_of(in SafeArray!byte, size_t,
												 RandomNumberGenerator&);
		bool verify(in SafeArray!byte, in SafeArray!byte,
						size_t);

		SafeArray!byte message;
};