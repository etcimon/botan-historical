/*
* GMP MPZ Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import gmp.h;
/**
* Lightweight GMP mpz_t wrapper. For internal use only.
*/
class GMP_MPZ
{
	public:
		mpz_t value;

		BigInt to_bigint() const;
		void encode(byte[], size_t) const;
		size_t bytes() const;

		SafeVector!byte to_bytes() const
		{ return BigInt::encode_locked(to_bigint()); }

		GMP_MPZ& operator=(in GMP_MPZ);

		GMP_MPZ(in GMP_MPZ);
		GMP_MPZ(in BigInt = 0);
		GMP_MPZ(const byte[], size_t);
		~GMP_MPZ();
};