/*
* GMP Wrapper
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.gmp_wrap;

#define GNU_MP_VERSION_CODE_FOR(a,b,c) ((a << 16) | (b << 8) | (c))

#define GNU_MP_VERSION_CODE \
	GNU_MP_VERSION_CODE_FOR(__GNU_MP_VERSION, __GNU_MP_VERSION_MINOR, \
									__GNU_MP_VERSION_PATCHLEVEL)

#if GNU_MP_VERSION_CODE < GNU_MP_VERSION_CODE_FOR(4,1,0)
  #error Your GNU MP install is too old, upgrade to 4.1 or later
#endif
/*
* GMP_MPZ Constructor
*/
GMP_MPZ::GMP_MPZ(in BigInt input)
{
	mpz_init(value);
	if (input != 0)
		mpz_import(value, input.sig_words(), -1, sizeof(word), 0, 0, input.data());
}

/*
* GMP_MPZ Constructor
*/
GMP_MPZ::GMP_MPZ(in ubyte* input, size_t length)
{
	mpz_init(value);
	mpz_import(value, length, 1, 1, 0, 0, input);
}

/*
* GMP_MPZ Copy Constructor
*/
GMP_MPZ::GMP_MPZ(in GMP_MPZ other)
{
	mpz_init_set(value, other.value);
}

/*
* GMP_MPZ Destructor
*/
GMP_MPZ::~this()
{
	mpz_clear(value);
}

/*
* GMP_MPZ Assignment Operator
*/
GMP_MPZ& GMP_MPZ::operator=(in GMP_MPZ other)
{
	mpz_set(value, other.value);
	return (*this);
}

/*
* Export the mpz_t as a bytestring
*/
void GMP_MPZ::encode(ubyte* output) const
{
	size_t length = output.length;
	size_t dummy = 0;
	mpz_export(output.ptr + (length - bytes()), &dummy, 1, 1, 0, 0, value);
}

/*
* Return the number of significant bytes
*/
size_t GMP_MPZ::bytes() const
{
	return ((mpz_sizeinbase(value, 2) + 7) / 8);
}

/*
* GMP to BigInt Conversions
*/
BigInt GMP_MPZ::to_bigint() const
{
	BigInt output = BigInt(BigInt.Positive, (bytes() + sizeof(word) - 1) / sizeof(word));
	size_t dummy = 0;

	word* reg = output.mutable_data();

	mpz_export(reg, &dummy, -1, sizeof(word), 0, 0, value);

	if (mpz_sgn(value) < 0)
		output.flip_sign();

	return output;
}

}
