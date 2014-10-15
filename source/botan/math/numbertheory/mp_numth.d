/*
* Fused and Important MP Algorithms
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.numthry;
import botan.internal.mp_core;
import botan.utils.rounding;
import std.algorithm;
/*
* Square a BigInt
*/
BigInt square(in BigInt x)
{
	const size_t x_sw = x.sig_words();

	BigInt z(BigInt.Positive, round_up!size_t(2*x_sw, 16));
	SafeVector!word workspace(z.size());

	bigint_sqr(z.mutable_data(), z.size(),
				  &workspace[0],
				  x.data(), x.size(), x_sw);
	return z;
}

/*
* Multiply-Add Operation
*/
BigInt mul_add(in BigInt a, ref const BigInt b, ref const BigInt c)
{
	if (c.is_negative() || c.is_zero())
		throw new Invalid_Argument("mul_add: Third argument must be > 0");

	BigInt.Sign sign = BigInt.Positive;
	if (a.sign() != b.sign())
		sign = BigInt.Negative;

	const size_t a_sw = a.sig_words();
	const size_t b_sw = b.sig_words();
	const size_t c_sw = c.sig_words();

	BigInt r(sign, std.algorithm.max(a.size() + b.size(), c_sw) + 1);
	SafeVector!word workspace(r.size());

	bigint_mul(r.mutable_data(), r.size(),
				  &workspace[0],
				  a.data(), a.size(), a_sw,
				  b.data(), b.size(), b_sw);

	const size_t r_size = std.algorithm.max(r.sig_words(), c_sw);
	bigint_add2(r.mutable_data(), r_size, c.data(), c_sw);
	return r;
}

/*
* Subtract-Multiply Operation
*/
BigInt sub_mul(in BigInt a, ref const BigInt b, ref const BigInt c)
{
	if (a.is_negative() || b.is_negative())
		throw new Invalid_Argument("sub_mul: First two arguments must be >= 0");

	BigInt r = a;
	r -= b;
	r *= c;
	return r;
}

}
