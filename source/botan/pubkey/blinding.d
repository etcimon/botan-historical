/*
* Blinding for public key operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.blinding;
import botan.math.numbertheory.numthry;
/*
* Blinder Constructor
*/
Blinder::Blinder(in BigInt e, const ref BigInt d, const ref BigInt n)
{
	if (e < 1 || d < 1 || n < 1)
		throw new Invalid_Argument("Blinder: Arguments too small");

	reducer = Modular_Reducer(n);
	this.e = e;
	this.d = d;
}

/*
* Blind a number
*/
BigInt Blinder::blind(in BigInt i) const
{
	if (!reducer.initialized())
		return i;

	e = reducer.square(e);
	d = reducer.square(d);
	return reducer.multiply(i, e);
}

/*
* Unblind a number
*/
BigInt Blinder::unblind(in BigInt i) const
{
	if (!reducer.initialized())
		return i;
	return reducer.multiply(i, d);
}

}
