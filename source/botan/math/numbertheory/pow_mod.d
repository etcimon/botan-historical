/*
* Modular Exponentiation Proxy
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pow_mod;
import botan.libstate;
import botan.engine;
/*
* Power_Mod Constructor
*/
Power_Mod::Power_Mod(in BigInt n, Usage_Hints hints)
{
	core = null;
	set_modulus(n, hints);
}

/*
* Power_Mod Copy Constructor
*/
Power_Mod::Power_Mod(in Power_Mod other)
{
	core = null;
	if (other.core)
		core = other.core.copy();
}

/*
* Power_Mod Assignment Operator
*/
Power_Mod& Power_Mod::operator=(in Power_Mod other)
{
	delete core;
	core = null;
	if (other.core)
		core = other.core.copy();
	return (*this);
}

/*
* Power_Mod Destructor
*/
Power_Mod::~this()
{
	delete core;
}

/*
* Set the modulus
*/
void Power_Mod::set_modulus(in BigInt n, Usage_Hints hints) const
{
	delete core;
	core = null;

	if (n != 0)
	{
		Algorithm_Factory.Engine_Iterator i(global_state().algorithm_factory());

		while(const Engine engine = i.next())
		{
			core = engine.mod_exp(n, hints);

			if (core)
				break;
		}

		if (!core)
			throw new Lookup_Error("Power_Mod: Unable to find a working engine");
	}
}

/*
* Set the base
*/
void Power_Mod::set_base(in BigInt b) const
{
	if (b.is_zero() || b.is_negative())
		throw new Invalid_Argument("Power_Mod::set_base: arg must be > 0");

	if (!core)
		throw new Internal_Error("Power_Mod::set_base: core was NULL");
	core.set_base(b);
}

/*
* Set the exponent
*/
void Power_Mod::set_exponent(in BigInt e) const
{
	if (e.is_negative())
		throw new Invalid_Argument("Power_Mod::set_exponent: arg must be > 0");

	if (!core)
		throw new Internal_Error("Power_Mod::set_exponent: core was NULL");
	core.set_exponent(e);
}

/*
* Compute the result
*/
BigInt Power_Mod::execute() const
{
	if (!core)
		throw new Internal_Error("Power_Mod::execute: core was NULL");
	return core.execute();
}

/*
* Try to choose a good window size
*/
size_t Power_Mod::window_bits(size_t exp_bits, size_t,
										Power_Mod::Usage_Hints hints)
{
	immutable size_t[][2] wsize = {
	{ 1434, 7 },
	{  539, 6 },
	{  197, 4 },
	{	70, 3 },
	{	25, 2 },
	{	 0, 0 }
};

	size_t window_bits = 1;

	if (exp_bits)
	{
		for (size_t j = 0; wsize[j][0]; ++j)
		{
			if (exp_bits >= wsize[j][0])
			{
				window_bits += wsize[j][1];
				break;
			}
		}
	}

	if (hints & Power_Mod::BASE_IS_FIXED)
		window_bits += 2;
	if (hints & Power_Mod::EXP_IS_LARGE)
		++window_bits;

	return window_bits;
}

namespace {

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_base_hints(in BigInt b, ref const BigInt n)
{
	if (b == 2)
		return Power_Mod::Usage_Hints(Power_Mod::BASE_IS_2 |
												Power_Mod::BASE_IS_SMALL);

	const size_t b_bits = b.bits();
	const size_t n_bits = n.bits();

	if (b_bits < n_bits / 32)
		return Power_Mod::BASE_IS_SMALL;
	if (b_bits > n_bits / 4)
		return Power_Mod::BASE_IS_LARGE;

	return Power_Mod::NO_HINTS;
}

/*
* Choose potentially useful hints
*/
Power_Mod::Usage_Hints choose_exp_hints(in BigInt e, ref const BigInt n)
{
	const size_t e_bits = e.bits();
	const size_t n_bits = n.bits();

	if (e_bits < n_bits / 32)
		return Power_Mod::BASE_IS_SMALL;
	if (e_bits > n_bits / 4)
		return Power_Mod::BASE_IS_LARGE;
	return Power_Mod::NO_HINTS;
}

}

/*
* Fixed_Exponent_Power_Mod Constructor
*/
Fixed_Exponent_Power_Mod::Fixed_Exponent_Power_Mod(in BigInt e,
																	ref const BigInt n,
																	Usage_Hints hints) :
	Power_Mod(n, Usage_Hints(hints | EXP_IS_FIXED | choose_exp_hints(e, n)))
{
	set_exponent(e);
}

/*
* Fixed_Base_Power_Mod Constructor
*/
Fixed_Base_Power_Mod::Fixed_Base_Power_Mod(in BigInt b, ref const BigInt n,
														 Usage_Hints hints) :
	Power_Mod(n, Usage_Hints(hints | BASE_IS_FIXED | choose_base_hints(b, n)))
{
	set_base(b);
}

}
