/*
* Modular Exponentiator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.pow_mod;

import botan.math.bigint.bigint;
import botan.libstate.libstate;
import botan.engine.engine;

/**
* Modular Exponentiator Interface
*/
class Modular_Exponentiator
{
public:
	abstract void set_base(in BigInt);
	abstract void set_exponent(in BigInt);
	abstract BigInt execute() const;
	abstract Modular_Exponentiator copy() const;
	~this() {}
}

/**
* Modular Exponentiator Proxy
*/
class Power_Mod
{
public:
	typedef ushort Usage_Hints;
	enum : Usage_Hints {
		NO_HINTS		  = 0x0000,

		BASE_IS_FIXED	= 0x0001,
		BASE_IS_SMALL	= 0x0002,
		BASE_IS_LARGE	= 0x0004,
		BASE_IS_2		 = 0x0008,

		EXP_IS_FIXED	 = 0x0100,
		EXP_IS_SMALL	 = 0x0200,
		EXP_IS_LARGE	 = 0x0400
	}

	/*
	* Try to choose a good window size
	*/
	static size_t window_bits(size_t exp_bits, size_t,
	                          Power_Mod.Usage_Hints hints)
	{
		__gshared immutable size_t[][2] wsize = [
			[ 1434, 7 ],
			[  539, 6 ],
			[  197, 4 ],
			[	70, 3 ],
			[	25, 2 ],
			[	 0, 0 ]
		];
		
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
		
		if (hints & Power_Mod.BASE_IS_FIXED)
			window_bits += 2;
		if (hints & Power_Mod.EXP_IS_LARGE)
			++window_bits;
		
		return window_bits;
	}

	/*
	* Set the modulus
	*/
	void set_modulus(in BigInt n, Usage_Hints hints = NO_HINTS)
	{
		delete core;
		core = null;
		
		if (n != 0)
		{
			Algorithm_Factory af = global_state().algorithm_factory();

			foreach (Engine engine; af.engines) {
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
	void set_base(in BigInt b) const
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
	void set_exponent(in BigInt e) const
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
	BigInt execute()
	{
		if (!core)
			throw new Internal_Error("Power_Mod::execute: core was NULL");
		return core.execute();
	}

	/*
	* Power_Mod Assignment Operator
	*/
	ref Power_Mod opAssign(in Power_Mod other)
	{
		delete core;
		core = null;
		if (other.core)
			core = other.core.copy();
		return this;
	}

	this(in BigInt n, Usage_Hints hints = NO_HINTS)
	{
		core = null;
		set_modulus(n, hints);
	}

	this(in Power_Mod other)
	{
		core = null;
		if (other.core)
			core = other.core.copy();
	}

	~this()
	{
		delete core;
	}
private:
	Modular_Exponentiator core;
}

/**
* Fixed Exponent Modular Exponentiator Proxy
*/
class Fixed_Exponent_Power_Mod : Power_Mod
{
public:
	BigInt opCall(in BigInt b) const
	{ set_base(b); return execute(); }

	this() {}

	/*
	* Fixed_Exponent_Power_Mod Constructor
	*/
	this(in BigInt e,
         const ref BigInt n,
         Usage_Hints hints = NO_HINTS)
	{ 
		super(n, Usage_Hints(hints | EXP_IS_FIXED | choose_exp_hints(e, n)));
		set_exponent(e);
	}
	

}

/**
* Fixed Base Modular Exponentiator Proxy
*/
class Fixed_Base_Power_Mod : Power_Mod
{
public:
	BigInt opCall(in BigInt e) const
	{ set_exponent(e); return execute(); }

	this() {}
	/*
	* Fixed_Base_Power_Mod Constructor
	*/
	this(in BigInt b, const ref BigInt n,
    		Usage_Hints hints = NO_HINTS)
	{
		super(n, Usage_Hints(hints | BASE_IS_FIXED | choose_base_hints(b, n)));
		set_base(b);
	}

}


/*
* Choose potentially useful hints
*/
Power_Mod.Usage_Hints choose_base_hints(in BigInt b, const ref BigInt n)
{
	if (b == 2)
		return Power_Mod.Usage_Hints(Power_Mod.BASE_IS_2 |
		                             Power_Mod.BASE_IS_SMALL);
	
	const size_t b_bits = b.bits();
	const size_t n_bits = n.bits();
	
	if (b_bits < n_bits / 32)
		return Power_Mod.BASE_IS_SMALL;
	if (b_bits > n_bits / 4)
		return Power_Mod.BASE_IS_LARGE;
	
	return Power_Mod.NO_HINTS;
}

/*
* Choose potentially useful hints
*/
Power_Mod.Usage_Hints choose_exp_hints(in BigInt e, const ref BigInt n) pure
{
	const size_t e_bits = e.bits();
	const size_t n_bits = n.bits();

	if (e_bits < n_bits / 32)
		return Power_Mod.BASE_IS_SMALL;
	if (e_bits > n_bits / 4)
		return Power_Mod.BASE_IS_LARGE;
	return Power_Mod.NO_HINTS;
}