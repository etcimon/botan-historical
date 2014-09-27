/*
* Modular Exponentiator
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
/**
* Modular Exponentiator Interface
*/
class Modular_Exponentiator
{
	public:
		abstract void set_base(in BigInt);
		abstract void set_exponent(in BigInt);
		abstract BigInt execute() const;
		abstract Modular_Exponentiator* copy() const;
		~this() {}
};

/**
* Modular Exponentiator Proxy
*/
class Power_Mod
{
	public:

		enum Usage_Hints {
			NO_HINTS		  = 0x0000,

			BASE_IS_FIXED	= 0x0001,
			BASE_IS_SMALL	= 0x0002,
			BASE_IS_LARGE	= 0x0004,
			BASE_IS_2		 = 0x0008,

			EXP_IS_FIXED	 = 0x0100,
			EXP_IS_SMALL	 = 0x0200,
			EXP_IS_LARGE	 = 0x0400
	};

		/*
		* Try to choose a good window size
		*/
		static size_t window_bits(size_t exp_bits, size_t base_bits,
										  Power_Mod::Usage_Hints hints);

		void set_modulus(in BigInt, Usage_Hints = NO_HINTS) const;
		void set_base(in BigInt) const;
		void set_exponent(in BigInt) const;

		BigInt execute() const;

		Power_Mod& operator=(in Power_Mod);

		Power_Mod(in BigInt = 0, Usage_Hints = NO_HINTS);
		Power_Mod(in Power_Mod);
		~this();
	private:
		mutable Modular_Exponentiator* core;
};

/**
* Fixed Exponent Modular Exponentiator Proxy
*/
class Fixed_Exponent_Power_Mod : public Power_Mod
{
	public:
		BigInt operator()(in BigInt b) const
		{ set_base(b); return execute(); }

		Fixed_Exponent_Power_Mod() {}

		Fixed_Exponent_Power_Mod(in BigInt exponent,
										 ref const BigInt modulus,
										 Usage_Hints hints = NO_HINTS);
};

/**
* Fixed Base Modular Exponentiator Proxy
*/
class Fixed_Base_Power_Mod : public Power_Mod
{
	public:
		BigInt operator()(in BigInt e) const
		{ set_exponent(e); return execute(); }

		Fixed_Base_Power_Mod() {}

		Fixed_Base_Power_Mod(in BigInt base,
									ref const BigInt modulus,
									Usage_Hints hints = NO_HINTS);
};