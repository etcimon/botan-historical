/*
* OpenSSL Modular Exponentiation
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.openssl_engine;
import botan.internal.bn_wrap;
namespace {

/*
* OpenSSL Modular Exponentiator
*/
class OpenSSL_Modular_Exponentiator : Modular_Exponentiator
{
	public:
		void set_base(in BigInt b) { base = b; }
		void set_exponent(in BigInt e) { exp = e; }
		BigInt execute() const;
		Modular_Exponentiator* copy() const
		{ return new OpenSSL_Modular_Exponentiator(*this); }

		OpenSSL_Modular_Exponentiator(in BigInt n) : mod(n) {}
	private:
		OSSL_BN base, exp, mod;
		OSSL_BN_CTX ctx;
};

/*
* Compute the result
*/
BigInt OpenSSL_Modular_Exponentiator::execute() const
{
	OSSL_BN r;
	BN_mod_exp(r.ptr(), base.ptr(), exp.ptr(), mod.ptr(), ctx.ptr());
	return r.to_bigint();
}

}

/*
* Return the OpenSSL-based modular exponentiator
*/
Modular_Exponentiator* OpenSSL_Engine::mod_exp(in BigInt n,
															  Power_Mod::Usage_Hints) const
{
	return new OpenSSL_Modular_Exponentiator(n);
}

}
