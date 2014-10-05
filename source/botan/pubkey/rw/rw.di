/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.if_algo;
import botan.pk_ops;
import botan.reducer;
import botan.blinding;
/**
* Rabin-Williams Public Key
*/
class RW_PublicKey : public abstract IF_Scheme_PublicKey
{
	public:
		string algo_name() const { return "RW"; }

		RW_PublicKey(in AlgorithmIdentifier alg_id,
						 in SafeVector!ubyte key_bits) :
			IF_Scheme_PublicKey(alg_id, key_bits)
		{}

		RW_PublicKey(in BigInt mod, ref const BigInt exponent) :
			IF_Scheme_PublicKey(mod, exponent)
		{}

	package:
		RW_PublicKey() {}
};

/**
* Rabin-Williams Private Key
*/
class RW_PrivateKey : public RW_PublicKey,
										  public IF_Scheme_PrivateKey
{
	public:
		RW_PrivateKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits,
						  RandomNumberGenerator rng) :
			IF_Scheme_PrivateKey(rng, alg_id, key_bits) {}

		RW_PrivateKey(RandomNumberGenerator rng,
						  ref const BigInt p, ref const BigInt q,
						  ref const BigInt e, ref const BigInt d = 0,
						  ref const BigInt n = 0) :
			IF_Scheme_PrivateKey(rng, p, q, e, d, n) {}

		RW_PrivateKey(RandomNumberGenerator rng, size_t bits, size_t = 2);

		bool check_key(RandomNumberGenerator rng, bool) const;
};

/**
* Rabin-Williams Signature Operation
*/
class RW_Signature_Operation : public PK_Ops::Signature
{
	public:
		RW_Signature_Operation(in RW_PrivateKey rw);

		size_t max_input_bits() const { return (n.bits() - 1); }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator rng);
	private:
		ref const BigInt n;
		ref const BigInt e;
		ref const BigInt q;
		ref const BigInt c;

		Fixed_Exponent_Power_Mod powermod_d1_p, powermod_d2_q;
		Modular_Reducer mod_p;
		Blinder blinder;
};

/**
* Rabin-Williams Verification Operation
*/
class RW_Verification_Operation : public PK_Ops::Verification
{
	public:
		RW_Verification_Operation(in RW_PublicKey rw) :
			n(rw.get_n()), powermod_e_n(rw.get_e(), rw.get_n())
		{}

		size_t max_input_bits() const { return (n.bits() - 1); }
		bool with_recovery() const { return true; }

		SafeVector!ubyte verify_mr(in ubyte* msg, size_t msg_len);

	private:
		ref const BigInt n;
		Fixed_Exponent_Power_Mod powermod_e_n;
};