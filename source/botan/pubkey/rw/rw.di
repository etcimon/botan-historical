/*
* Rabin-Williams
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/if_algo.h>
#include <botan/pk_ops.h>
#include <botan/reducer.h>
#include <botan/blinding.h>
/**
* Rabin-Williams Public Key
*/
class RW_PublicKey : public abstract IF_Scheme_PublicKey
{
	public:
		string algo_name() const { return "RW"; }

		RW_PublicKey(const AlgorithmIdentifier& alg_id,
						 in SafeArray!byte key_bits) :
			IF_Scheme_PublicKey(alg_id, key_bits)
		{}

		RW_PublicKey(const BigInt& mod, const BigInt& exponent) :
			IF_Scheme_PublicKey(mod, exponent)
		{}

	protected:
		RW_PublicKey() {}
};

/**
* Rabin-Williams Private Key
*/
class RW_PrivateKey : public RW_PublicKey,
										  public IF_Scheme_PrivateKey
{
	public:
		RW_PrivateKey(const AlgorithmIdentifier& alg_id,
						  in SafeArray!byte key_bits,
						  RandomNumberGenerator& rng) :
			IF_Scheme_PrivateKey(rng, alg_id, key_bits) {}

		RW_PrivateKey(RandomNumberGenerator& rng,
						  const BigInt& p, const BigInt& q,
						  const BigInt& e, const BigInt& d = 0,
						  const BigInt& n = 0) :
			IF_Scheme_PrivateKey(rng, p, q, e, d, n) {}

		RW_PrivateKey(RandomNumberGenerator& rng, size_t bits, size_t = 2);

		bool check_key(RandomNumberGenerator& rng, bool) const;
};

/**
* Rabin-Williams Signature Operation
*/
class RW_Signature_Operation : public PK_Ops::Signature
{
	public:
		RW_Signature_Operation(const RW_PrivateKey& rw);

		size_t max_input_bits() const { return (n.bits() - 1); }

		SafeArray!byte sign(in byte[] msg, size_t msg_len,
										RandomNumberGenerator& rng);
	private:
		const BigInt& n;
		const BigInt& e;
		const BigInt& q;
		const BigInt& c;

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
		RW_Verification_Operation(const RW_PublicKey& rw) :
			n(rw.get_n()), powermod_e_n(rw.get_e(), rw.get_n())
		{}

		size_t max_input_bits() const { return (n.bits() - 1); }
		bool with_recovery() const { return true; }

		SafeArray!byte verify_mr(in byte[] msg, size_t msg_len);

	private:
		const BigInt& n;
		Fixed_Exponent_Power_Mod powermod_e_n;
};