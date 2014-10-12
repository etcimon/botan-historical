/*
* RSA
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.if_algo;
import botan.pubkey.pk_ops;
import botan.reducer;
import botan.blinding;
/**
* RSA Public Key
*/
class RSA_PublicKey : IF_Scheme_PublicKey
{
	public:
		string algo_name() const { return "RSA"; }

		RSA_PublicKey(in AlgorithmIdentifier alg_id,
						  in SafeVector!ubyte key_bits) :
			IF_Scheme_PublicKey(alg_id, key_bits)
		{}

		/**
		* Create a RSA_PublicKey
		* @arg n the modulus
		* @arg e the exponent
		*/
		RSA_PublicKey(in BigInt n, ref const BigInt e) :
			IF_Scheme_PublicKey(n, e)
		{}

	package:
		RSA_PublicKey() {}
};

/**
* RSA Private Key
*/
class RSA_PrivateKey : RSA_PublicKey,
											public IF_Scheme_PrivateKey
{
	public:
		bool check_key(RandomNumberGenerator rng, bool) const;

		RSA_PrivateKey(in AlgorithmIdentifier alg_id,
							in SafeVector!ubyte key_bits,
							RandomNumberGenerator rng) :
			IF_Scheme_PrivateKey(rng, alg_id, key_bits) {}

		/**
		* Construct a private key from the specified parameters.
		* @param rng a random number generator
		* @param p the first prime
		* @param q the second prime
		* @param e the exponent
		* @param d if specified, this has to be d with
		* exp * d = 1 mod (p - 1, q - 1). Leave it as 0 if you wish to
		* the constructor to calculate it.
		* @param n if specified, this must be n = p * q. Leave it as 0
		* if you wish to the constructor to calculate it.
		*/
		RSA_PrivateKey(RandomNumberGenerator rng,
							ref const BigInt p, ref const BigInt q,
							ref const BigInt e, ref const BigInt d = 0,
							ref const BigInt n = 0) :
			IF_Scheme_PrivateKey(rng, p, q, e, d, n) {}

		/**
		* Create a new private key with the specified bit length
		* @param rng the random number generator to use
		* @param bits the desired bit length of the private key
		* @param exp the public exponent to be used
		*/
		RSA_PrivateKey(RandomNumberGenerator rng,
							size_t bits, size_t exp = 65537);
};

/**
* RSA private (decrypt/sign) operation
*/
class RSA_Private_Operation : pk_ops.Signature,
													 public pk_ops.Decryption
{
	public:
		RSA_Private_Operation(in RSA_PrivateKey rsa,
									 RandomNumberGenerator rng);

		size_t max_input_bits() const { return (n.bits() - 1); }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator rng);

		SafeVector!ubyte decrypt(in ubyte* msg, size_t msg_len);

	private:
		BigInt private_op(in BigInt m) const;

		ref const BigInt n;
		ref const BigInt q;
		ref const BigInt c;
		Fixed_Exponent_Power_Mod powermod_e_n, powermod_d1_p, powermod_d2_q;
		Modular_Reducer mod_p;
		Blinder blinder;
};

/**
* RSA public (encrypt/verify) operation
*/
class RSA_Public_Operation : pk_ops.Verification,
													public pk_ops.Encryption
{
	public:
		RSA_Public_Operation(in RSA_PublicKey rsa) :
			n(rsa.get_n()), powermod_e_n(rsa.get_e(), rsa.get_n())
		{}

		size_t max_input_bits() const { return (n.bits() - 1); }
		bool with_recovery() const { return true; }

		SafeVector!ubyte encrypt(in ubyte* msg, size_t msg_len,
											RandomNumberGenerator)
		{
			BigInt m(msg, msg_len);
			return BigInt.encode_1363(public_op(m), n.bytes());
		}

		SafeVector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
		{
			BigInt m(msg, msg_len);
			return BigInt.encode_locked(public_op(m));
		}

	private:
		BigInt public_op(in BigInt m) const
		{
			if (m >= n)
				throw new Invalid_Argument("RSA public op - input is too large");
			return powermod_e_n(m);
		}

		ref const BigInt n;
		Fixed_Exponent_Power_Mod powermod_e_n;
};