/*
* OpenSSL PK operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.openssl_engine;
import botan.internal.bn_wrap;

#if defined(BOTAN_HAS_RSA)
  import botan.rsa;
#endif

#if defined(BOTAN_HAS_DSA)
  import botan.dsa;
#endif

#if defined(BOTAN_HAS_ECDSA)
  import botan.ecdsa;
  import openssl.ecdsa;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  import botan.dh;
#endif
namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
class OSSL_DH_KA_Operation : pk_ops.Key_Agreement
{
	public:
		OSSL_DH_KA_Operation(in DH_PrivateKey dh) :
			x(dh.get_x()), p(dh.group_p()) {}

		SafeVector!ubyte agree(in ubyte* w, size_t w_len)
		{
			OSSL_BN i(w, w_len), r;
			BN_mod_exp(r.ptr(), i.ptr(), x.ptr(), p.ptr(), ctx.ptr());
			return r.to_bytes();
		}

	private:
		const OSSL_BN x, p;
		OSSL_BN_CTX ctx;
};
#endif

#if defined(BOTAN_HAS_DSA)

class OSSL_DSA_Signature_Operation : pk_ops.Signature
{
	public:
		OSSL_DSA_Signature_Operation(in DSA_PrivateKey dsa) :
			x(dsa.get_x()),
			p(dsa.group_p()),
			q(dsa.group_q()),
			g(dsa.group_g()),
			q_bits(dsa.group_q().bits()) {}

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator rng);
	private:
		const OSSL_BN x, p, q, g;
		const OSSL_BN_CTX ctx;
		size_t q_bits;
};

SafeVector!ubyte
OSSL_DSA_Signature_Operation::sign(in ubyte* msg, size_t msg_len,
											 RandomNumberGenerator rng)
{
	const size_t q_bytes = (q_bits + 7) / 8;

	rng.add_entropy(msg, msg_len);

	BigInt k_bn;
	do
		k_bn.randomize(rng, q_bits);
	while(k_bn >= q.to_bigint());

	OSSL_BN i(msg, msg_len);
	OSSL_BN k(k_bn);

	OSSL_BN r;
	BN_mod_exp(r.ptr(), g.ptr(), k.ptr(), p.ptr(), ctx.ptr());
	BN_nnmod(r.ptr(), r.ptr(), q.ptr(), ctx.ptr());

	BN_mod_inverse(k.ptr(), k.ptr(), q.ptr(), ctx.ptr());

	OSSL_BN s;
	BN_mul(s.ptr(), x.ptr(), r.ptr(), ctx.ptr());
	BN_add(s.ptr(), s.ptr(), i.ptr());
	BN_mod_mul(s.ptr(), s.ptr(), k.ptr(), q.ptr(), ctx.ptr());

	if (BN_is_zero(r.ptr()) || BN_is_zero(s.ptr()))
		throw new Internal_Error("OpenSSL_DSA_Op::sign: r or s was zero");

	SafeVector!ubyte output = SafeVector!ubyte(2*q_bytes);
	r.encode(&output[0], q_bytes);
	s.encode(&output[q_bytes], q_bytes);
	return output;
}

class OSSL_DSA_Verification_Operation : pk_ops.Verification
{
	public:
		OSSL_DSA_Verification_Operation(in DSA_PublicKey dsa) :
			y(dsa.get_y()),
			p(dsa.group_p()),
			q(dsa.group_q()),
			g(dsa.group_g()),
			q_bits(dsa.group_q().bits()) {}

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }

		bool with_recovery() const { return false; }

		bool verify(in ubyte* msg, size_t msg_len,
						in ubyte* sig, size_t sig_len);
	private:
		const OSSL_BN y, p, q, g;
		const OSSL_BN_CTX ctx;
		size_t q_bits;
};

bool OSSL_DSA_Verification_Operation::verify(in ubyte* msg, size_t msg_len,
														  in ubyte* sig, size_t sig_len)
{
	const size_t q_bytes = q.bytes();

	if (sig_len != 2*q_bytes || msg_len > q_bytes)
		return false;

	OSSL_BN r(sig, q_bytes);
	OSSL_BN s(sig + q_bytes, q_bytes);
	OSSL_BN i(msg, msg_len);

	if (BN_is_zero(r.ptr()) || BN_cmp(r.ptr(), q.ptr()) >= 0)
		return false;
	if (BN_is_zero(s.ptr()) || BN_cmp(s.ptr(), q.ptr()) >= 0)
		return false;

	if (BN_mod_inverse(s.ptr(), s.ptr(), q.ptr(), ctx.ptr()) == 0)
		return false;

	OSSL_BN si;
	BN_mod_mul(si.ptr(), s.ptr(), i.ptr(), q.ptr(), ctx.ptr());
	BN_mod_exp(si.ptr(), g.ptr(), si.ptr(), p.ptr(), ctx.ptr());

	OSSL_BN sr;
	BN_mod_mul(sr.ptr(), s.ptr(), r.ptr(), q.ptr(), ctx.ptr());
	BN_mod_exp(sr.ptr(), y.ptr(), sr.ptr(), p.ptr(), ctx.ptr());

	BN_mod_mul(si.ptr(), si.ptr(), sr.ptr(), p.ptr(), ctx.ptr());
	BN_nnmod(si.ptr(), si.ptr(), q.ptr(), ctx.ptr());

	if (BN_cmp(si.ptr(), r.ptr()) == 0)
		return true;
	return false;

	return false;#if defined(BOTAN_HAS_RSA)

class OSSL_RSA_Private_Operation : pk_ops.Signature,
											  public pk_ops.Decryption
{
	public:
		OSSL_RSA_Private_Operation(in RSA_PrivateKey rsa) :
			mod(rsa.get_n()),
			p(rsa.get_p()),
			q(rsa.get_q()),
			d1(rsa.get_d1()),
			d2(rsa.get_d2()),
			c(rsa.get_c()),
			n_bits(rsa.get_n().bits())
		{}

		size_t max_input_bits() const { return (n_bits - 1); }

		SafeVector!ubyte sign(in ubyte* msg, size_t msg_len,
										RandomNumberGenerator)
		{
			BigInt m(msg, msg_len);
			BigInt x = private_op(m);
			return BigInt.encode_1363(x, (n_bits + 7) / 8);
		}

		SafeVector!ubyte decrypt(in ubyte* msg, size_t msg_len)
		{
			BigInt m(msg, msg_len);
			return BigInt.encode_locked(private_op(m));
		}

	private:
		BigInt private_op(in BigInt m) const;

		const OSSL_BN mod, p, q, d1, d2, c;
		const OSSL_BN_CTX ctx;
		size_t n_bits;
};

BigInt OSSL_RSA_Private_Operation::private_op(in BigInt m) const
{
	OSSL_BN j1, j2, h(m);

	BN_mod_exp(j1.ptr(), h.ptr(), d1.ptr(), p.ptr(), ctx.ptr());
	BN_mod_exp(j2.ptr(), h.ptr(), d2.ptr(), q.ptr(), ctx.ptr());
	BN_sub(h.ptr(), j1.ptr(), j2.ptr());
	BN_mod_mul(h.ptr(), h.ptr(), c.ptr(), p.ptr(), ctx.ptr());
	BN_mul(h.ptr(), h.ptr(), q.ptr(), ctx.ptr());
	BN_add(h.ptr(), h.ptr(), j2.ptr());
	return h.to_bigint();
}

class OSSL_RSA_Public_Operation : pk_ops.Verification,
											 public pk_ops.Encryption
{
	public:
		OSSL_RSA_Public_Operation(in RSA_PublicKey rsa) :
			n(rsa.get_n()), e(rsa.get_e()), mod(rsa.get_n())
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

			OSSL_BN m_bn(m), r;
			BN_mod_exp(r.ptr(), m_bn.ptr(), e.ptr(), mod.ptr(), ctx.ptr());
			return r.to_bigint();
		}

		ref const BigInt n;
		const OSSL_BN e, mod;
		const OSSL_BN_CTX ctx;
};

#endif

}

pk_ops.Key_Agreement
OpenSSL_Engine::get_key_agreement_op(in Private_Key key, RandomNumberGenerator) const
{
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	if (in DH_PrivateKey* dh = cast(const DH_PrivateKey*)(key))
		return new OSSL_DH_KA_Operation(*dh);
#endif

	return 0;
}

pk_ops.Signature
OpenSSL_Engine::get_signature_op(in Private_Key key, RandomNumberGenerator) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new OSSL_RSA_Private_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PrivateKey* s = cast(const DSA_PrivateKey*)(key))
		return new OSSL_DSA_Signature_Operation(*s);
#endif

	return 0;
}

pk_ops.Verification
OpenSSL_Engine::get_verify_op(in Public_Key key, RandomNumberGenerator) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new OSSL_RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PublicKey* s = cast(const DSA_PublicKey*)(key))
		return new OSSL_DSA_Verification_Operation(*s);
#endif

	return 0;
}

pk_ops.Encryption
OpenSSL_Engine::get_encryption_op(in Public_Key key, RandomNumberGenerator) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new OSSL_RSA_Public_Operation(*s);
#endif

	return 0;
}

pk_ops.Decryption
OpenSSL_Engine::get_decryption_op(in Private_Key key, RandomNumberGenerator) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new OSSL_RSA_Private_Operation(*s);
#endif

	return 0;
}

}
