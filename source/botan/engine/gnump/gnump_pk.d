/*
* GnuMP PK operations
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.gnump_engine;
import botan.internal.gmp_wrap;
import gmp.h;

/* GnuMP 5.0 and later have a side-channel resistent powm */
#if defined(HAVE_MPZ_POWM_SEC)
	#undef mpz_powm
	#define mpz_powm mpz_powm_sec
#endif

#if defined(BOTAN_HAS_RSA)
  import botan.rsa;
#endif

#if defined(BOTAN_HAS_DSA)
  import botan.dsa;
#endif

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
  import botan.dh;
#endif
namespace {

#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
class GMP_DH_KA_Operation : public PK_Ops::Key_Agreement
{
	public:
		GMP_DH_KA_Operation(in DH_PrivateKey dh) :
			x(dh.get_x()), p(dh.group_p()) {}

		SafeVector!byte agree(in byte* w, size_t w_len)
		{
			GMP_MPZ z(w, w_len);
			mpz_powm(z.value, z.value, x.value, p.value);
			return z.to_bytes();
		}

	private:
		GMP_MPZ x, p;
};
#endif

#if defined(BOTAN_HAS_DSA)

class GMP_DSA_Signature_Operation : public PK_Ops::Signature
{
	public:
		GMP_DSA_Signature_Operation(in DSA_PrivateKey dsa) :
			x(dsa.get_x()),
			p(dsa.group_p()),
			q(dsa.group_q()),
			g(dsa.group_g()),
			q_bits(dsa.group_q().bits()) {}

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }

		SafeVector!byte sign(in byte* msg, size_t msg_len,
										RandomNumberGenerator& rng);
	private:
		const GMP_MPZ x, p, q, g;
		size_t q_bits;
};

SafeVector!byte
GMP_DSA_Signature_Operation::sign(in byte* msg, size_t msg_len,
											 RandomNumberGenerator& rng)
{
	const size_t q_bytes = (q_bits + 7) / 8;

	rng.add_entropy(msg, msg_len);

	BigInt k_bn;
	do
		k_bn.randomize(rng, q_bits);
	while(k_bn >= q.to_bigint());

	GMP_MPZ i(msg, msg_len);
	GMP_MPZ k(k_bn);

	GMP_MPZ r;
	mpz_powm(r.value, g.value, k.value, p.value);
	mpz_mod(r.value, r.value, q.value);

	mpz_invert(k.value, k.value, q.value);

	GMP_MPZ s;
	mpz_mul(s.value, x.value, r.value);
	mpz_add(s.value, s.value, i.value);
	mpz_mul(s.value, s.value, k.value);
	mpz_mod(s.value, s.value, q.value);

	if (mpz_cmp_ui(r.value, 0) == 0 || mpz_cmp_ui(s.value, 0) == 0)
		throw new Internal_Error("GMP_DSA_Op::sign: r or s was zero");

	SafeVector!byte output(2*q_bytes);
	r.encode(&output[0], q_bytes);
	s.encode(&output[q_bytes], q_bytes);
	return output;
}

class GMP_DSA_Verification_Operation : public PK_Ops::Verification
{
	public:
		GMP_DSA_Verification_Operation(in DSA_PublicKey dsa) :
			y(dsa.get_y()),
			p(dsa.group_p()),
			q(dsa.group_q()),
			g(dsa.group_g()),
			q_bits(dsa.group_q().bits()) {}

		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }

		bool with_recovery() const { return false; }

		bool verify(in byte* msg, size_t msg_len,
						in byte* sig, size_t sig_len);
	private:
		const GMP_MPZ y, p, q, g;
		size_t q_bits;
};

bool GMP_DSA_Verification_Operation::verify(in byte* msg, size_t msg_len,
														  in byte* sig, size_t sig_len)
{
	const size_t q_bytes = q.bytes();

	if (sig_len != 2*q_bytes || msg_len > q_bytes)
		return false;

	GMP_MPZ r(sig, q_bytes);
	GMP_MPZ s(sig + q_bytes, q_bytes);
	GMP_MPZ i(msg, msg_len);

	if (mpz_cmp_ui(r.value, 0) <= 0 || mpz_cmp(r.value, q.value) >= 0)
		return false;
	if (mpz_cmp_ui(s.value, 0) <= 0 || mpz_cmp(s.value, q.value) >= 0)
		return false;

	if (mpz_invert(s.value, s.value, q.value) == 0)
		return false;

	GMP_MPZ si;
	mpz_mul(si.value, s.value, i.value);
	mpz_mod(si.value, si.value, q.value);
	mpz_powm(si.value, g.value, si.value, p.value);

	GMP_MPZ sr;
	mpz_mul(sr.value, s.value, r.value);
	mpz_mod(sr.value, sr.value, q.value);
	mpz_powm(sr.value, y.value, sr.value, p.value);

	mpz_mul(si.value, si.value, sr.value);
	mpz_mod(si.value, si.value, p.value);
	mpz_mod(si.value, si.value, q.value);

	if (mpz_cmp(si.value, r.value) == 0)
		return true;
	return false;#if defined(BOTAN_HAS_RSA)

class GMP_RSA_Private_Operation : public PK_Ops::Signature,
											 public PK_Ops::Decryption
{
	public:
		GMP_RSA_Private_Operation(in RSA_PrivateKey rsa) :
			mod(rsa.get_n()),
			p(rsa.get_p()),
			q(rsa.get_q()),
			d1(rsa.get_d1()),
			d2(rsa.get_d2()),
			c(rsa.get_c()),
			n_bits(rsa.get_n().bits())
		{}

		size_t max_input_bits() const { return (n_bits - 1); }

		SafeVector!byte sign(in byte* msg, size_t msg_len,
										RandomNumberGenerator&)
		{
			BigInt m(msg, msg_len);
			BigInt x = private_op(m);
			return BigInt::encode_1363(x, (n_bits + 7) / 8);
		}

		SafeVector!byte decrypt(in byte* msg, size_t msg_len)
		{
			BigInt m(msg, msg_len);
			return BigInt::encode_locked(private_op(m));
		}

	private:
		BigInt private_op(in BigInt m) const;

		GMP_MPZ mod, p, q, d1, d2, c;
		size_t n_bits;
};

BigInt GMP_RSA_Private_Operation::private_op(in BigInt m) const
{
	GMP_MPZ j1, j2, h(m);

	mpz_powm(j1.value, h.value, d1.value, p.value);
	mpz_powm(j2.value, h.value, d2.value, q.value);
	mpz_sub(h.value, j1.value, j2.value);
	mpz_mul(h.value, h.value, c.value);
	mpz_mod(h.value, h.value, p.value);
	mpz_mul(h.value, h.value, q.value);
	mpz_add(h.value, h.value, j2.value);
	return h.to_bigint();
}

class GMP_RSA_Public_Operation : public PK_Ops::Verification,
											public PK_Ops::Encryption
{
	public:
		GMP_RSA_Public_Operation(in RSA_PublicKey rsa) :
			n(rsa.get_n()), e(rsa.get_e()), mod(rsa.get_n())
		{}

		size_t max_input_bits() const { return (n.bits() - 1); }
		bool with_recovery() const { return true; }

		SafeVector!byte encrypt(in byte* msg, size_t msg_len,
											RandomNumberGenerator&)
		{
			BigInt m(msg, msg_len);
			return BigInt::encode_1363(public_op(m), n.bytes());
		}

		SafeVector!byte verify_mr(in byte* msg, size_t msg_len)
		{
			BigInt m(msg, msg_len);
			return BigInt::encode_locked(public_op(m));
		}

	private:
		BigInt public_op(in BigInt m) const
		{
			if (m >= n)
				throw new Invalid_Argument("RSA public op - input is too large");

			GMP_MPZ m_gmp(m);
			mpz_powm(m_gmp.value, m_gmp.value, e.value, mod.value);
			return m_gmp.to_bigint();
		}

		ref const BigInt n;
		const GMP_MPZ e, mod;
};

#endif

}

PK_Ops::Key_Agreement*
GMP_Engine::get_key_agreement_op(in Private_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_DIFFIE_HELLMAN)
	if (in DH_PrivateKey* dh = cast(const DH_PrivateKey*)(key))
		return new GMP_DH_KA_Operation(*dh);
#endif

	return null;
}

PK_Ops::Signature*
GMP_Engine::get_signature_op(in Private_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new GMP_RSA_Private_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PrivateKey* s = cast(const DSA_PrivateKey*)(key))
		return new GMP_DSA_Signature_Operation(*s);
#endif

	return null;
}

PK_Ops::Verification*
GMP_Engine::get_verify_op(in Public_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new GMP_RSA_Public_Operation(*s);
#endif

#if defined(BOTAN_HAS_DSA)
	if (in DSA_PublicKey* s = cast(const DSA_PublicKey*)(key))
		return new GMP_DSA_Verification_Operation(*s);
#endif

	return null;
}

PK_Ops::Encryption*
GMP_Engine::get_encryption_op(in Public_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PublicKey* s = cast(const RSA_PublicKey*)(key))
		return new GMP_RSA_Public_Operation(*s);
#endif

	return null;
}

PK_Ops::Decryption*
GMP_Engine::get_decryption_op(in Private_Key key, RandomNumberGenerator&) const
{
#if defined(BOTAN_HAS_RSA)
	if (in RSA_PrivateKey* s = cast(const RSA_PrivateKey*)(key))
		return new GMP_RSA_Private_Operation(*s);
#endif

	return null;
}

}
