/*
* Format Preserving Encryption (FE1 scheme)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.fpe_fe1;
import botan.numthry;
import botan.hmac;
import botan.sha2_32;
import stdexcept;
namespace FPE {

namespace {

// Normally FPE is for SSNs, CC#s, etc, nothing too big
const size_t MAX_N_BYTES = 128/8;

/*
* Factor n into a and b which are as close together as possible.
* Assumes n is composed mostly of small factors which is the case for
* typical uses of FPE (typically, n is a power of 10)
*
* Want a >= b since the safe number of rounds is 2+log_a(b); if a >= b
* then this is always 3
*/
void factor(BigInt n, ref BigInt a, ref BigInt b)
{
	a = 1;
	b = 1;

	size_t n_low_zero = low_zero_bits(n);

	a <<= (n_low_zero / 2);
	b <<= n_low_zero - (n_low_zero / 2);
	n >>= n_low_zero;

	for (size_t i = 0; i != PRIME_TABLE_SIZE; ++i)
	{
		while(n % PRIMES[i] == 0)
		{
			a *= PRIMES[i];
			if (a > b)
				std::swap(a, b);
			n /= PRIMES[i];
		}
	}

	if (a > b)
		std::swap(a, b);
	a *= n;
	if (a < b)
		std::swap(a, b);

	if (a <= 1 || b <= 1)
		throw new Exception("Could not factor n for use in FPE");
}

/*
* According to a paper by Rogaway, Bellare, etc, the min safe number
* of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) <= 1
* so 3 rounds is safe. The FPE factorization routine should always
* return a >= b, so just confirm that and return 3.
*/
size_t rounds(in BigInt a, ref const BigInt b)
{
	if (a < b)
		throw new std::logic_error("FPE rounds: a < b");
	return 3;
}

/*
* A simple round function based on HMAC(SHA-256)
*/
class FPE_Encryptor
{
	public:
		FPE_Encryptor(in SymmetricKey key,
						  ref const BigInt n,
						  in Vector!byte tweak);

		BigInt operator()(size_t i, ref const BigInt R);

	private:
		std::unique_ptr<MessageAuthenticationCode> mac;
		Vector!( byte ) mac_n_t;
};

FPE_Encryptor::FPE_Encryptor(in SymmetricKey key,
									  ref const BigInt n,
									  in Vector!byte tweak)
{
	mac.reset(new HMAC(new SHA_256));
	mac->set_key(key);

	Vector!( byte ) n_bin = BigInt::encode(n);

	if (n_bin.size() > MAX_N_BYTES)
		throw new Exception("N is too large for FPE encryption");

	mac->update_be(cast(uint)(n_bin.size()));
	mac->update(&n_binput[0], n_bin.size());

	mac->update_be(cast(uint)(tweak.size()));
	mac->update(&tweak[0], tweak.size());

	mac_n_t = unlock(mac->flush());
}

BigInt FPE_Encryptor::operator()(size_t round_no, ref const BigInt R)
{
	SafeVector!byte r_bin = BigInt::encode_locked(R);

	mac->update(mac_n_t);
	mac->update_be(cast(uint)(round_no));

	mac->update_be(cast(uint)(r_bin.size()));
	mac->update(&r_binput[0], r_bin.size());

	SafeVector!byte X = mac->flush();
	return BigInt(&X[0], X.size());
}

}

/*
* Generic Z_n FPE encryption, FE1 scheme
*/
BigInt fe1_encrypt(in BigInt n, ref const BigInt X0,
						 const SymmetricKey& key,
						 in Vector!byte tweak)
{
	FPE_Encryptor F(key, n, tweak);

	BigInt a, b;
	factor(n, a, b);

	const size_t r = rounds(a, b);

	BigInt X = X0;

	for (size_t i = 0; i != r; ++i)
	{
		BigInt L = X / b;
		BigInt R = X % b;

		BigInt W = (L + F(i, R)) % a;
		X = a * R + W;
	}

	return X;
}

/*
* Generic Z_n FPE decryption, FD1 scheme
*/
BigInt fe1_decrypt(in BigInt n, ref const BigInt X0,
						 const SymmetricKey& key,
						 in Vector!byte tweak)
{
	FPE_Encryptor F(key, n, tweak);

	BigInt a, b;
	factor(n, a, b);

	const size_t r = rounds(a, b);

	BigInt X = X0;

	for (size_t i = 0; i != r; ++i)
	{
		BigInt W = X % a;
		BigInt R = X / a;

		BigInt L = (W - F(r-i-1, R)) % a;
		X = b * L + R;
	}

	return X;
}

}

}
