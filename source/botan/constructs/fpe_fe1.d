/*
* Format Preserving Encryption (FE1 scheme)
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.constructs.fpe_fe1;

import botan.math.bigint.bigint;
import botan.algo_base.symkey;
import botan.math.numbertheory.numthry;
import botan.mac.hmac;
import botan.hash.sha2_32;
import botan.utils.exceptn;
import std.exception;

struct FPE {

	/**
	* Format Preserving Encryption using the scheme FE1 from the paper
	* "Format-Preserving Encryption" by Bellare, Rogaway, et al
	* (http://eprint.iacr.org/2009/251)
	*
	* Encrypt X from and onto the group Z_n using key and tweak
	* @param n the modulus
	* @param X the plaintext as a BigInt
	* @param key a random key
	* @param tweak will modify the ciphertext (think of as an IV)
	*/
	static BigInt fe1_encrypt(in BigInt n, const ref BigInt X0,
	                          const ref SymmetricKey key,
	                          in Vector!ubyte tweak)
	{
		FPE_Encryptor F = FPE_Encryptor(key, n, tweak);
		
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


	/**
	* Decrypt X from and onto the group Z_n using key and tweak
	* @param n the modulus
	* @param X the ciphertext as a BigInt
	* @param key is the key used for encryption
	* @param tweak the same tweak used for encryption
	*/
	static BigInt fe1_decrypt(in BigInt n, const ref BigInt X0,
	                          const ref SymmetricKey key,
	                          in Vector!ubyte tweak)
	{
		FPE_Encryptor F = FPE_Encryptor(key, n, tweak);
		
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

private:

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
				std.algorithm.swap(a, b);
			n /= PRIMES[i];
		}
	}
	
	if (a > b)
		std.algorithm.swap(a, b);
	a *= n;
	if (a < b)
		std.algorithm.swap(a, b);
	
	if (a <= 1 || b <= 1)
		throw new Exception("Could not factor n for use in FPE");
}

/*
* According to a paper by Rogaway, Bellare, etc, the min safe number
* of rounds to use for FPE is 2+log_a(b). If a >= b then log_a(b) <= 1
* so 3 rounds is safe. The FPE factorization routine should always
* return a >= b, so just confirm that and return 3.
*/
size_t rounds(in BigInt a, const ref BigInt b)
{
	if (a < b)
		throw new Logic_Error("FPE rounds: a < b");
	return 3;
}

/*
* A simple round function based on HMAC(SHA-256)
*/
final class FPE_Encryptor
{
public:
	this(in SymmetricKey key,
	     const ref BigInt n,
	     in Vector!ubyte tweak)
	{
		mac = new HMAC(new SHA_256);
		mac.set_key(key);
		
		Vector!ubyte n_bin = BigInt.encode(n);
		
		if (n_bin.length > MAX_N_BYTES)
			throw new Exception("N is too large for FPE encryption");
		
		mac.update_be(cast(uint)(n_bin.length));
		mac.update(&n_binput[0], n_bin.length);
		
		mac.update_be(cast(uint)(tweak.length));
		mac.update(&tweak[0], tweak.length);
		
		mac_n_t = unlock(mac.flush());
	}

	
	BigInt opCall(size_t round_no, const ref BigInt R)
	{
		Secure_Vector!ubyte r_bin = BigInt.encode_locked(R);
		
		mac.update(mac_n_t);
		mac.update_be(cast(uint)(round_no));
		
		mac.update_be(cast(uint)(r_bin.length));
		mac.update(&r_binput[0], r_bin.length);
		
		Secure_Vector!ubyte X = mac.flush();
		return BigInt(&X[0], X.length);
	}
	
private:
	Unique!MessageAuthenticationCode mac;
	Vector!ubyte mac_n_t;
}