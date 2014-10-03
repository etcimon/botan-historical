/*
* Number Theory Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.pow_mod;
import botan.rng;
/**
* Fused multiply-add
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a*b)+c
*/
BigInt mul_add(in BigInt a,
								 ref const BigInt b,
								 ref const BigInt c);

/**
* Fused subtract-multiply
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a-b)*c
*/
BigInt sub_mul(in BigInt a,
								 ref const BigInt b,
								 ref const BigInt c);

/**
* Return the absolute value
* @param n an integer
* @return absolute value of n
*/
 BigInt abs(in BigInt n) { return n.abs(); }

/**
* Compute the greatest common divisor
* @param x a positive integer
* @param y a positive integer
* @return gcd(x,y)
*/
BigInt gcd(in BigInt x, ref const BigInt y);

/**
* Least common multiple
* @param x a positive integer
* @param y a positive integer
* @return z, smallest integer such that z % x == 0 and z % y == 0
*/
BigInt lcm(in BigInt x, ref const BigInt y);

/**
* @param x an integer
* @return (x*x)
*/
BigInt square(in BigInt x);

/**
* Modular inversion
* @param x a positive integer
* @param modulus a positive integer
* @return y st (x*y) % modulus == 1
*/
BigInt inverse_mod(in BigInt x,
									  ref const BigInt modulus);

/**
* Compute the Jacobi symbol. If n is prime, this is equivalent
* to the Legendre symbol.
* @see http://mathworld.wolfram.com/JacobiSymbol.html
*
* @param a is a non-negative integer
* @param n is an odd integer > 1
* @return (n / m)
*/
s32bit jacobi(in BigInt a,
								ref const BigInt n);

/**
* Modular exponentation
* @param b an integer base
* @param x a positive exponent
* @param m a positive modulus
* @return (b^x) % m
*/
BigInt power_mod(in BigInt b,
									ref const BigInt x,
									ref const BigInt m);

/**
* Compute the square root of x modulo a prime using the
* Shanks-Tonnelli algorithm
*
* @param x the input
* @param p the prime
* @return y such that (y*y)%p == x, or -1 if no such integer
*/
BigInt ressol(in BigInt x, ref const BigInt p);

/*
* Compute -input^-1 mod 2^MP_WORD_BITS. Returns zero if input
* is even. If input is odd, input and 2^n are relatively prime
* and an inverse exists.
*/
word monty_inverse(word input);

/**
* @param x a positive integer
* @return count of the zero bits in x, or, equivalently, the largest
*			value of n such that 2^n divides x evenly. Returns zero if
*			n is less than or equal to zero.
*/
size_t low_zero_bits(in BigInt x);

/**
* Check for primality
* @param n a positive integer to test for primality
* @param rng a random number generator
* @param prob chance of false positive is bounded by 1/2**prob
* @param is_random true if n was randomly chosen by us
* @return true if all primality tests passed, otherwise false
*/
bool is_prime(in BigInt n,
								RandomNumberGenerator rng,
								size_t prob = 56,
								bool is_random = false);

 bool quick_check_prime(in BigInt n, RandomNumberGenerator rng)
{ return is_prime(n, rng, 32); }

 bool check_prime(in BigInt n, RandomNumberGenerator rng)
{ return is_prime(n, rng, 56); }

 bool verify_prime(in BigInt n, RandomNumberGenerator rng)
{ return is_prime(n, rng, 80); }/**
* Randomly generate a prime
* @param rng a random number generator
* @param bits how large the resulting prime should be in bits
* @param coprime a positive integer the result should be coprime to
* @param equiv a non-negative number that the result should be
					equivalent to modulo equiv_mod
* @param equiv_mod the modulus equiv should be checked against
* @return random prime with the specified criteria
*/
BigInt random_prime(RandomNumberGenerator rng,
										size_t bits, ref const BigInt coprime = 1,
										size_t equiv = 1, size_t equiv_mod = 2);

/**
* Return a 'safe' prime, of the form p=2*q+1 with q prime
* @param rng a random number generator
* @param bits is how long the resulting prime should be
* @return prime randomly chosen from safe primes of length bits
*/
BigInt random_safe_prime(RandomNumberGenerator rng,
											  size_t bits);

class Algorithm_Factory;

/**
* Generate DSA parameters using the FIPS 186 kosherizer
* @param rng a random number generator
* @param af an algorithm factory
* @param p_out where the prime p will be stored
* @param q_out where the prime q will be stored
* @param pbits how long p will be in bits
* @param qbits how long q will be in bits
* @return random seed used to generate this parameter set
*/
Vector!( byte )
generate_dsa_primes(RandomNumberGenerator rng,
						  ref Algorithm_Factory af,
						  ref BigInt p_out, ref BigInt q_out,
						  size_t pbits, size_t qbits);

/**
* Generate DSA parameters using the FIPS 186 kosherizer
* @param rng a random number generator
* @param af an algorithm factory
* @param p_out where the prime p will be stored
* @param q_out where the prime q will be stored
* @param pbits how long p will be in bits
* @param qbits how long q will be in bits
* @param seed the seed used to generate the parameters
* @return true if seed generated a valid DSA parameter set, otherwise
			 false. p_out and q_out are only valid if true was returned.
*/
bool
generate_dsa_primes(RandomNumberGenerator rng,
						  ref Algorithm_Factory af,
						  ref BigInt p_out, ref BigInt q_out,
						  size_t pbits, size_t qbits,
						  in Vector!byte seed);

/**
* The size of the PRIMES[] array
*/
const size_t PRIME_TABLE_SIZE = 6541;

/**
* A const array of all primes less than 65535
*/
extern const ushort PRIMES[];