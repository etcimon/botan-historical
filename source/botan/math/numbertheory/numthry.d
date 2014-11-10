/*
* Number Theory Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.numbertheory.numthry;

public import botan.math.bigint.bigint;
public import botan.math.numbertheory.pow_mod;
import botan.rng.rng;
import botan.algo_factory.algo_factory;
import botan.hash.hash;
import botan.utils.parsing;
import std.algorithm;
import botan.math.numbertheory.reducer;
import botan.utils.bit_ops;
import botan.math.mp.mp_core;
import botan.math.numbertheory.primes;
import std.algorithm;
import botan.algo_factory.algo_factory : Algorithm_Factory;
/**
* Fused multiply-add
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a*b)+c
*/
/*
* Multiply-Add Operation
*/
BigInt mul_add(in BigInt a, const ref BigInt b, const ref BigInt c)
{
	if (c.is_negative() || c.is_zero())
		throw new Invalid_Argument("mul_add: Third argument must be > 0");
	
	BigInt.Sign sign = BigInt.Positive;
	if (a.sign() != b.sign())
		sign = BigInt.Negative;
	
	const size_t a_sw = a.sig_words();
	const size_t b_sw = b.sig_words();
	const size_t c_sw = c.sig_words();
	
	BigInt r = BigInt(sign, std.algorithm.max(a.length + b.length, c_sw) + 1);
	Secure_Vector!word workspace(r.length);
	
	bigint_mul(r.mutable_data(), r.length,
	           &workspace[0],
	a.data(), a.length, a_sw,
	b.data(), b.length, b_sw);
	
	const size_t r_size = std.algorithm.max(r.sig_words(), c_sw);
	bigint_add2(r.mutable_data(), r_size, c.data(), c_sw);
	return r;
}


/**
* Fused subtract-multiply
* @param a an integer
* @param b an integer
* @param c an integer
* @return (a-b)*c
*/
BigInt sub_mul(in BigInt a, const ref BigInt b, const ref BigInt c)
{
	if (a.is_negative() || b.is_negative())
		throw new Invalid_Argument("sub_mul: First two arguments must be >= 0");
	
	BigInt r = a;
	r -= b;
	r *= c;
	return r;
}

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
BigInt gcd(in BigInt a, const ref BigInt b)
{
	if (a.is_zero() || b.is_zero()) return 0;
	if (a == 1 || b == 1)			  return 1;
	
	BigInt x = a, y = b;
	x.set_sign(BigInt.Positive);
	y.set_sign(BigInt.Positive);
	size_t shift = std.algorithm.min(low_zero_bits(x), low_zero_bits(y));
	
	x >>= shift;
	y >>= shift;
	
	while(x.is_nonzero())
	{
		x >>= low_zero_bits(x);
		y >>= low_zero_bits(y);
		if (x >= y) { x -= y; x >>= 1; }
		else		 { y -= x; y >>= 1; }
	}
	
	return (y << shift);
}

/**
* Least common multiple
* @param x a positive integer
* @param y a positive integer
* @return z, smallest integer such that z % x == 0 and z % y == 0
*/
BigInt lcm(in BigInt a, const ref BigInt b)
{
	return ((a * b) / gcd(a, b));
}


/**
* @param x an integer
* @return (x*x)
*/
BigInt square(in BigInt x)
{
	const size_t x_sw = x.sig_words();
	
	BigInt z = BigInt(BigInt.Positive, round_up!size_t(2*x_sw, 16));
	Secure_Vector!word workspace = Secure_Vector!word(z.length);
	
	bigint_sqr(z.mutable_data(), z.length,
	           &workspace[0],
	x.data(), x.length, x_sw);
	return z;
}

/**
* Modular inversion
* @param x a positive integer
* @param modulus a positive integer
* @return y st (x*y) % modulus == 1
*/
BigInt inverse_mod(in BigInt n, const ref BigInt mod)
{
	if (mod.is_zero())
		throw new BigInt.DivideByZero();
	if (mod.is_negative() || n.is_negative())
		throw new Invalid_Argument("inverse_mod: arguments must be non-negative");
	
	if (n.is_zero() || (n.is_even() && mod.is_even()))
		return 0; // fast fail checks
	
	if (mod.is_odd())
		return inverse_mod_odd_modulus(n, mod);
	
	BigInt u = mod, v = n;
	BigInt A = 1, B = 0, C = 0, D = 1;
	
	while(u.is_nonzero())
	{
		const size_t u_zero_bits = low_zero_bits(u);
		u >>= u_zero_bits;
		for (size_t i = 0; i != u_zero_bits; ++i)
		{
			if (A.is_odd() || B.is_odd())
			{ A += n; B -= mod; }
			A >>= 1; B >>= 1;
		}
		
		const size_t v_zero_bits = low_zero_bits(v);
		v >>= v_zero_bits;
		for (size_t i = 0; i != v_zero_bits; ++i)
		{
			if (C.is_odd() || D.is_odd())
			{ C += n; D -= mod; }
			C >>= 1; D >>= 1;
		}
		
		if (u >= v) { u -= v; A -= C; B -= D; }
		else		 { v -= u; C -= A; D -= B; }
	}
	
	if (v != 1)
		return 0; // no modular inverse
	
	while(D.is_negative()) D += mod;
	while(D >= mod) D -= mod;
	
	return D;
}


/**
* Compute the Jacobi symbol. If n is prime, this is equivalent
* to the Legendre symbol.
* @see http://mathworld.wolfram.com/JacobiSymbol.html
*
* @param a is a non-negative integer
* @param n is an odd integer > 1
* @return (n / m)
*/
int jacobi(in BigInt a, const ref BigInt n)
{
	if (a.is_negative())
		throw new Invalid_Argument("jacobi: first argument must be non-negative");
	if (n.is_even() || n < 2)
		throw new Invalid_Argument("jacobi: second argument must be odd and > 1");
	
	BigInt x = a, y = n;
	int J = 1;
	
	while(y > 1)
	{
		x %= y;
		if (x > y / 2)
		{
			x = y - x;
			if (y % 4 == 3)
				J = -J;
		}
		if (x.is_zero())
			return 0;
		
		size_t shifts = low_zero_bits(x);
		x >>= shifts;
		if (shifts % 2)
		{
			word y_mod_8 = y % 8;
			if (y_mod_8 == 3 || y_mod_8 == 5)
				J = -J;
		}
		
		if (x % 4 == 3 && y % 4 == 3)
			J = -J;
		std.algorithm.swap(x, y);
	}
	return J;
}

/**
* Modular exponentation
* @param b an integer base
* @param x a positive exponent
* @param m a positive modulus
* @return (b^x) % m
*/
BigInt power_mod(in BigInt base, const ref BigInt exp, const ref BigInt mod)
{
	auto pow_mod = scoped!Power_Mod(mod);

	/*
	* Calling set_base before set_exponent means we end up using a
	* minimal window. This makes sense given that here we know that any
	* precomputation is wasted.
	*/
	pow_mod.set_base(base);
	pow_mod.set_exponent(exp);
	return pow_mod.execute();
}


/**
* Compute the square root of x modulo a prime using the
* Shanks-Tonnelli algorithm
*
* @param x the input
* @param p the prime
* @return y such that (y*y)%p == x, or -1 if no such integer
*/

/*
* Shanks-Tonnelli algorithm
*/
BigInt ressol(in BigInt a, const ref BigInt p)
{
	if (a < 0)
		throw new Invalid_Argument("ressol(): a to solve for must be positive");
	if (p <= 1)
		throw new Invalid_Argument("ressol(): prime must be > 1");
	
	if (a == 0)
		return 0;
	if (p == 2)
		return a;
	
	if (jacobi(a, p) != 1) // not a quadratic residue
		return -BigInt(1);
	
	if (p % 4 == 3)
		return power_mod(a, ((p+1) >> 2), p);
	
	size_t s = low_zero_bits(p - 1);
	BigInt q = p >> s;
	
	q -= 1;
	q >>= 1;
	
	Modular_Reducer mod_p(p);
	
	BigInt r = power_mod(a, q, p);
	BigInt n = mod_p.multiply(a, mod_p.square(r));
	r = mod_p.multiply(r, a);
	
	if (n == 1)
		return r;
	
	// find random non quadratic residue z
	BigInt z = 2;
	while(jacobi(z, p) == 1) // while z quadratic residue
		++z;
	
	BigInt c = power_mod(z, (q << 1) + 1, p);
	
	while(n > 1)
	{
		q = n;
		
		size_t i = 0;
		while(q != 1)
		{
			q = mod_p.square(q);
			++i;
		}
		
		if (s <= i)
			return -BigInt(1);
		
		c = power_mod(c, BigInt.power_of_2(s-i-1), p);
		r = mod_p.multiply(r, c);
		c = mod_p.square(c);
		n = mod_p.multiply(n, c);
		s = i;
	}
	
	return r;
}

/*
* Compute -input^-1 mod 2^MP_WORD_BITS. Returns zero if input
* is even. If input is odd, input and 2^n are relatively prime
* and an inverse exists.
*/
word monty_inverse(word input)
{
	word b = input;
	word x2 = 1, x1 = 0, y2 = 0, y1 = 1;
	
	// First iteration, a = n+1
	word q = bigint_divop(1, 0, b);
	word r = (MP_WORD_MAX - q*b) + 1;
	word x = x2 - q*x1;
	word y = y2 - q*y1;
	
	word a = b;
	b = r;
	x2 = x1;
	x1 = x;
	y2 = y1;
	y1 = y;
	
	while(b > 0)
	{
		q = a / b;
		r = a - q*b;
		x = x2 - q*x1;
		y = y2 - q*y1;
		
		a = b;
		b = r;
		x2 = x1;
		x1 = x;
		y2 = y1;
		y1 = y;
	}
	
	// Now invert in addition space
	y2 = (MP_WORD_MAX - y2) + 1;
	
	return y2;
}

/**
* @param x a positive integer
* @return count of the zero bits in x, or, equivalently, the largest
*			value of n such that 2^n divides x evenly. Returns zero if
*			n is less than or equal to zero.
*/
size_t low_zero_bits(in BigInt n)
{
	size_t low_zero = 0;
	
	if (n.is_positive() && n.is_nonzero())
	{
		for (size_t i = 0; i != n.length; ++i)
		{
			const word x = n.word_at(i);
			
			if (x)
			{
				low_zero += ctz(x);
				break;
			}
			else
				low_zero += BOTAN_MP_WORD_BITS;
		}
	}
	
	return low_zero;
}

/**
* Check for primality
* @param n a positive integer to test for primality
* @param rng a random number generator
* @param prob chance of false positive is bounded by 1/2**prob
* @param is_random true if n was randomly chosen by us
* @return true if all primality tests passed, otherwise false
*/

/*
* Test for primaility using Miller-Rabin
*/
bool is_prime(in BigInt n, RandomNumberGenerator rng,
              size_t prob = 56, bool is_random = false)
{
	if (n == 2)
		return true;
	if (n <= 1 || n.is_even())
		return false;
	
	// Fast path testing for small numbers (<= 65521)
	if (n <= PRIMES[PRIME_TABLE_SIZE-1])
	{
		const ushort num = n.word_at(0);
		
		return std::binary_search(PRIMES, PRIMES + PRIME_TABLE_SIZE, num);
	}
	
	const size_t test_iterations = mr_test_iterations(n.bits(), prob, is_random);
	
	const BigInt n_minus_1 = n - 1;
	const size_t s = low_zero_bits(n_minus_1);
	
	Fixed_Exponent_Power_Mod pow_mod = Fixed_Exponent_Power_Mod(n_minus_1 >> s, n);
	Modular_Reducer reducer = Modular_Reducer(n);
	
	for (size_t i = 0; i != test_iterations; ++i)
	{
		const BigInt a = BigInt.random_integer(rng, 2, n_minus_1);
		
		BigInt y = pow_mod(a);
		
		if (mr_witness(std.algorithm.move(y), reducer, n_minus_1, s))
			return false;
	}
	
	return true;
}

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
                    size_t bits, const ref BigInt coprime,
                    size_t equiv, size_t modulo)
{
	if (bits <= 1)
		throw new Invalid_Argument("random_prime: Can't make a prime of " ~
		                           std.conv.to!string(bits) ~ " bits");
	else if (bits == 2)
		return ((rng.next_byte() % 2) ? 2 : 3);
	else if (bits == 3)
		return ((rng.next_byte() % 2) ? 5 : 7);
	else if (bits == 4)
		return ((rng.next_byte() % 2) ? 11 : 13);
	
	if (coprime <= 0)
		throw new Invalid_Argument("random_prime: coprime must be > 0");
	if (modulo % 2 == 1 || modulo == 0)
		throw new Invalid_Argument("random_prime: Invalid modulo value");
	if (equiv >= modulo || equiv % 2 == 0)
		throw new Invalid_Argument("random_prime: equiv must be < modulo, and odd");
	
	while(true)
	{
		BigInt p(rng, bits);
		
		// Force lowest and two top bits on
		p.set_bit(bits - 1);
		p.set_bit(bits - 2);
		p.set_bit(0);
		
		if (p % modulo != equiv)
			p += (modulo - p % modulo) + equiv;
		
		const size_t sieve_size = std.algorithm.min(bits / 2, PRIME_TABLE_SIZE);
		Secure_Vector!ushort sieve(sieve_size);
		
		for (size_t j = 0; j != sieve.length; ++j)
			sieve[j] = p % PRIMES[j];
		
		size_t counter = 0;
		while(true)
		{
			if (counter == 4096 || p.bits() > bits)
				break;
			
			bool passes_sieve = true;
			++counter;
			p += modulo;
			
			if (p.bits() > bits)
				break;
			
			for (size_t j = 0; j != sieve.length; ++j)
			{
				sieve[j] = (sieve[j] + modulo) % PRIMES[j];
				if (sieve[j] == 0)
					passes_sieve = false;
			}
			
			if (!passes_sieve || gcd(p - 1, coprime) != 1)
				continue;
			if (is_prime(p, rng, 64, true))
				return p;
		}
	}
}

/**
* Return a 'safe' prime, of the form p=2*q+1 with q prime
* @param rng a random number generator
* @param bits is how long the resulting prime should be
* @return prime randomly chosen from safe primes of length bits
*/

/*
* Generate a random safe prime
*/
BigInt random_safe_prime(RandomNumberGenerator rng, size_t bits)
{
	if (bits <= 64)
		throw new Invalid_Argument("random_safe_prime: Can't make a prime of " ~
		                           std.conv.to!string(bits) ~ " bits");
	
	BigInt p;
	do
		p = (random_prime(rng, bits - 1) << 1) + 1;
	while(!is_prime(p, rng, 64, true));
	return p;
}

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
Vector!ubyte generate_dsa_primes(RandomNumberGenerator rng,
                                 Algorithm_Factory af,
                                 ref BigInt p, ref BigInt q,
                                 size_t pbits, size_t qbits)
{
	while(true)
	{
		Vector!ubyte seed = Vector!ubyte(qbits / 8);
		rng.randomize(&seed[0], seed.length);
		
		if (generate_dsa_primes(rng, af, p, q, pbits, qbits, seed))
			return seed;
	}
}


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
bool generate_dsa_primes(RandomNumberGenerator rng,
                         Algorithm_Factory af,
                         ref BigInt p, ref BigInt q,
                         size_t pbits, size_t qbits,
                         in Vector!ubyte seed_c)
{
	if (!fips186_3_valid_size(pbits, qbits))
		throw new Invalid_Argument(
			"FIPS 186-3 does not allow DSA domain parameters of " ~
			std.conv.to!string(pbits) ~ "/" ~ std.conv.to!string(qbits) ~ " bits long");
	
	if (seed_c.length * 8 < qbits)
		throw new Invalid_Argument(
			"Generating a DSA parameter set with a " ~ std.conv.to!string(qbits) +
			"long q requires a seed at least as many bits long");
	
	Unique!HashFunction hash =
		af.make_hash_function("SHA-" ~ std.conv.to!string(qbits));
	
	const size_t HASH_SIZE = hash.output_length;
	
	struct Seed
	{
	public:
		this(in Vector!ubyte s) { seed = s; }
		
		T opCast(T : Vector!ubyte)() { return seed; }
		
		alias seed this;
		
		ref Seed opUnary(string op)()
			if (op == "++")
		{
			for (size_t j = seed.length; j > 0; --j)
				if (++seed[j-1])
					break;
			return this;
		}
	m_tag
		Vector!ubyte seed;
	};
	
	Seed seed = Seed(seed_c);
	
	q.binary_decode(hash.process(seed));
	q.set_bit(qbits-1);
	q.set_bit(0);
	
	if (!is_prime(q, rng))
		return false;
	
	const size_t n = (pbits-1) / (HASH_SIZE * 8),
		b = (pbits-1) % (HASH_SIZE * 8);
	
	BigInt X;
	Vector!ubyte V = Vector!ubyte(HASH_SIZE * (n+1));
	
	for (size_t j = 0; j != 4096; ++j)
	{
		for (size_t k = 0; k <= n; ++k)
		{
			++seed;
			hash.update(seed);
			hash.flushInto(&V[HASH_SIZE * (n-k)]);
		}
		
		X.binary_decode(&V[HASH_SIZE - 1 - b/8],
		V.length - (HASH_SIZE - 1 - b/8));
		X.set_bit(pbits-1);
		
		p = X - (X % (2*q) - 1);
		
		if (p.bits() == pbits && is_prime(p, rng))
			return true;
	}
	return false;
}

/*
* Check if this size is allowed by FIPS 186-3
*/
bool fips186_3_valid_size(size_t pbits, size_t qbits)
{
	if (qbits == 160)
		return (pbits == 512 || pbits == 768 || pbits == 1024);
	
	if (qbits == 224)
		return (pbits == 2048);
	
	if (qbits == 256)
		return (pbits == 2048 || pbits == 3072);
	
	return false;
}




/*
* If the modulus is odd, then we can avoid computing A and C. This is
* a critical path algorithm in some instances and an odd modulus is
* the common case for crypto, so worth special casing. See note 14.64
* in Handbook of Applied Cryptography for more details.
*/
BigInt inverse_mod_odd_modulus(in BigInt n, const ref BigInt mod)
{
	BigInt u = mod, v = n;
	BigInt B = 0, D = 1;
	
	while(u.is_nonzero())
	{
		const size_t u_zero_bits = low_zero_bits(u);
		u >>= u_zero_bits;
		for (size_t i = 0; i != u_zero_bits; ++i)
		{
			if (B.is_odd())
			{ B -= mod; }
			B >>= 1;
		}
		
		const size_t v_zero_bits = low_zero_bits(v);
		v >>= v_zero_bits;
		for (size_t i = 0; i != v_zero_bits; ++i)
		{
			if (D.is_odd())
			{ D -= mod; }
			D >>= 1;
		}
		
		if (u >= v) { u -= v; B -= D; }
		else		 { v -= u; D -= B; }
	}
	
	if (v != 1)
		return 0; // no modular inverse
	
	while(D.is_negative()) D += mod;
	while(D >= mod) D -= mod;
	
	return D;
}




bool mr_witness(ref BigInt y,
                const ref Modular_Reducer reducer_n,
                const ref BigInt n_minus_1, size_t s)
{
	if (y == 1 || y == n_minus_1)
		return false;
	
	for (size_t i = 1; i != s; ++i)
	{
		y = reducer_n.square(y);
		
		if (y == 1) // found a non-trivial square root
			return true;
		
		if (y == n_minus_1) // -1, trivial square root, so give up
			return false;
	}
	
	return true; // fails Fermat test
}

size_t mr_test_iterations(size_t n_bits, size_t prob, bool random)
{
	const size_t base = (prob + 2) / 2; // worst case 4^-t error rate
	
	/*
* For randomly chosen numbers we can use the estimates from
* http://www.math.dartmouth.edu/~carlp/PDF/paper88.pdf‎
*
* These values are derived from the inequality for p(k,t) given on
* the second page.
*/
	if (random && prob <= 80)
	{
		if (n_bits >= 1536)
			return 2; // < 2^-89
		if (n_bits >= 1024)
			return 4; // < 2^-89
		if (n_bits >= 512)
			return 5; // < 2^-80
		if (n_bits >= 256)
			return 11; // < 2^-80
	}
	
	return base;
}
