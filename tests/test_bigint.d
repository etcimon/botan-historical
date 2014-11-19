/*
* (C) 2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include "tests.h"

#include <vector>
#include <string>
#include <fstream>
#include <iostream>
#include <cstdlib>
#include <iterator>

#include <botan/auto_rng.h>
#include <botan/bigint.h>
#include <botan/exceptn.h>
#include <botan/numthry.h>



namespace {

void strip_comments(string line)
{
	if(line.canFind('#'))
		line = line.erase(line.find('#'), -1);
}

/* Strip comments, whitespace, etc */
void strip(string line)
{
	strip_comments(line);

#if 0
	while(line.find(' ') != -1)
		line = line.erase(line.find(' '), 1);
#endif

	while(line.canFind('\t'))
		line = line.erase(line.find('\t'), 1);
}

Vector!string parse(string line)
{
	const char DELIMITER = ':';
	Vector!string substr;
	string::size_type start = 0, end = line.find(DELIMITER);
	while(end != -1)
	{
		substr.push_back(line[start .. end]);
		start = end+1;
		end = line.find(DELIMITER, start);
	}
	if(line.length > start)
		substr.push_back(line[start .. $]);
	while(substr.length <= 4) // at least 5 substr, some possibly empty
		substr.push_back("");
	return substr;
}

// c==expected, d==a op b, e==a op= b
size_t results(string op, in BigInt a, in BigInt b,	in BigInt c, in BigInt d, in BigInt e)
{
	string op1 = "operator" ~ op;
	string op2 = op1 ~ "=";

	if(c == d && d == e)
		return 0;
	else
	{
		writeln();

		writeln("ERROR: " ~ op1);

		writeln("a = ", a);
		writeln("b = ", b);

		writeln("c = ", c);
		writeln("d = ", d);
		writeln("e = ", e);

		if(d != e)
		{
			writeln("ERROR: " ~ op1 ~ " | " ~ op2 ~ " mismatch");
		}
		return 1;
	}
}

size_t check_add(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt c(args[2]);

	BigInt d = a + b;
	BigInt e = a;
	e += b;

	if(results("+", a, b, c, d, e))
		return 1;

	d = b + a;
	e = b;
	e += a;

	return results("+", a, b, c, d, e);
}

size_t check_sub(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt c(args[2]);

	BigInt d = a - b;
	BigInt e = a;
	e -= b;

	return results("-", a, b, c, d, e);
}

size_t check_mul(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt c(args[2]);

	/*
	writeln("a = " ~ args[0] " ~\n"
				 " ~b = " ~ args[1]);
	*/
	/* This makes it more likely the fast multiply algorithms will be usable,
		which is what we really want to test here (the simple n^2 multiply is
		pretty well tested at this point).
	*/
	a.grow_to(64);
	b.grow_to(64);

	BigInt d = a * b;
	BigInt e = a;
	e *= b;

	if(results("*", a, b, c, d, e))
		return 1;

	d = b * a;
	e = b;
	e *= a;

	return results("*", a, b, c, d, e);
}

size_t check_sqr(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);

	a.grow_to(64);
	b.grow_to(64);

	BigInt c = square(a);
	BigInt d = a * a;

	return results("sqr", a, a, b, c, d);
}

size_t check_div(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt c(args[2]);

	BigInt d = a / b;
	BigInt e = a;
	e /= b;

	return results("/", a, b, c, d, e);
}

size_t check_mod(in Vector!string args,
					  RandomNumberGenerator rng)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt c(args[2]);

	BigInt d = a % b;
	BigInt e = a;
	e %= b;

	size_t got = results("%", a, b, c, d, e);

	if(got) return got;

	word b_word = b.word_at(0);

	/* Won't work for us, just pick one at random */
	while(b_word == 0)
		for(size_t j = 0; j != 2*sizeof(word); j++)
			b_word = (b_word << 4) ^ rng.next_byte();

	b = b_word;

	c = a % b; /* we declare the BigInt % BigInt version to be correct here */

	word d2 = a % b_word;
	e = a;
	e %= b_word;

	return results("%(word)", a, b, c, d2, e);
}

size_t check_shl(in Vector!string args)
{
	BigInt a(args[0]);
	size_t b = args[1].to!size_t;
	BigInt c(args[2]);

	BigInt d = a << b;
	BigInt e = a;
	e <<= b;

	return results("<<", a, b, c, d, e);
}

size_t check_shr(in Vector!string args)
{
	BigInt a(args[0]);
	size_t b = args[1].to!size_t;
	BigInt c(args[2]);

	BigInt d = a >> b;
	BigInt e = a;
	e >>= b;

	return results(">>", a, b, c, d, e);
}

/* Make sure that (a^b)%m == r */
size_t check_powmod(in Vector!string args)
{
	BigInt a(args[0]);
	BigInt b(args[1]);
	BigInt m(args[2]);
	BigInt c(args[3]);

	BigInt r = power_mod(a, b, m);

	if(c != r)
	{
		writeln("ERROR: power_mod");
		writeln("a = " ~ std::hex << a);
		writeln("b = " ~ std::hex << b);
		writeln("m = " ~ std::hex << m);
		writeln("c = " ~ std::hex << c);
		writeln("r = " ~ std::hex << r);
		return 1;
	}
	return 0;
}

/* Make sure that n is prime or not prime, according to should_be_prime */
size_t is_primetest(in Vector!string args,
							  RandomNumberGenerator rng)
{
	BigInt n(args[0]);
	bool should_be_prime = (args[1] == "1");

	bool is_prime = is_prime(n, rng);

	if(is_prime != should_be_prime)
	{
		writeln("ERROR: is_prime");
		writeln("n = " ~ n);
		writeln(is_prime ~ " != " ~ should_be_prime);
	}
	return 0;
}

}

size_t test_bigint()
{
	const string filename = "test_data//mp_valid.dat";
	File test_data(filename);

	if(!test_data)
		throw new Stream_IO_Error("Couldn't open test file " + filename);

	size_t total_errors = 0;
	size_t errors = 0, alg_count = 0;
	string algorithm;
	bool first = true;
	size_t counter = 0;

	AutoSeeded_RNG rng;

	while(!test_data.eof())
	{
		if(test_data.bad() || test_data.fail())
			throw new Stream_IO_Error("File I/O error reading from " +
												  filename);

		string line;
		std::getline(test_data, line);

		strip(line);
		if(line.length == 0) continue;

		// Do line continuation
		while(line[line.length-1] == '\\' && !test_data.eof())
		{
			line.replace(line.length-1, 1, "");
			string nextline;
			std::getline(test_data, nextline);
			strip(nextline);
			if(nextline.length == 0) continue;
			line += nextline;
		}

		if(line[0] == '[' && line[line.length - 1] == ']')
		{
			if(!first)
				test_report("Bigint " + algorithm, alg_count, errors);

			algorithm = line.substr(1, line.length - 2);

			total_errors += errors;
			errors = 0;
			alg_count = 0;
			counter = 0;

			first = false;
			continue;
		}

		Vector!string substr = parse(line);

#if DEBUG
		writeln("Testing: " ~ algorithm);
#endif

		size_t new_errors = 0;
		if(algorithm.canFind("Addition"))
			new_errors = check_add(substr);
		else if(algorithm.canFind("Subtraction"))
			new_errors = check_sub(substr);
		else if(algorithm.canFind("Multiplication"))
			new_errors = check_mul(substr);
		else if(algorithm.canFind("Square"))
			new_errors = check_sqr(substr);
		else if(algorithm.canFind("Division"))
			new_errors = check_div(substr);
		else if(algorithm.canFind("Modulo"))
			new_errors = check_mod(substr, rng);
		else if(algorithm.canFind("LeftShift"))
			new_errors = check_shl(substr);
		else if(algorithm.canFind("RightShift"))
			new_errors = check_shr(substr);
		else if(algorithm.canFind("ModExp"))
			new_errors = check_powmod(substr);
		else if(algorithm.canFind("PrimeTest"))
			new_errors = is_primetest(substr, rng);
		else
			writeln("Unknown MPI test " ~ algorithm);

		counter++;
		alg_count++;
		errors += new_errors;

		if(new_errors)
			writeln("ERROR: BigInt " ~ algorithm ~ " failed test #"
						 << std::dec << alg_count);
	}

	return total_errors;
}

