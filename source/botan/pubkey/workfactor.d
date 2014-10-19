/*
* Public Key Work Factor Functions
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.workfactor;
import botan.utils.types;
/**
* Estimate work factor for discrete logarithm
* @param prime_group_size size of the group in bits
* @return estimated security level for this group
*/
size_t dl_work_factor(size_t prime_group_size)
{
	import std.algorithm : max;
	import std.math : pow, log;
	/*
	Based on GNFS work factors. Constant is 1.43 times the asymptotic
	value; I'm not sure but I believe that came from a paper on 'real
	world' runtimes, but I don't remember where now.

	Sample return values:
		|512|  . 64
		|1024| . 86
		|1536| . 102
		|2048| . 116
		|3072| . 138
		|4096| . 155
		|8192| . 206

	For DL algos, we use an exponent of twice the size of the result;
	the assumption is that an arbitrary discrete log on a group of size
	bits would take about 2^n effort, and thus using an exponent of
	size 2^(2*n) implies that all available attacks are about as easy
	(as e.g Pollard's kangaroo algorithm can compute the DL in sqrt(x)
	operations) while minimizing the exponent size for performance
	reasons.
	*/
	
	immutable size_t MIN_WORKFACTOR = 64;
	
	// approximates natural logarithm of p
	const double log_p = prime_group_size / 1.4426;

	const double strength =
		2.76 * pow(log_p, 1.0/3.0) * pow(log(log_p), 2.0/3.0);
	
	return max(cast(size_t)(strength), MIN_WORKFACTOR);
}
