/*
* RFC 6979 Deterministic Nonce Generator
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.rfc6979;

import botan.math.bigint.bigint;
import string;
import botan.hmac_drbg;
import botan.libstate.libstate;
/**
* @param x the secret (EC)DSA key
* @param q the group order
* @param h the message hash already reduced mod q
* @param hash the hash function used to generate h
*/
BigInt generate_rfc6979_nonce(in BigInt x,
                              const ref BigInt q,
                              const ref BigInt h,
                              in string hash)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	
	HMAC_DRBG rng = new HMAC_DRBG(af.make_mac("HMAC(" ~ hash ~ ")"), null);
	scope(exit) delete rng;
	
	const size_t qlen = q.bits();
	const size_t rlen = qlen / 8 + (qlen % 8 ? 1 : 0);
	
	SafeVector!ubyte input = BigInt.encode_1363(x, rlen);
	
	input += BigInt.encode_1363(h, rlen);
	
	rng.add_entropy(&input[0], input.length);
	
	BigInt k;
	
	SafeVector!ubyte kbits(rlen);
	
	while(k == 0 || k >= q)
	{
		rng.randomize(&kbits[0], kbits.length);
		k = BigInt.decode(kbits) >> (8*rlen - qlen);
	}
	
	return k;
}