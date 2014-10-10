/*
* Random Number Generator Base
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.rng;
import botan.hmac_rng;
import botan.libstate.libstate;
RandomNumberGenerator* RandomNumberGenerator::make_rng()
{
	return make_rng(global_state().algorithm_factory()).release();
}

/*
* Create and seed a new RNG object
*/
Unique!RandomNumberGenerator RandomNumberGenerator::make_rng(Algorithm_Factory af)
{
	Unique!RandomNumberGenerator rng =
		new HMAC_RNG(af.make_mac("HMAC(SHA-512)"),
						 af.make_mac("HMAC(SHA-256)"))
		;

	rng.reseed(256);

	return rng;
}

}
