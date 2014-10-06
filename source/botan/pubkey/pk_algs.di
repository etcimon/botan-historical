/*
* PK Key Factory
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pk_keys;
Public_Key make_public_key(in AlgorithmIdentifier alg_id,
									 in SafeVector!ubyte key_bits);

Private_Key make_Private_Key(in AlgorithmIdentifier alg_id,
										in SafeVector!ubyte key_bits,
										RandomNumberGenerator rng);