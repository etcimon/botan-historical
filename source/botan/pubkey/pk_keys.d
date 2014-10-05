/*
* PK Key Types
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.pk_keys;
import botan.der_enc;
import botan.asn1.oid_lookup.oids;
/*
* Default OID access
*/
OID Public_Key::get_oid() const
{
	try {
		return OIDS::lookup(algo_name());
	}
	catch(Lookup_Error)
	{
		throw new Lookup_Error("PK algo " ~ algo_name() ~ " has no defined OIDs");
	}
}

/*
* Run checks on a loaded public key
*/
void Public_Key::load_check(RandomNumberGenerator rng) const
{
	if (!check_key(rng, BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD))
		throw new Invalid_Argument(algo_name() ~ ": Invalid public key");
}

/*
* Run checks on a loaded private key
*/
void Private_Key::load_check(RandomNumberGenerator rng) const
{
	if (!check_key(rng, BOTAN_Private_Key_STRONG_CHECKS_ON_LOAD))
		throw new Invalid_Argument(algo_name() ~ ": Invalid private key");
}

/*
* Run checks on a generated private key
*/
void Private_Key::gen_check(RandomNumberGenerator rng) const
{
	if (!check_key(rng, BOTAN_Private_Key_STRONG_CHECKS_ON_GENERATE))
		throw new Self_Test_Failure(algo_name() ~ " private key generation failed");
}

}
