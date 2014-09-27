/*
* PBKDF Lookup
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.scan_name;
import botan.algo_factory;

#if defined(BOTAN_HAS_PBKDF1)
  import botan.pbkdf1;
#endif

#if defined(BOTAN_HAS_PBKDF2)
  import botan.pbkdf2;
#endif
PBKDF* Core_Engine::find_pbkdf(in SCAN_Name algo_spec,
										 Algorithm_Factory& af) const
{
#if defined(BOTAN_HAS_PBKDF1)
	if (algo_spec.algo_name() == "PBKDF1" && algo_spec.arg_count() == 1)
		return new PKCS5_PBKDF1(af.make_hash_function(algo_spec.arg(0)));
#endif

#if defined(BOTAN_HAS_PBKDF2)
	if (algo_spec.algo_name() == "PBKDF2" && algo_spec.arg_count() == 1)
	{
		if (const MessageAuthenticationCode* mac_proto = af.prototype_mac(algo_spec.arg(0)))
			return new PKCS5_PBKDF2(mac_proto->clone());

		return new PKCS5_PBKDF2(af.make_mac("HMAC(" + algo_spec.arg(0) + ")"));
	}
#endif

	return null;
}

}
