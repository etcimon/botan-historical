/*
* MAC Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.algo_base.scan_name;
import botan.algo_factory;

#if defined(BOTAN_HAS_CBC_MAC)
  import botan.cbc_mac;
#endif

#if defined(BOTAN_HAS_CMAC)
  import botan.cmac;
#endif

#if defined(BOTAN_HAS_HMAC)
  import botan.hmac;
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
  import botan.ssl3_mac;
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
  import botan.x919_mac;
#endif
/*
* Look for an algorithm with this name
*/
MessageAuthenticationCode
Core_Engine::find_mac(in SCAN_Name request,
							 ref Algorithm_Factory af) const
{

#if defined(BOTAN_HAS_CBC_MAC)
	if (request.algo_name() == "CBC-MAC" && request.arg_count() == 1)
		return new CBC_MAC(af.make_block_cipher(request.arg(0)));
#endif

#if defined(BOTAN_HAS_CMAC)
	if (request.algo_name() == "CMAC" && request.arg_count() == 1)
		return new CMAC(af.make_block_cipher(request.arg(0)));
#endif

#if defined(BOTAN_HAS_HMAC)
	if (request.algo_name() == "HMAC" && request.arg_count() == 1)
		return new HMAC(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_SSL3_MAC)
	if (request.algo_name() == "SSL3-MAC" && request.arg_count() == 1)
		return new SSL3_MAC(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_ANSI_X919_MAC)
	if (request.algo_name() == "X9.19-MAC" && request.arg_count() == 0)
		return new ANSI_X919_MAC(af.make_block_cipher("DES"));
#endif

	return null;
}

}
