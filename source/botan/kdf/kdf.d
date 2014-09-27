/*
* KDF Retrieval
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.kdf;
import botan.libstate;
import botan.scan_name;

#if defined(BOTAN_HAS_KDF1)
  import botan.kdf1;
#endif

#if defined(BOTAN_HAS_KDF2)
  import botan.kdf2;
#endif

#if defined(BOTAN_HAS_X942_PRF)
  import botan.prf_x942;
#endif

#if defined(BOTAN_HAS_SSL_V3_PRF)
  import botan.prf_ssl3;
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
  import botan.prf_tls;
#endif
KDF* get_kdf(in string algo_spec)
{
	SCAN_Name request(algo_spec);

	Algorithm_Factory& af = global_state().algorithm_factory();

	if (request.algo_name() == "Raw")
		return null; // No KDF

#if defined(BOTAN_HAS_KDF1)
	if (request.algo_name() == "KDF1" && request.arg_count() == 1)
		return new KDF1(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_KDF2)
	if (request.algo_name() == "KDF2" && request.arg_count() == 1)
		return new KDF2(af.make_hash_function(request.arg(0)));
#endif

#if defined(BOTAN_HAS_X942_PRF)
	if (request.algo_name() == "X9.42-PRF" && request.arg_count() == 1)
		return new X942_PRF(request.arg(0)); // OID
#endif

#if defined(BOTAN_HAS_SSL_V3_PRF)
	if (request.algo_name() == "SSL3-PRF" && request.arg_count() == 0)
		return new SSL3_PRF;
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
	if (request.algo_name() == "TLS-PRF" && request.arg_count() == 0)
		return new TLS_PRF;
#endif

#if defined(BOTAN_HAS_TLS_V10_PRF)
	if (request.algo_name() == "TLS-PRF" && request.arg_count() == 0)
		return new TLS_PRF;
#endif

#if defined(BOTAN_HAS_TLS_V12_PRF)
	if (request.algo_name() == "TLS-12-PRF" && request.arg_count() == 1)
		return new TLS_12_PRF(af.make_mac("HMAC(" + request.arg(0) + ")"));
#endif

	throw new Algorithm_Not_Found(algo_spec);
}

}
