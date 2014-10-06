/*
* Stream Cipher Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.algo_base.scan_name;
import botan.algo_factory;

#if defined(BOTAN_HAS_OFB)
  import botan.ofb;
#endif

#if defined(BOTAN_HAS_CTR_BE)
  import botan.ctr;
#endif

#if defined(BOTAN_HAS_RC4)
  import botan.rc4;
#endif

#if defined(BOTAN_HAS_CHACHA)
  import botan.chacha;
#endif

#if defined(BOTAN_HAS_SALSA20)
  import botan.salsa20;
#endif
/*
* Look for an algorithm with this name
*/
StreamCipher
Core_Engine::find_stream_cipher(in SCAN_Name request,
										  Algorithm_Factory af) const
{
#if defined(BOTAN_HAS_OFB)
	if (request.algo_name() == "OFB" && request.arg_count() == 1)
	{
		if (auto proto = af.prototype_block_cipher(request.arg(0)))
			return new OFB(proto.clone());
	}
#endif

#if defined(BOTAN_HAS_CTR_BE)
	if (request.algo_name() == "CTR-BE" && request.arg_count() == 1)
	{
		if (auto proto = af.prototype_block_cipher(request.arg(0)))
			return new CTR_BE(proto.clone());
	}
#endif

#if defined(BOTAN_HAS_RC4)
	if (request.algo_name() == "RC4")
		return new RC4(request.arg_as_integer(0, 0));
	if (request.algo_name() == "RC4_drop")
		return new RC4(768);
#endif

#if defined(BOTAN_HAS_CHACHA)
	if (request.algo_name() == "ChaCha")
		return new ChaCha;
#endif

#if defined(BOTAN_HAS_SALSA20)
	if (request.algo_name() == "Salsa20")
		return new Salsa20;
#endif

	return null;
}

}
