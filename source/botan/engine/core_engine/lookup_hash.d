/*
* Hash Algorithms Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.scan_name;
import botan.algo_factory;

#if defined(BOTAN_HAS_ADLER32)
  import botan.adler32;
#endif

#if defined(BOTAN_HAS_CRC24)
  import botan.crc24;
#endif

#if defined(BOTAN_HAS_CRC32)
  import botan.crc32;
#endif

#if defined(BOTAN_HAS_GOST_34_11)
  import botan.gost_3411;
#endif

#if defined(BOTAN_HAS_HAS_160)
  import botan.has160;
#endif

#if defined(BOTAN_HAS_KECCAK)
  import botan.keccak;
#endif

#if defined(BOTAN_HAS_MD2)
  import botan.md2;
#endif

#if defined(BOTAN_HAS_MD4)
  import botan.md4;
#endif

#if defined(BOTAN_HAS_MD5)
  import botan.md5;
#endif

#if defined(BOTAN_HAS_RIPEMD_128)
  import botan.rmd128;
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
  import botan.rmd160;
#endif

#if defined(BOTAN_HAS_SHA1)
  import botan.sha160;
#endif

#if defined(BOTAN_HAS_SHA2_32)
  import botan.sha2_32;
#endif

#if defined(BOTAN_HAS_SHA2_64)
  import botan.sha2_64;
#endif

#if defined(BOTAN_HAS_SKEIN_512)
  import botan.skein_512;
#endif

#if defined(BOTAN_HAS_TIGER)
  import botan.tiger;
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
  import botan.whrlpool;
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)
  import botan.par_hash;
#endif

#if defined(BOTAN_HAS_COMB4P)
  import botan.comb4p;
#endif
/*
* Look for an algorithm with this name
*/
HashFunction* Core_Engine::find_hash(in SCAN_Name request,
												 Algorithm_Factory& af) const
{
#if defined(BOTAN_HAS_ADLER32)
	if (request.algo_name() == "Adler32")
		return new Adler32;
#endif

#if defined(BOTAN_HAS_CRC24)
	if (request.algo_name() == "CRC24")
		return new CRC24;
#endif

#if defined(BOTAN_HAS_CRC32)
	if (request.algo_name() == "CRC32")
		return new CRC32;
#endif

#if defined(BOTAN_HAS_GOST_34_11)
	if (request.algo_name() == "GOST-R-34.11-94")
		return new GOST_34_11;
#endif

#if defined(BOTAN_HAS_HAS_160)
	if (request.algo_name() == "HAS-160")
		return new HAS_160;
#endif

#if defined(BOTAN_HAS_KECCAK)
	if (request.algo_name() == "Keccak-1600")
		return new Keccak_1600(request.arg_as_integer(0, 512));
#endif

#if defined(BOTAN_HAS_MD2)
	if (request.algo_name() == "MD2")
		return new MD2;
#endif

#if defined(BOTAN_HAS_MD4)
	if (request.algo_name() == "MD4")
		return new MD4;
#endif

#if defined(BOTAN_HAS_MD5)
	if (request.algo_name() == "MD5")
		return new MD5;
#endif

#if defined(BOTAN_HAS_RIPEMD_128)
	if (request.algo_name() == "RIPEMD-128")
		return new RIPEMD_128;
#endif

#if defined(BOTAN_HAS_RIPEMD_160)
	if (request.algo_name() == "RIPEMD-160")
		return new RIPEMD_160;
#endif

#if defined(BOTAN_HAS_SHA1)
	if (request.algo_name() == "SHA-160")
		return new SHA_160;
#endif

#if defined(BOTAN_HAS_SHA2_32)
	if (request.algo_name() == "SHA-224")
		return new SHA_224;
	if (request.algo_name() == "SHA-256")
		return new SHA_256;
#endif

#if defined(BOTAN_HAS_SHA2_64)
	if (request.algo_name() == "SHA-384")
		return new SHA_384;
	if (request.algo_name() == "SHA-512")
		return new SHA_512;
#endif

#if defined(BOTAN_HAS_TIGER)
	if (request.algo_name() == "Tiger")
		return new Tiger(request.arg_as_integer(0, 24), // hash output
							  request.arg_as_integer(1, 3)); // # passes
#endif

#if defined(BOTAN_HAS_SKEIN_512)
	if (request.algo_name() == "Skein-512")
		return new Skein_512(request.arg_as_integer(0, 512),
									request.arg(1, ""));
#endif

#if defined(BOTAN_HAS_WHIRLPOOL)
	if (request.algo_name() == "Whirlpool")
		return new Whirlpool;
#endif

#if defined(BOTAN_HAS_COMB4P)
	if (request.algo_name() == "Comb4P" && request.arg_count() == 2)
	{
		const HashFunction* h1 = af.prototype_hash_function(request.arg(0));
		const HashFunction* h2 = af.prototype_hash_function(request.arg(1));

		if (h1 && h2)
			return new Comb4P(h1->clone(), h2->clone());
	}
#endif

#if defined(BOTAN_HAS_PARALLEL_HASH)

	if (request.algo_name() == "Parallel")
	{
		Vector!( const HashFunction* ) hash_prototypes;

		/* First pass, just get the prototypes (no memory allocation). Then
			if all were found, replace each prototype with a newly created clone
		*/
		for (size_t i = 0; i != request.arg_count(); ++i)
		{
			const HashFunction* hash = af.prototype_hash_function(request.arg(i));
			if (!hash)
				return null;

			hash_prototypes.push_back(hash);
		}

		Vector!( HashFunction* ) hashes;
		for (size_t i = 0; i != hash_prototypes.size(); ++i)
			hashes.push_back(hash_prototypes[i]->clone());

		return new Parallel(hashes);
	

	return null;
}

}
