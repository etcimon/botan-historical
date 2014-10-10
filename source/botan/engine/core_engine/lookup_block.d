/*
* Block Cipher Lookup
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.internal.core_engine;
import botan.algo_base.scan_name;
import botan.algo_factory;

#if defined(BOTAN_HAS_AES)
  import botan.block.aes.aes;
#endif

#if defined(BOTAN_HAS_BLOWFISH)
  import botan.block.blowfish.blowfish;
#endif

#if defined(BOTAN_HAS_CAMELLIA)
  import botan.block.camellia.camellia;
#endif

#if defined(BOTAN_HAS_CAST)
  import botan.block.cast_.cast128;
  import botan.block.cast_.cast256;
#endif

#if defined(BOTAN_HAS_CASCADE)
  import botan.block.cascade.cascade;
#endif

#if defined(BOTAN_HAS_DES)
  import botan.block.des.des;
  import botan.block.des.desx;
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
  import botan.block.gost_28147;
#endif

#if defined(BOTAN_HAS_IDEA)
  import botan.block.idea.idea;
#endif

#if defined(BOTAN_HAS_KASUMI)
  import botan.block.kasumi.kasumi;
#endif

#if defined(BOTAN_HAS_LION)
  import botan.block.lion.lion;
#endif

#if defined(BOTAN_HAS_MARS)
  import botan.block.mars.mars;
#endif

#if defined(BOTAN_HAS_MISTY1)
  import botan.block.misty1.misty1;
#endif

#if defined(BOTAN_HAS_NOEKEON)
  import botan.block.noekeon.noekeon;
#endif

#if defined(BOTAN_HAS_RC2)
  import botan.block.rc2.rc2;
#endif

#if defined(BOTAN_HAS_RC5)
  import botan.block.rc5.rc5;
#endif

#if defined(BOTAN_HAS_RC6)
  import botan.block.rc6.rc6;
#endif

#if defined(BOTAN_HAS_SAFER)
  import botan.block.safer.safer_sk;
#endif

#if defined(BOTAN_HAS_SEED)
  import botan.block.seed.seed;
#endif

#if defined(BOTAN_HAS_SERPENT)
  import botan.block.serpent.serpent;
#endif

#if defined(BOTAN_HAS_TEA)
  import botan.block.tea.tea;
#endif

#if defined(BOTAN_HAS_TWOFISH)
  import botan.block.twofish.twofish;
#endif

#if defined(BOTAN_HAS_THREEFISH_512)
  import botan.block.threefish.threefish;
#endif

#if defined(BOTAN_HAS_XTEA)
  import botan.block.xtea.xtea;
#endif
/*
* Look for an algorithm with this name
*/
BlockCipher Core_Engine::find_block_cipher(in SCAN_Name request,
														  Algorithm_Factory af) const
{

#if defined(BOTAN_HAS_AES)
	if (request.algo_name() == "AES-128")
		return new AES_128;
	if (request.algo_name() == "AES-192")
		return new AES_192;
	if (request.algo_name() == "AES-256")
		return new AES_256;
#endif

#if defined(BOTAN_HAS_BLOWFISH)
	if (request.algo_name() == "Blowfish")
		return new Blowfish;
#endif

#if defined(BOTAN_HAS_CAMELLIA)
	if (request.algo_name() == "Camellia-128")
		return new Camellia_128;
	if (request.algo_name() == "Camellia-192")
		return new Camellia_192;
	if (request.algo_name() == "Camellia-256")
		return new Camellia_256;
#endif

#if defined(BOTAN_HAS_CAST)
	if (request.algo_name() == "CAST-128")
		return new CAST_128;
	if (request.algo_name() == "CAST-256")
		return new CAST_256;
#endif

#if defined(BOTAN_HAS_DES)
	if (request.algo_name() == "DES")
		return new DES;
	if (request.algo_name() == "DESX")
		return new DESX;
	if (request.algo_name() == "TripleDES")
		return new TripleDES;
#endif

#if defined(BOTAN_HAS_GOST_28147_89)
	if (request.algo_name() == "GOST-28147-89")
		return new GOST_28147_89(request.arg(0, "R3411_94_TestParam"));
#endif

#if defined(BOTAN_HAS_IDEA)
	if (request.algo_name() == "IDEA")
		return new IDEA;
#endif

#if defined(BOTAN_HAS_KASUMI)
	if (request.algo_name() == "KASUMI")
		return new KASUMI;
#endif

#if defined(BOTAN_HAS_MARS)
	if (request.algo_name() == "MARS")
		return new MARS;
#endif

#if defined(BOTAN_HAS_MISTY1)
	if (request.algo_name() == "MISTY1")
		return new MISTY1(request.arg_as_integer(0, 8));
#endif

#if defined(BOTAN_HAS_NOEKEON)
	if (request.algo_name() == "Noekeon")
		return new Noekeon;
#endif

#if defined(BOTAN_HAS_RC2)
	if (request.algo_name() == "RC2")
		return new RC2;
#endif

#if defined(BOTAN_HAS_RC5)
	if (request.algo_name() == "RC5")
		return new RC5(request.arg_as_integer(0, 12));
#endif

#if defined(BOTAN_HAS_RC6)
	if (request.algo_name() == "RC6")
		return new RC6;
#endif

#if defined(BOTAN_HAS_SAFER)
	if (request.algo_name() == "SAFER-SK")
		return new SAFER_SK(request.arg_as_integer(0, 10));
#endif

#if defined(BOTAN_HAS_SEED)
	if (request.algo_name() == "SEED")
		return new SEED;
#endif

#if defined(BOTAN_HAS_SERPENT)
	if (request.algo_name() == "Serpent")
		return new Serpent;
#endif

#if defined(BOTAN_HAS_TEA)
	if (request.algo_name() == "TEA")
		return new TEA;
#endif

#if defined(BOTAN_HAS_TWOFISH)
	if (request.algo_name() == "Twofish")
		return new Twofish;
#endif

#if defined(BOTAN_HAS_TWOFISH)
	if (request.algo_name() == "Threefish-512")
		return new Threefish_512;
#endif

#if defined(BOTAN_HAS_XTEA)
	if (request.algo_name() == "XTEA")
		return new XTEA;
#endif

#if defined(BOTAN_HAS_CASCADE)
	if (request.algo_name() == "Cascade" && request.arg_count() == 2)
	{
		const BlockCipher c1 = af.prototype_block_cipher(request.arg(0));
		const BlockCipher c2 = af.prototype_block_cipher(request.arg(1));

		if (c1 && c2)
			return new Cascade_Cipher(c1.clone(), c2.clone());
	}
#endif

#if defined(BOTAN_HAS_LION)
	if (request.algo_name() == "Lion" && request.arg_count_between(2, 3))
	{
		const size_t block_size = request.arg_as_integer(2, 1024);

		const HashFunction hash =
			af.prototype_hash_function(request.arg(0));

		const StreamCipher stream_cipher =
			af.prototype_stream_cipher(request.arg(1));

		if (!hash || !stream_cipher)
			return null;

		return new Lion(hash.clone(), stream_cipher.clone(), block_size);
	}
#endif

	return null;
}

}
