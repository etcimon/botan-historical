/*
* Core Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.core_engine;

import botan.engine.engine;
import botan.utils.parsing;
import botan.filters.filters;
import botan.algo_factory.algo_factory;
import botan.modes.mode_pad;
import botan.filters.transform_filter;
import botan.math.numbertheory.def_powm;
import botan.algo_base.scan_name;
import botan.algo_factory.algo_factory;

static if (BOTAN_HAS_MODE_CFB)		import botan.modes.cfb;
static if (BOTAN_HAS_MODE_ECB)		import botan.modes.ecb;
static if (BOTAN_HAS_MODE_CBC) 		import botan.modes.cbc;
static if (BOTAN_HAS_MODE_XTS)	 	import botan.modes.xts;

static if (BOTAN_HAS_OFB) 			import botan.stream.ofb;
static if (BOTAN_HAS_CTR_BE)		import botan.stream.ctr;

static if (BOTAN_HAS_AEAD_FILTER)	import botan.filters.aead_filt;
static if (BOTAN_HAS_AEAD_CCM) 		import botan.modes.aead.ccm;
static if (BOTAN_HAS_AEAD_EAX) 		import botan.modes.aead.eax;	
static if (BOTAN_HAS_AEAD_OCB) 		import botan.modes.aead.ocb;
static if (BOTAN_HAS_AEAD_GCM) 		import botan.modes.aead.gcm;
static if (BOTAN_HAS_RSA) 			import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_RW) 			import botan.pubkey.algo.rw;
static if (BOTAN_HAS_DSA) 			import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_ECDSA) 		import botan.pubkey.algo.ecdsa;
static if (BOTAN_HAS_ELGAMAL) 		import botan.pubkey.algo.elgamal;
static if (BOTAN_HAS_GOST_34_10_2001) 	import botan.pubkey.algo.gost_3410;
static if (BOTAN_HAS_NYBERG_RUEPPEL)import  botan.pubkey.algo.nr;
static if (BOTAN_HAS_DIFFIE_HELLMAN)import botan.pubkey.algo.dh;
static if (BOTAN_HAS_ECDH) 			import botan.pubkey.algo.ecdh;
/// Blocks
static if (BOTAN_HAS_AES) 			import botan.block.aes;
static if (BOTAN_HAS_BLOWFISH) 		import botan.block.blowfish;
static if (BOTAN_HAS_CAMELLIA) 		import botan.block.camellia;
static if (BOTAN_HAS_CAST) {
									import botan.block.cast128;
									import botan.block.cast256;
}
static if (BOTAN_HAS_CASCADE)  		import botan.block.cascade;
static if (BOTAN_HAS_DES){
									import botan.block.des;
									import botan.block.desx;
}
static if (BOTAN_HAS_GOST_28147_89)	import botan.block.gost_28147;
static if (BOTAN_HAS_IDEA) 			import botan.block.idea;
static if (BOTAN_HAS_KASUMI) 		import botan.block.kasumi;
static if (BOTAN_HAS_LION) 			import botan.block.lion;
static if (BOTAN_HAS_MARS) 			import botan.block.mars;
static if (BOTAN_HAS_MISTY1) 		import botan.block.misty1;
static if (BOTAN_HAS_NOEKEON) 		import botan.block.noekeon;
static if (BOTAN_HAS_RC2) 			import botan.block.rc2;
static if (BOTAN_HAS_RC5) 			import botan.block.rc5;
static if (BOTAN_HAS_RC6) 			import botan.block.rc6;
static if (BOTAN_HAS_SAFER) 		import botan.block.safer_sk;
static if (BOTAN_HAS_SEED) 			import botan.block.seed;
static if (BOTAN_HAS_SERPENT) 		import botan.block.serpent;
static if (BOTAN_HAS_TEA) 			import botan.block.tea;
static if (BOTAN_HAS_TWOFISH) 		import botan.block.twofish;
static if (BOTAN_HAS_THREEFISH_512) import botan.block.threefish;
static if (BOTAN_HAS_XTEA) 			import botan.block.xtea;

//Hash
static if (BOTAN_HAS_ADLER32) 		import botan.checksum.adler32;
static if (BOTAN_HAS_CRC24) 		import botan.checksum.crc24;
static if (BOTAN_HAS_CRC32) 		import botan.checksum.crc32;
static if (BOTAN_HAS_GOST_34_11) 	import botan.hash.gost_3411;
static if (BOTAN_HAS_HAS_160) 		import botan.hash.has160;
static if (BOTAN_HAS_KECCAK) 		import botan.hash.keccak;
static if (BOTAN_HAS_MD2) 			import botan.hash.md2;
static if (BOTAN_HAS_MD4) 			import botan.hash.md4;
static if (BOTAN_HAS_MD5) 			import botan.hash.md5;
static if (BOTAN_HAS_RIPEMD_128) 	import botan.hash.rmd128;
static if (BOTAN_HAS_RIPEMD_160) 	import botan.hash.rmd160;
static if (BOTAN_HAS_SHA1) 			import botan.hash.sha160;
static if (BOTAN_HAS_SHA2_32) 		import botan.hash.sha2_32;
static if (BOTAN_HAS_SHA2_64) 		import botan.hash.sha2_64;
static if (BOTAN_HAS_SKEIN_512) 	import botan.hash.skein_512;
static if (BOTAN_HAS_TIGER) 		import botan.hash.tiger;
static if (BOTAN_HAS_WHIRLPOOL) 	import botan.hash.whrlpool;
static if (BOTAN_HAS_PARALLEL_HASH) import botan.hash.par_hash;
static if (BOTAN_HAS_COMB4P) 		import botan.hash.comb4p;

/// MAC
static if (BOTAN_HAS_CBC_MAC) 		import botan.mac.cbc_mac;
static if (BOTAN_HAS_CMAC)  		import botan.cmac.cmac;
static if (BOTAN_HAS_HMAC)  		import botan.mac.hmac;
static if (BOTAN_HAS_SSL3_MAC)  	import botan.mac.ssl3_mac;
static if (BOTAN_HAS_ANSI_X919_MAC) import botan.mac.x919_mac;

/// PBKDF
static if (BOTAN_HAS_PBKDF1) 		import botan.pbkdf.pbkdf1;
static if (BOTAN_HAS_PBKDF2)		import botan.pbkdf.pbkdf2;

/// STREAM
static if (BOTAN_HAS_RC4)  			import botan.stream.rc4;
static if (BOTAN_HAS_CHACHA)  		import botan.stream.chacha;
static if (BOTAN_HAS_SALSA20)  		import botan.stream.salsa20;

/**
* Core Engine
*/
final class Core_Engine : Engine
{
public:
	string provider_name() const { return "core"; }

	Key_Agreement get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		static if (BOTAN_HAS_DIFFIE_HELLMAN) {
			if (const DH_PrivateKey dh = cast(const DH_PrivateKey)(key))
				return new DH_KA_Operation(dh, rng);
		}
		
		static if (BOTAN_HAS_ECDH) {
			if (const ECDH_PrivateKey ecdh = cast(const ECDH_PrivateKey)(key))
				return new ECDH_KA_Operation(ecdh);
		}
		
		return null;
	}

	Signature get_signature_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PrivateKey s = cast(const RSA_PrivateKey)(key))
				return new RSA_Private_Operation(s, rng);
		}
		
		static if (BOTAN_HAS_RW) {
			if (const RW_PrivateKey s = cast(const RW_PrivateKey)(key))
				return new RW_Signature_Operation(s);
		}
		
		static if (BOTAN_HAS_DSA) {
			if (const DSA_PrivateKey s = cast(const DSA_PrivateKey)(key))
				return new DSA_Signature_Operation(s);
		}
		
		static if (BOTAN_HAS_ECDSA) {
			if (const ECDSA_PrivateKey s = cast(const ECDSA_PrivateKey)(key))
				return new ECDSA_Signature_Operation(s);
		}
		
		static if (BOTAN_HAS_GOST_34_10_2001) {
			if (const GOST_3410_PrivateKey s = cast(const GOST_3410_PrivateKey)(key))
				return new GOST_3410_Signature_Operation(s);
		}
		
		static if (BOTAN_HAS_NYBERG_RUEPPEL) {
			if (const NR_PrivateKey s = cast(const NR_PrivateKey)(key))
				return new NR_Signature_Operation(s);
		}
		
		return null;
	}

	Verification get_verify_op(in Public_Key key, RandomNumberGenerator rng) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PublicKey s = cast(const RSA_PublicKey)(key))
				return new RSA_Public_Operation(s);
		}
		
		static if (BOTAN_HAS_RW) {
			if (const RW_PublicKey s = cast(const RW_PublicKey)(key))
				return new RW_Verification_Operation(s);
		}
		
		static if (BOTAN_HAS_DSA) {
			if (const DSA_PublicKey s = cast(const DSA_PublicKey)(key))
				return new DSA_Verification_Operation(s);
		}
		
		static if (BOTAN_HAS_ECDSA) {
			if (const ECDSA_PublicKey s = cast(const ECDSA_PublicKey)(key))
				return new ECDSA_Verification_Operation(s);
		}
		
		static if (BOTAN_HAS_GOST_34_10_2001) {
			if (const GOST_3410_PublicKey s = cast(const GOST_3410_PublicKey)(key))
				return new GOST_3410_Verification_Operation(s);
		}
		
		static if (BOTAN_HAS_NYBERG_RUEPPEL) {
			if (const NR_PublicKey s = cast(const NR_PublicKey)(key))
				return new NR_Verification_Operation(s);
		}
		
		return null;
	}


	Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PublicKey s = cast(const RSA_PublicKey)(key))
				return new RSA_Public_Operation(s);
		}
		
		static if (BOTAN_HAS_ELGAMAL) {
			if (const ElGamal_PublicKey s = cast(const ElGamal_PublicKey)(key))
				return new ElGamal_Encryption_Operation(s);
		}
		
		return null;
	}

	Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PrivateKey s = cast(const RSA_PrivateKey)(key))
				return new RSA_Private_Operation(s, rng);
		}
		
		static if (BOTAN_HAS_ELGAMAL) {
			if (const ElGamal_PrivateKey s = cast(const ElGamal_PrivateKey)(key))
				return new ElGamal_Decryption_Operation(s, rng);
		}
		
		return null;
	}

	Modular_Exponentiator mod_exp(in BigInt n, Power_Mod.Usage_Hints hints) const
	{
		if (n.is_odd())
			return new Montgomery_Exponentiator(n, hints);
		return new Fixed_Window_Exponentiator(n, hints);
	}


	Keyed_Filter get_cipher(in string algo_spec,
	                                 Cipher_Dir direction,
	                                 Algorithm_Factory af)
	{
		Vector!string algo_parts = splitter(algo_spec, '/');
		if (algo_parts.empty)
			throw new Invalid_Algorithm_Name(algo_spec);
		
		const string cipher_name = algo_parts[0];
		
		// check if it is a stream cipher first (easy case)
		const StreamCipher stream_cipher = af.prototype_stream_cipher(cipher_name);
		if (stream_cipher)
			return new StreamCipher_Filter(stream_cipher.clone());
		
		const BlockCipher block_cipher = af.prototype_block_cipher(cipher_name);
		if (!block_cipher)
			return null;
		
		if (algo_parts.length >= 4)
			return null; // 4 part mode, not something we know about
		
		if (algo_parts.length < 2)
			throw new Lookup_Error("Cipher specification '" ~ algo_spec +
			                       "' is missing mode identifier");
		
		string mode = algo_parts[1];
		
		string padding;
		if (algo_parts.length == 3)
			padding = algo_parts[2];
		else
			padding = (mode == "CBC") ? "PKCS7" : "NoPadding";
		
		if (mode == "ECB" && padding == "CTS")
			return null;
		else if ((mode != "CBC" && mode != "ECB") && padding != "NoPadding")
			throw new Invalid_Algorithm_Name(algo_spec);
		
		Keyed_Filter filt = get_cipher_mode(block_cipher, direction, mode, padding);
		if (filt)
			return filt;
		
		if (padding != "NoPadding")
			throw new Algorithm_Not_Found(cipher_name ~ "/" ~ mode ~ "/" ~ padding);
		else
			throw new Algorithm_Not_Found(cipher_name ~ "/" ~ mode);
	}


	BlockCipher find_block_cipher(in SCAN_Name request,
                                      		Algorithm_Factory af) const
	{
		
		static if (BOTAN_HAS_AES) {
			if (request.algo_name == "AES-128")
				return new AES_128;
			if (request.algo_name == "AES-192")
				return new AES_192;
			if (request.algo_name == "AES-256")
				return new AES_256;
		}
		
		static if (BOTAN_HAS_BLOWFISH) {
			if (request.algo_name == "Blowfish")
				return new Blowfish;
		}
		
		static if (BOTAN_HAS_CAMELLIA) {
			if (request.algo_name == "Camellia-128")
				return new Camellia_128;
			if (request.algo_name == "Camellia-192")
				return new Camellia_192;
			if (request.algo_name == "Camellia-256")
				return new Camellia_256;
		}
		
		static if (BOTAN_HAS_CAST) {
			if (request.algo_name == "CAST-128")
				return new CAST_128;
			if (request.algo_name == "CAST-256")
				return new CAST_256;
		}
		
		static if (BOTAN_HAS_DES) {
			if (request.algo_name == "DES")
				return new DES;
			if (request.algo_name == "DESX")
				return new DESX;
			if (request.algo_name == "TripleDES")
				return new TripleDES;
		}
		
		static if (BOTAN_HAS_GOST_28147_89) {
			if (request.algo_name == "GOST-28147-89")
				return new GOST_28147_89(request.arg(0, "R3411_94_TestParam"));
		}
		
		static if (BOTAN_HAS_IDEA) {
			if (request.algo_name == "IDEA")
				return new IDEA;
		}
		
		static if (BOTAN_HAS_KASUMI) {
			if (request.algo_name == "KASUMI")
				return new KASUMI;
		}
		
		static if (BOTAN_HAS_MARS) {
			if (request.algo_name == "MARS")
					return new MARS;
		}
		
		static if (BOTAN_HAS_MISTY1) {
			if (request.algo_name == "MISTY1")
				return new MISTY1(request.arg_as_integer(0, 8));
		}
		
		static if (BOTAN_HAS_NOEKEON) {
			if (request.algo_name == "Noekeon")
				return new Noekeon;
		}
		
		static if (BOTAN_HAS_RC2) {
			if (request.algo_name == "RC2")
				return new RC2;
		}
		
		static if (BOTAN_HAS_RC5) {
			if (request.algo_name == "RC5")
				return new RC5(request.arg_as_integer(0, 12));
		}
		
		static if (BOTAN_HAS_RC6) {
			if (request.algo_name == "RC6")
				return new RC6;
		}
		
		static if (BOTAN_HAS_SAFER) {
			if (request.algo_name == "SAFER-SK")
				return new SAFER_SK(request.arg_as_integer(0, 10));
		}
		
		static if (BOTAN_HAS_SEED) {
			if (request.algo_name == "SEED")
				return new SEED;
		}
		
		static if (BOTAN_HAS_SERPENT) {
			if (request.algo_name == "Serpent")
				return new Serpent;
		}
		
		static if (BOTAN_HAS_TEA) {
			if (request.algo_name == "TEA")
				return new TEA;
		}
		
		static if (BOTAN_HAS_TWOFISH) {
			if (request.algo_name == "Twofish")
				return new Twofish;
		}
		
		static if (BOTAN_HAS_TWOFISH) {
			if (request.algo_name == "Threefish-512")
				return new Threefish_512;
		}
		
		static if (BOTAN_HAS_XTEA) {
			if (request.algo_name == "XTEA")
				return new XTEA;
		}
		
		static if (BOTAN_HAS_CASCADE) {
			if (request.algo_name == "Cascade" && request.arg_count() == 2)
			{
				const BlockCipher c1 = af.prototype_block_cipher(request.arg(0));
				const BlockCipher c2 = af.prototype_block_cipher(request.arg(1));
				
				if (c1 && c2)
					return new Cascade_Cipher(c1.clone(), c2.clone());
			}
		}
		
		static if (BOTAN_HAS_LION) {
			if (request.algo_name == "Lion" && request.arg_count_between(2, 3))
			{
				const size_t block_size = request.arg_as_integer(2, 1024);
				
				const HashFunction hash = af.prototype_hash_function(request.arg(0));
				
				const StreamCipher stream_cipher = af.prototype_stream_cipher(request.arg(1));
				
				if (!hash || !stream_cipher)
					return null;
				
				return new Lion(hash.clone(), stream_cipher.clone(), block_size);
			}
		}
		
		return null;
	}

	StreamCipher find_stream_cipher(in SCAN_Name request,
	                                         Algorithm_Factory af) const
	{
		static if (BOTAN_HAS_OFB) {
			if (request.algo_name == "OFB" && request.arg_count() == 1)
			{
				if (auto proto = af.prototype_block_cipher(request.arg(0)))
					return new OFB(proto.clone());
			}
		}
		
		static if (BOTAN_HAS_CTR_BE) {
			if (request.algo_name == "CTR-BE" && request.arg_count() == 1)
			{
				if (auto proto = af.prototype_block_cipher(request.arg(0)))
					return new CTR_BE(proto.clone());
			}
		}
		
		static if (BOTAN_HAS_RC4) {
			if (request.algo_name == "RC4")
				return new RC4(request.arg_as_integer(0, 0));
			if (request.algo_name == "RC4_drop")
				return new RC4(768);
		}
		
		static if (BOTAN_HAS_CHACHA) {
			if (request.algo_name == "ChaCha")
				return new ChaCha;
		}
		
		static if (BOTAN_HAS_SALSA20) {
			if (request.algo_name == "Salsa20")
				return new Salsa20;
		}
		
		return null;
	}

	HashFunction find_hash(in SCAN_Name request,
	                                Algorithm_Factory af) const
	{
		static if (BOTAN_HAS_ADLER32) {
			if (request.algo_name == "Adler32")
				return new Adler32;
		}
		
		static if (BOTAN_HAS_CRC24) {
			if (request.algo_name == "CRC24")
				return new CRC24;
		}
		
		static if (BOTAN_HAS_CRC32) {
			if (request.algo_name == "CRC32")
				return new CRC32;
		}
		
		static if (BOTAN_HAS_GOST_34_11) {
			if (request.algo_name == "GOST-R-34.11-94")
				return new GOST_34_11;
		}
		
		static if (BOTAN_HAS_HAS_160) {
			if (request.algo_name == "HAS-160")
				return new HAS_160;
		}
		
		static if (BOTAN_HAS_KECCAK) {
			if (request.algo_name == "Keccak-1600")
				return new Keccak_1600(request.arg_as_integer(0, 512));
		}
		
		static if (BOTAN_HAS_MD2) {
			if (request.algo_name == "MD2")
				return new MD2;
		}
		
		static if (BOTAN_HAS_MD4) {
			if (request.algo_name == "MD4")
				return new MD4;
		}
		
		static if (BOTAN_HAS_MD5) {
			if (request.algo_name == "MD5")
				return new MD5;
		}
		
		static if (BOTAN_HAS_RIPEMD_128) {
			if (request.algo_name == "RIPEMD-128")
				return new RIPEMD_128;
		}
		
		static if (BOTAN_HAS_RIPEMD_160) {
			if (request.algo_name == "RIPEMD-160")
				return new RIPEMD_160;
		}
		
		static if (BOTAN_HAS_SHA1) {
			if (request.algo_name == "SHA-160")
				return new SHA_160;
		}
		
		static if (BOTAN_HAS_SHA2_32) {
			if (request.algo_name == "SHA-224")
				return new SHA_224;
			if (request.algo_name == "SHA-256")
				return new SHA_256;
		}
		
		static if (BOTAN_HAS_SHA2_64) {
			if (request.algo_name == "SHA-384")
				return new SHA_384;
			if (request.algo_name == "SHA-512")
				return new SHA_512;
		}
		
		static if (BOTAN_HAS_TIGER) {
			if (request.algo_name == "Tiger")
				return new Tiger(request.arg_as_integer(0, 24), // hash output
				                 request.arg_as_integer(1, 3)); // # passes
		}
		
		static if (BOTAN_HAS_SKEIN_512) {
			if (request.algo_name == "Skein-512")
				return new Skein_512(request.arg_as_integer(0, 512),
				                     request.arg(1, ""));
		}
		
		static if (BOTAN_HAS_WHIRLPOOL) {
			if (request.algo_name == "Whirlpool")
				return new Whirlpool;
		}
		
		static if (BOTAN_HAS_COMB4P) {
			if (request.algo_name == "Comb4P" && request.arg_count() == 2)
			{
				const HashFunction h1 = af.prototype_hash_function(request.arg(0));
				const HashFunction h2 = af.prototype_hash_function(request.arg(1));
				
				if (h1 && h2)
					return new Comb4P(h1.clone(), h2.clone());
			}
		}
		
		static if (BOTAN_HAS_PARALLEL_HASH) {
			
			if (request.algo_name == "Parallel")
			{
				Vector!( const HashFunction ) hash_prototypes;
				
				/* First pass, just get the prototypes (no memory allocation). Then
					if all were found, replace each prototype with a newly created clone
				*/
				foreach (size_t i; 0 .. request.arg_count())
				{
					const HashFunction hash = af.prototype_hash_function(request.arg(i));
					if (!hash)
						return null;
					
					hash_prototypes.push_back(hash);
				}
				
				Vector!HashFunction hashes;
				foreach (hash_prototype; hash_prototypes)
					hashes.push_back(hash_prototype.clone());
				
				return new Parallel(hashes);
			}
		}
		
		return null;
		
	}

	MessageAuthenticationCode find_mac(in SCAN_Name request,
	                                            Algorithm_Factory af) const
	{
		
		static if (BOTAN_HAS_CBC_MAC) {
			if (request.algo_name == "CBC-MAC" && request.arg_count() == 1)
				return new CBC_MAC(af.make_block_cipher(request.arg(0)));
		}
		
		static if (BOTAN_HAS_CMAC) {
			if (request.algo_name == "CMAC" && request.arg_count() == 1)
				return new CMAC(af.make_block_cipher(request.arg(0)));
		}
		
		static if (BOTAN_HAS_HMAC) {
			if (request.algo_name == "HMAC" && request.arg_count() == 1)
				return new HMAC(af.make_hash_function(request.arg(0)));
		}
		
		static if (BOTAN_HAS_SSL3_MAC) {
			if (request.algo_name == "SSL3-MAC" && request.arg_count() == 1)
				return new SSL3_MAC(af.make_hash_function(request.arg(0)));
		}
		
		static if (BOTAN_HAS_ANSI_X919_MAC) {
			if (request.algo_name == "X9.19-MAC" && request.arg_count() == 0)
				return new ANSI_X919_MAC(af.make_block_cipher("DES"));
		}
		
		return null;
	}


	PBKDF find_pbkdf(in SCAN_Name algo_spec,
	                          Algorithm_Factory af) const
	{
		static if (BOTAN_HAS_PBKDF1) {
			if (algo_spec.algo_name == "PBKDF1" && algo_spec.arg_count() == 1)
				return new PKCS5_PBKDF1(af.make_hash_function(algo_spec.arg(0)));
		}
		
		static if (BOTAN_HAS_PBKDF2) {
			if (algo_spec.algo_name == "PBKDF2" && algo_spec.arg_count() == 1)
			{
				if (const MessageAuthenticationCode mac_proto = af.prototype_mac(algo_spec.arg(0)))
					return new PKCS5_PBKDF2(mac_proto.clone());
				
				return new PKCS5_PBKDF2(af.make_mac("HMAC(" ~ algo_spec.arg(0) ~ ")"));
			}
		}
		
		return null;
	}

}

/**
* Create a cipher mode filter object
* @param block_cipher a block cipher object
* @param direction are we encrypting or decrypting?
* @param mode the name of the cipher mode to use
* @param padding the mode padding to use (only used for ECB, CBC)
*/
Keyed_Filter get_cipher_mode(const BlockCipher block_cipher,
                             Cipher_Dir direction,
                             in string mode,
                             in string padding)
{
	static if (BOTAN_HAS_OFB) {
		if (mode == "OFB")
			return new StreamCipher_Filter(new OFB(block_cipher.clone()));
	}
		
	static if (BOTAN_HAS_CTR_BE) {
		if (mode == "CTR-BE")
			return new StreamCipher_Filter(new CTR_BE(block_cipher.clone()));
	}
		
	static if (BOTAN_HAS_MODE_ECB) {
		if (mode == "ECB" || mode == "")
		{
			if (direction == ENCRYPTION)
				return new Transformation_Filter(
					new ECB_Encryption(block_cipher.clone(), get_bc_pad(padding, "NoPadding")));
			else
				return new Transformation_Filter(
					new ECB_Decryption(block_cipher.clone(), get_bc_pad(padding, "NoPadding")));
		}
	}
	
	if (mode == "CBC")
	{
		static if (BOTAN_HAS_MODE_CBC) {
				if (padding == "CTS")
				{
					if (direction == ENCRYPTION)
						return new Transformation_Filter(new CTS_Encryption(block_cipher.clone()));
					else
						return new Transformation_Filter(new CTS_Decryption(block_cipher.clone()));
				}
				
				if (direction == ENCRYPTION)
					return new Transformation_Filter(
						new CBC_Encryption(block_cipher.clone(), get_bc_pad(padding, "PKCS7")));
				else
					return new Transformation_Filter(
						new CBC_Decryption(block_cipher.clone(), get_bc_pad(padding, "PKCS7")));
		} else {
				return null;
		}
	}
	
	static if (BOTAN_HAS_MODE_XTS) {
		if (mode == "XTS")
		{
			if (direction == ENCRYPTION)
				return new Transformation_Filter(new XTS_Encryption(block_cipher.clone()));
			else
				return new Transformation_Filter(new XTS_Decryption(block_cipher.clone()));
		}
	}
	
	if (mode.find("CFB") != -1 ||
	    mode.find("EAX") != -1 ||
	    mode.find("GCM") != -1 ||
	    mode.find("OCB") != -1 ||
	    mode.find("CCM") != -1)
	{
		Vector!string algo_info = parse_algorithm_name(mode);
		const string mode_name = algo_info[0];
		
		size_t bits = 8 * block_cipher.block_size;
		if (algo_info.length > 1)
			bits = to_uint(algo_info[1]);
		
		static if (BOTAN_HAS_MODE_CFB) {
				if (mode_name == "CFB")
				{
					if (direction == ENCRYPTION)
						return new Transformation_Filter(new CFB_Encryption(block_cipher.clone(), bits));
					else
						return new Transformation_Filter(new CFB_Decryption(block_cipher.clone(), bits));
				}
		}
				
		if (bits % 8 != 0)
			throw new Invalid_Argument("AEAD interface does not support non-octet length tags");
		
		static if (BOTAN_HAS_AEAD_FILTER) {
		
			const size_t tag_size = bits / 8;
			
			static if (BOTAN_HAS_AEAD_CCM) {
					if (mode_name == "CCM")
					{
						const size_t L = (algo_info.length == 3) ? to_uint(algo_info[2]) : 3;
						if (direction == ENCRYPTION)
							return new AEAD_Filter(new CCM_Encryption(block_cipher.clone(), tag_size, L));
						else
							return new AEAD_Filter(new CCM_Decryption(block_cipher.clone(), tag_size, L));
					}
			}
					
			static if (BOTAN_HAS_AEAD_EAX) {
					if (mode_name == "EAX")
					{
						if (direction == ENCRYPTION)
							return new AEAD_Filter(new EAX_Encryption(block_cipher.clone(), tag_size));
						else
							return new AEAD_Filter(new EAX_Decryption(block_cipher.clone(), tag_size));
					}
			}
					
			static if (BOTAN_HAS_AEAD_OCB) {
					if (mode_name == "OCB")
					{
						if (direction == ENCRYPTION)
							return new AEAD_Filter(new OCB_Encryption(block_cipher.clone(), tag_size));
						else
							return new AEAD_Filter(new OCB_Decryption(block_cipher.clone(), tag_size));
					}
			}
					
			static if (BOTAN_HAS_AEAD_GCM) {
					if (mode_name == "GCM")
					{
						if (direction == ENCRYPTION)
							return new AEAD_Filter(new GCM_Encryption(block_cipher.clone(), tag_size));
						else
							return new AEAD_Filter(new GCM_Decryption(block_cipher.clone(), tag_size));
					}
			}
			
		}
	}
	
	return null;
}

private {
	
	/**
	* Get a block cipher padding method by name
	*/
	BlockCipherModePaddingMethod get_bc_pad(in string algo_spec,
	                                         in string def_if_empty)
	{
		static if (BOTAN_HAS_CIPHER_MODE_PADDING) {
			if (algo_spec == "NoPadding" || (algo_spec == "" && def_if_empty == "NoPadding"))
				return new Null_Padding;
			
			if (algo_spec == "PKCS7" || (algo_spec == "" && def_if_empty == "PKCS7"))
				return new PKCS7_Padding;
			
			if (algo_spec == "OneAndZeros")
				return new OneAndZeros_Padding;
			
			if (algo_spec == "X9.23")
				return new ANSI_X923_Padding;
			
		}
		
		throw new Algorithm_Not_Found(algo_spec);
	}
	
}