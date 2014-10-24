﻿module botan.constants;

enum BOTAN_VERSION_MAJOR = 2;
enum BOTAN_VERSION_MINOR = 0;
enum BOTAN_VERSION_PATCH = 0;
enum BOTAN_VERSION_DATESTAMP = 20141030;
enum BOTAN_VERSION_RELEASE_TYPE = "unreleased";
enum BOTAN_VERSION_VC_REVISION = "123";
enum BOTAN_DISTRIBUTION_INFO = "unspecified";

// Guessing these are okay this way.
enum BOTAN_TARGET_CPU_HAS_KNOWN_ENDIANNESS = true;
enum BOTAN_TARGET_UNALIGNED_MEMORY_ACCESS_OK = true;
enum BOTAN_DEFAULT_BUFFER_SIZE = 4096;
enum BOTAN_MEM_POOL_CHUNK_SIZE = 64*1024;
enum BOTAN_BLOCK_CIPHER_PAR_MULT = 4;

version(X86) enum BOTAN_MP_WORD_BITS = 32;
version(X86_64) enum BOTAN_MP_WORD_BITS = 64;
version(ARM) enum BOTAN_MP_WORD_BITS = 32;
enum BOTAN_KARAT_MUL_THRESHOLD = 32;
enum BOTAN_KARAT_SQR_THRESHOLD = 32;
enum BOTAN_RNG_MAX_OUTPUT_BEFORE_RESEED = 512;
enum BOTAN_RNG_RESEED_POLL_BITS = 128;

version(D_InlineAsm_X86) {	enum BOTAN_USE_GCC_INLINE_ASM = true;													}
version(D_InlineAsm_X86_64){enum BOTAN_USE_GCC_INLINE_ASM = true;													}
else static assert("Inline ASM not implemented");

version(X86_64)			{	enum BOTAN_TARGET_CPU_HAS_SSE2 = true;													}
else						enum BOTAN_TARGET_CPU_HAS_SSE2 = false;
version(X86)			{	enum BOTAN_TARGET_CPU_IS_X86_FAMILY = true;												}
else version(X86_64)	{	enum BOTAN_TARGET_CPU_IS_X86_FAMILY = true;												}
else						enum BOTAN_TARGET_CPU_IS_X86_FAMILY = false;
version(ARM)			{	enum BOTAN_TARGET_CPU_IS_ARM_FAMILY = true;												}
else						enum BOTAN_TARGET_CPU_IS_ARM_FAMILY = false;

version(SIMD_SSE2)		{	enum BOTAN_HAS_SIMD_SSE2 = true;														}
else						enum BOTAN_HAS_SIMD_SSE2 = false;
version(SIMD_Altivec)	{	enum BOTAN_HAS_SIMD_ALTIVEC = true;														}
else						enum BOTAN_HAS_SIMD_ALTIVEC = false;
version(SIMD_Scalar)	{	enum BOTAN_HAS_SIMD_SCALAR = true;														}
else						enum BOTAN_HAS_SIMD_SCALAR = false;

version(No_SSE_Intrinsics){	enum BOTAN_NO_SSE_INTRINSICS = true;													}
else						enum BOTAN_NO_SSE_INTRINSICS = false;
version(Locking_Allocator){	enum BOTAN_HAS_LOCKING_ALLOCATOR = true;												}
else						enum BOTAN_HAS_LOCKING_ALLOCATOR = false;

version(RT_Test)		{	enum BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = true;										}
else						enum BOTAN_PUBLIC_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv)	{	enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = true;									}
else						enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_LOAD = false;
version(RT_Test_Priv_Gen){	enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = true;								}
else						enum BOTAN_PRIVATE_KEY_STRONG_CHECKS_ON_GENERATE = false;

version(AES_NI)			{	enum BOTAN_HAS_AES_NI = true;															}
else						enum BOTAN_HASH_AES_NI = false;
version(Serpent_x86_32)	{	enum BOTAN_HAS_SERPENT_X86_32 = true;		version(X86){} else static assert(false); 	}
else						enum BOTAN_HAS_SERPENT_X86_32 = false;
version(MD4_x86_32)		{	enum BOTAN_HAS_MD4_X86_32 = true;			version(X86){} else static assert(false); 	}
else						enum BOTAN_HAS_MD4_X86_32 = false;
version(MD5_x86_32)		{	enum BOTAN_HAS_MD5_X86_32 = true;			version(X86){} else static assert(false); 	}
else						enum BOTAN_HAS_MD5_X86_32 = false;
version(SHA1_x86_64)	{	enum BOTAN_HAS_SHA1_X86_64 = true;			version(X86_64){} else static assert(false);}
else						enum BOTAN_HAS_SHA1_X86_64 = false;
version(SHA1_x86_32)	{	enum BOTAN_HAS_SHA1_X86_32 = true;			version(X86){} else static assert(false);	}
else						enum BOTAN_HAS_SHA1_X86_32 = false;
version(CFB)			{	enum BOTAN_HAS_MODE_CFB = true;															}
else						enum BOTAN_HAS_MODE_CFB = false;
version(ECB)			{	enum BOTAN_HAS_MODE_ECB = true;															}
else						enum BOTAN_HAS_MODE_ECB = false;
version(CBC)			{	enum BOTAN_HAS_MODE_CBC = true;															}
else						enum BOTAN_HAS_MODE_CBC = false;
version(XTS)			{	enum BOTAN_HAS_MODE_XTS = true;															}
else						enum BOTAN_HAS_MODE_XTS = false;
version(OFB)			{	enum BOTAN_HAS_OFB = true;																}
else						enum BOTAN_HAS_OFB = false;
version(CTR_BE)			{	enum BOTAN_HAS_CTR_BE = true;															}
else						enum BOTAN_HAS_CTR_BE = false;
version(AEAD_FILTER)	{	enum BOTAN_HAS_AEAD_FILTER = true;														}
else						enum BOTAN_HAS_AEAD_FILTER = false;
version(AEAD_CCM)		{	enum BOTAN_HAS_AEAD_CCM = true;															}
else						enum BOTAN_HAS_AEAD_CCM = false;
version(AEAD_EAX)		{	enum BOTAN_HAS_AEAD_EAX = true;															}
else						enum BOTAN_HAS_AEAD_EAX = false;
version(AEAD_OCB)		{	enum BOTAN_HAS_AEAD_OCB = true;															}
else						enum BOTAN_HAS_AEAD_OCB = false;
version(AEAD_GCM)		{	enum BOTAN_HAS_AEAD_GCM = true;															}
else						enum BOTAN_HAS_AEAD_GCM = false;
version(RSA)			{	enum BOTAN_HAS_RSA = true;																}
else						enum BOTAN_HAS_RSA = false;
version(RW)				{	enum BOTAN_HAS_RW = true;																}
else						enum BOTAN_HAS_RW = false;
version(DSA)			{	enum BOTAN_HAS_DSA = true;																}
else						enum BOTAN_HAS_DSA = false;
version(ECDSA)			{	enum BOTAN_HAS_ECDSA = true;															}
else						enum BOTAN_HAS_ECDSA = false;
version(ElGamal)		{	enum BOTAN_HAS_ELGAMAL = true;															}
else						enum BOTAN_HAS_ELGAMAL = false;
version(GOST_3410)		{	enum BOTAN_HAS_GOST_34_10_2001 = true;													}
else						enum BOTAN_HAS_GOST_34_10_2001 = false;
version(Nyberg_Rueppel)	{	enum BOTAN_HAS_NYBERG_RUEPPEL = true;													}
else						enum BOTAN_HAS_NYBERG_RUEPPEL = false;
version(Diffie_Hellman)	{	enum BOTAN_HAS_DIFFIE_HELLMAN = true;													}
else						enum BOTAN_HAS_DIFFIE_HELLMAN = false;
version(ECDH)			{	enum BOTAN_HAS_ECDH = true;																}
else						enum BOTAN_HAS_ECDH = false;
version(AES)			{	enum BOTAN_HAS_AES = true;																}
else						enum BOTAN_HAS_AES = false;
version(Blowfish)		{	enum BOTAN_HAS_BLOWFISH = true;															}
else						enum BOTAN_HAS_BLOWFISH = false;
version(Camellia)		{	enum BOTAN_HAS_CAMELLIA = true;															}
else						enum BOTAN_HAS_CAMELLIA = false;
version(CAST)			{	enum BOTAN_HAS_CAST = true;																}
else						enum BOTAN_HAS_CAST = false;
version(Cascade)		{	enum BOTAN_HAS_CASCADE = true;															}
else						enum BOTAN_HAS_CASCADE = false;
version(DES)			{	enum BOTAN_HAS_DES = true;																}
else						enum BOTAN_HAS_DES = false;
version(GOST_28147)		{	enum BOTAN_HAS_GOST_28147_89 = true;													}
else						enum BOTAN_HAS_GOST_28147_89 = false;
version(IDEA)			{	enum BOTAN_HAS_IDEA = true;																}
else						enum BOTAN_HAS_IDEA = false;
version(KASUMI)			{	enum BOTAN_HAS_KASUMI = true;															}
else						enum BOTAN_HAS_KASUMI = false;
version(LION)			{	enum BOTAN_HAS_LION = true;																}
else						enum BOTAN_HAS_LION = false;
version(MARS)			{	enum BOTAN_HAS_MARS = true;																}
else						enum BOTAN_HAS_MARS = false;
version(MISTY1)			{	enum BOTAN_HAS_MISTY1 = true;															}
else						enum BOTAN_HAS_MISTY1 = false;
version(NOEKEON)		{	enum BOTAN_HAS_NOEKEON = true;															}
else						enum BOTAN_HAS_NOEKEON = false;
version(RC2)			{	enum BOTAN_HAS_RC2 = true;																}
else						enum BOTAN_HAS_RC2 = false;
version(RC5)			{	enum BOTAN_HAS_RC5 = true;																}
else						enum BOTAN_HAS_RC5 = false;
version(RC6)			{	enum BOTAN_HAS_RC6 = true;																}
else						enum BOTAN_HAS_RC6 = false;
version(SAFER)			{	enum BOTAN_HAS_SAFER = true;															}
else						enum BOTAN_HAS_SAFER = false;
version(SEED)			{	enum BOTAN_HAS_SEED = true;																}
else						enum BOTAN_HAS_SEED = false;
version(Serpent)		{	enum BOTAN_HAS_SERPENT = true;															}
else						enum BOTAN_HAS_SERPENT = false;
version(TEA)			{	enum BOTAN_HAS_TEA = true;																}
else						enum BOTAN_HAS_TEA = false;
version(Twofish)		{	enum BOTAN_HAS_TWOFISH = true;															}
else						enum BOTAN_HAS_TWOFISH = false;
version(Threefish)		{	enum BOTAN_HAS_THREEFISH_512 = true;													}
else						enum BOTAN_HAS_THREEFISH_512 = false;
version(XTEA)			{	enum BOTAN_HAS_XTEA = true;																}
else						enum BOTAN_HAS_XTEA = false;
version(Adler32)		{	enum BOTAN_HAS_ADLER32 = true;															}
else						enum BOTAN_HAS_ADLER32 = false;
version(CRC24)			{	enum BOTAN_HAS_CRC24 = true;															}
else						enum BOTAN_HAS_CRC24 = false;
version(CRC32)			{	enum BOTAN_HAS_CRC32 = true;															}
else						enum BOTAN_HAS_CRC32 = false;
version(GOST_3411)		{	enum BOTAN_HAS_GOST_34_11 = true;														}
else						enum BOTAN_HAS_GOST_34_11 = false;
version(HAS_160)		{	enum BOTAN_HAS_HAS_160 = true;															}
else						enum BOTAN_HAS_HAS_160 = false;
version(Keccak)			{	enum BOTAN_HAS_KECCAK = true;															}
else						enum BOTAN_HAS_KECCAK = false;
version(MD2)			{	enum BOTAN_HAS_MD2 = true;																}
else						enum BOTAN_HAS_MD2 = false;
version(MD4)			{	enum BOTAN_HAS_MD4 = true;																}
else						enum BOTAN_HAS_MD4 = false;
version(MD5)			{	enum BOTAN_HAS_MD5 = true;																}
else						enum BOTAN_HAS_MD5 = false;
version(RIPEMD_128)		{	enum BOTAN_HAS_RIPEMD_128 = true;														}
else						enum BOTAN_HAS_RIPEMD_128 = false;
version(RIPEMD_160)		{	enum BOTAN_HAS_RIPEMD_160 = true;														}
else						enum BOTAN_HAS_RIPEMD_160 = false;
version(SHA1)			{	enum BOTAN_HAS_SHA160 = true;															}
else						enum BOTAN_HAS_SHA160 = false;
version(SHA2_32)		{	enum BOTAN_HAS_SHA2_32 = true;															}
else						enum BOTAN_HAS_SHA2_32 = false;
version(SHA2_64)		{	enum BOTAN_HAS_SHA2_64 = true;															}
else						enum BOTAN_HAS_SHA2_64 = false;
version(Skein_512)		{	enum BOTAN_HAS_SKEIN_512 = true;														}
else						enum BOTAN_HAS_SKEIN_512 = false;
version(Tiger)			{	enum BOTAN_HAS_TIGER = true;															}
else						enum BOTAN_HAS_TIGER = false;
version(Whirlpool)		{	enum BOTAN_HAS_WHIRLPOOL = true;														}
else						enum BOTAN_HAS_TIGER = false;
version(ParallelHash)	{	enum BOTAN_HAS_PARALLEL_HASH = true;													}
else						enum BOTAN_HAS_PARALLEL_HASH = false;
version(Comb4P)			{	enum BOTAN_HAS_COMB4P = true;															}
else						enum BOTAN_HAS_COMB4P = false;
version(CBC_MAC)		{	enum BOTAN_HAS_CBC_MAC = true;															}
else						enum BOTAN_HAS_CBC_MAC = false;
version(CMAC)			{	enum BOTAN_HAS_CMAC = true;																}
else						enum BOTAN_HAS_CMAC = false;
version(HMAC)			{	enum BOTAN_HAS_HMAC = true;																}
else						enum BOTAN_HAS_HMAC = false;
version(SSL3_MAC)		{	enum BOTAN_HAS_SSL3_MAC = true;															}
else						enum BOTAN_HAS_SSL3_MAC = false;
version(ANSI_X919_MAC)	{	enum BOTAN_HAS_ANSI_X919_MAC = true;													}
else						enum BOTAN_HAS_ANSI_X919_MAC = false;
version(PBKDF1)			{	enum BOTAN_HAS_PBKDF1 = true;															}
else						enum BOTAN_HAS_PBKDF1 = false;
version(PBKDF2)			{	enum BOTAN_HAS_PBKDF2 = true;															}
else						enum BOTAN_HAS_PBKDF2 = false;
version(RC4)			{	enum BOTAN_HAS_RC4 = true;																}
else						enum BOTAN_HAS_RC4 = false;
version(ChaCha)			{	enum BOTAN_HAS_CHACHA = true;															}
else						enum BOTAN_HAS_CHACHA = false;
version(Salsa20)		{	enum BOTAN_HAS_SALSA20 = true;															}
else						enum BOTAN_HAS_SALSA20 = false;
version(AES_SSSE3)		{	enum BOTAN_HAS_AES_SSSE3 = true;														}
else						enum BOTAN_HAS_AES_SSSE3 = false;
version(Serpent_SIMD)	{	enum BOTAN_HAS_SERPENT_SIMD = true;														}
else						enum BOTAN_HAS_SERPENT_SIMD = false;
version(Threefish_512_AVX2){enum BOTAN_HAS_THREEFISH_512_AVX2 = true;												}
else						enum BOTAN_HAS_THREEFISH_512_AVX2 = false;
version(Noekeon_SIMD)	{	enum BOTAN_HAS_NOEKEON_SIMD = true;														}
else						enum BOTAN_HAS_NOEKEON_SIMD = false;
version(XTEA_SIMD)		{	enum BOTAN_HAS_XTEA_SIMD = true;														}
else						enum BOTAN_HAS_XTEA_SIMD = false;
version(IDEA_SSE2)		{	enum BOTAN_HAS_IDEA_SSE2 = true;														}
else						enum BOTAN_HAS_IDEA_SSE2 = false;
version(SHA1_SSE2)		{	enum BOTAN_HAS_SHA1_SSE2 = true;														}
else						enum BOTAN_HAS_SHA1_SSE2 = false;


version(Engine_ASM)		{	enum BOTAN_HAS_ENGINE_ASSEMBLER = true;													}
else						enum BOTAN_HAS_ENGINE_ASSEMBLER = false;
version(Engine_AES_ISA)	{	enum BOTAN_HAS_ENGINE_AES_ISA = true;													}
else						enum BOTAN_HAS_ENGINE_AES_ISA = false;
version(Engine_SIMD)	{	enum BOTAN_HAS_ENGINE_SIMD = true;														}
else						enum BOTAN_HAS_ENGINE_SIMD = false;
version(Engine_GNU_MP)	{	enum BOTAN_HAS_ENGINE_GNU_MP = true;													}
else						enum BOTAN_HAS_ENGINE_GNU_MP = false;
version(Entropy_HRTimer){	enum BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = true;								}
else						enum BOTAN_HAS_ENTROPY_SRC_HIGH_RESOLUTION_TIMER = false;
version(Entropy_Rdrand)	{	enum BOTAN_HAS_ENTROPY_SRC_RDRAND = true;												}
else						enum BOTAN_HAS_ENTROPY_SRC_RDRAND = false;
version(Entropy_DevRand){	enum BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = true;											}	
else						enum BOTAN_HAS_ENTROPY_SRC_DEV_RANDOM = false;
version(Entropy_EGD)	{	enum BOTAN_HAS_ENTROPY_SRC_EGD = true;													}
else						enum BOTAN_HAS_ENTROPY_SRC_EGD = false;
version(Entropy_UnixProc){	enum BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = true;									}
else						enum BOTAN_HAS_ENTROPY_SRC_UNIX_PROCESS_RUNNER = false;
version(Entropy_BEOS)	{	enum BOTAN_HAS_ENTROPY_SRC_BEOS = true;													}
else						enum BOTAN_HAS_ENTROPY_SRC_BEOS = false;
version(Entropy_CAPI)	{	enum BOTAN_HAS_ENTROPY_SRC_CAPI = true;													}
else						enum BOTAN_HAS_ENTROPY_SRC_CAPI = false;
version(Entropy_Win32)	{	enum BOTAN_HAS_ENTROPY_SRC_WIN32 = true;												}
else						enum BOTAN_HAS_ENTROPY_SRC_WIN32 = false;
version(Entropy_ProcWalk){	enum BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = true;											}
else						enum BOTAN_HAS_ENTROPY_SRC_PROC_WALKER = false;
version(EMSA1)			{	enum BOTAN_HAS_EMSA1 = true;															}
else						enum BOTAN_HAS_EMSA1 = false;
version(EMSA1_BSI)		{	enum BOTAN_HAS_EMSA1_BSI = true;														}
else						enum BOTAN_HAS_EMSA1_BSI = false;
version(EMSA_X931)		{	enum BOTAN_HAS_EMSA_X931 = true;														}
else						enum BOTAN_HAS_EMSA_X931 = false;
version(EMSA_PKCS1)		{	enum BOTAN_HAS_EMSA_PKCS1 = true;														}
else						enum BOTAN_HAS_EMSA_PKCS1 = false;
version(EMSA_PSSR)		{	enum BOTAN_HAS_EMSA_PSSR = true;														}
else						enum BOTAN_HAS_EMSA_PSSR = false;
version(EMSA_RAW)		{	enum BOTAN_HAS_EMSA_RAW = true;															}
else						enum BOTAN_HAS_EMSA_RAW = false;
version(EME_OAEP)		{	enum BOTAN_HAS_EME_OAEP = true;															}
else						enum BOTAN_HAS_EME_OAEP = false;
version(EME_PKCS1v15)	{	enum BOTAN_HAS_EME_PKCSv15 = true;														}
else						enum BOTAN_HAS_EME_PKCSv15 = false;
version(PBE_PKCSv20)	{	enum BOTAN_HAS_PBE_PKCS_V20 = true;														}
else						enum BOTAN_HAS_PBE_PKCS_V20 = false;
version(GCM_CLMUL)		{	enum BOTAN_HAS_GCM_CLMUL = true;														}
else						enum BOTAN_HAS_GCM_CLMUL = false;