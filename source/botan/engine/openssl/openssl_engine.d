/*
* OpenSSL Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.openssl_engine;
import botan.engine.engine;
import botan.internal.bn_wrap;
import botan.bigint;
import botan.parsing;
import openssl.rc4;
import openssl.evp;

/**
* OpenSSL Engine
*/
class OpenSSL_Engine : Engine
{
public:
	string provider_name() const { return "openssl"; }

	pk_ops.Key_Agreement
		 get_key_agreement_op(in Private_Key key, RandomNumberGenerator rng) const;

	pk_ops.Signature
		 get_signature_op(in Private_Key key, RandomNumberGenerator rng) const;

	pk_ops.Verification get_verify_op(in Public_Key key, RandomNumberGenerator rng) const;

	pk_ops.Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator rng) const;

	pk_ops.Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator rng) const;

	/*
	* Return the OpenSSL-based modular exponentiator
	*/
	Modular_Exponentiator mod_exp(in BigInt n,
	                              Power_Mod.Usage_Hints) const
	{
		return new OpenSSL_Modular_Exponentiator(n);
	}


	/*
	* Look for an algorithm with this name
	*/
	BlockCipher find_block_cipher(in SCAN_Name request,
	                              Algorithm_Factory af) const
	{
		
		version(OPENSSL_NO_AES){} else {
			/*
		Using OpenSSL's AES causes crashes inside EVP on x86-64 with OpenSSL 0.9.8g
		cause is unknown
		*/
			mixin(HANDLE_EVP_CIPHER!("AES-128", EVP_aes_128_ecb)());
			mixin(HANDLE_EVP_CIPHER!("AES-192", EVP_aes_192_ecb)());
			mixin(HANDLE_EVP_CIPHER!("AES-256", EVP_aes_256_ecb)());
		}

		version(OPENSSL_NO_DES){} else {
			mixin(HANDLE_EVP_CIPHER!("DES", EVP_des_ecb())());
			mixin(HANDLE_EVP_CIPHER_KEYLEN!("TripleDES", EVP_des_ede3_ecb, 16, 24, 8)());
		}
		
		version(OPENSSL_NO_BF){} else {
			HANDLE_EVP_CIPHER_KEYLEN("Blowfish", EVP_bf_ecb, 1, 56, 1);
		}
		
		version(OPENSSL_NO_CAST){} else {
			HANDLE_EVP_CIPHER_KEYLEN("cast(-128", EVP_cast5_ecb), 1, 16, 1);
		}
		
		version(OPENSSL_NO_CAMELLIA){} else {
			HANDLE_EVP_CIPHER("Camellia-128", EVP_camellia_128_ecb);
			HANDLE_EVP_CIPHER("Camellia-192", EVP_camellia_192_ecb);
			HANDLE_EVP_CIPHER("Camellia-256", EVP_camellia_256_ecb);
		}
		
		version(OPENSSL_NO_RC2){}else{
			HANDLE_EVP_CIPHER_KEYLEN("RC2", EVP_rc2_ecb, 1, 32, 1);
		}
		
		version(OPENSSL_NO_RC5){} else static if (false) {
			if (request.algo_name() == "RC5")
				if (request.arg_as_integer(0, 12) == 12)
					return new EVP_BlockCipher(EVP_rc5_32_12_16_ecb,
					                           "RC5(12)", 1, 32, 1);
		}
		
		version(OPENSSL_NO_IDEA){} else static if (false) {
			HANDLE_EVP_CIPHER("IDEA", EVP_idea_ecb);
		}
		
		version(OPENSSL_NO_SEED){} else {
			HANDLE_EVP_CIPHER("SEED", EVP_seed_ecb);
		}
		
		return 0;
	}

	/**
	* Look for an OpenSSL-supported stream cipher (RC4)
	*/
	StreamCipher find_stream_cipher(in SCAN_Name request,
	                                Algorithm_Factory) const
	{
		if (request.algo_name() == "RC4")
			return new RC4_OpenSSL(request.arg_as_integer(0, 0));
		if (request.algo_name() == "RC4_drop")
			return new RC4_OpenSSL(768);
		
		return 0;
	}


	/*
	* Look for an algorithm with this name
	*/
	HashFunction find_hash(in SCAN_Name request,
	                       Algorithm_Factory af) const
	{
		version(OPENSSL_NO_SHA){} else {
			if (request.algo_name() == "SHA-160")
				return new EVP_HashFunction(EVP_sha1(), "SHA-160");
		}
		
		version(OPENSSL_NO_SHA256){} else {
			if (request.algo_name() == "SHA-224")
				return new EVP_HashFunction(EVP_sha224(), "SHA-224");
			if (request.algo_name() == "SHA-256")
				return new EVP_HashFunction(EVP_sha256(), "SHA-256");
		}
		
		version(OPENSSL_NO_SHA512) {} else {
			if (request.algo_name() == "SHA-384")
				return new EVP_HashFunction(EVP_sha384(), "SHA-384");
			if (request.algo_name() == "SHA-512")
				return new EVP_HashFunction(EVP_sha512(), "SHA-512");
		}
		
		version(OPENSSL_NO_MD2) {} else {
			if (request.algo_name() == "MD2")
				return new EVP_HashFunction(EVP_md2(), "MD2");
		}
		
		version(OPENSSL_NO_MD4) {} else {
			if (request.algo_name() == "MD4")
				return new EVP_HashFunction(EVP_md4(), "MD4");
		}
		
		version(OPENSSL_NO_MD5) {} else {
			if (request.algo_name() == "MD5")
				return new EVP_HashFunction(EVP_md5(), "MD5");
		}
		
		version(OPENSSL_NO_RIPEMD) {} else {
			if (request.algo_name() == "RIPEMD-160")
				return new EVP_HashFunction(EVP_ripemd160(), "RIPEMD-160");
		}
		
		return 0;
	}
};

package:

/*
* OpenSSL Modular Exponentiator
*/
class OpenSSL_Modular_Exponentiator : Modular_Exponentiator
{
public:
	void set_base(in BigInt b) { base = b; }
	
	void set_exponent(in BigInt e) { exp = e; }
	
	BigInt execute() const
	{
		OSSL_BN r;
		BN_mod_exp(r.ptr(), base.ptr(), exp.ptr(), mod.ptr(), ctx.ptr());
		return r.to_bigint();
	}
	
	Modular_Exponentiator copy() const
	{ 
		return new OpenSSL_Modular_Exponentiator(*this); 
	}
	
	this(in BigInt n) {
		mod = n;
	}
private:
	OSSL_BN base, exp, mod;
	OSSL_BN_CTX ctx;
};

import openssl.bn;
/**
* Lightweight OpenSSL BN wrapper. For internal use only.
*/
class OSSL_BN
{
public:
	/*
	* OpenSSL to BigInt Conversions
	*/
	BigInt to_bigint() const
	{
		SafeVector!ubyte output = SafeVector!ubyte(bytes());
		BN_bn2bin(m_bn, &output[0]);
		return BigInt.decode(output);
	}
	
	/*
	* Export the BIGNUM as a bytestring
	*/
	void encode(ubyte* output) const
	{
		size_t length = output.length;
		BN_bn2bin(m_bn, output.ptr + (length - bytes()));
	}
	
	/*
	* Return the number of significant bytes
	*/
	size_t bytes() const
	{
		return BN_num_bytes(m_bn);
	}
	
	
	SafeVector!ubyte to_bytes() const
	{ 
		return BigInt.encode_locked(to_bigint()); 
	}
	
	void opAssign(in OSSL_BN other)
	{
		BN_copy(m_bn, other.m_bn);
	}
	
	/*
	* OSSL_BN Constructor
	*/
	this(in BigInt input = 0)
	{
		m_bn = BN_new();
		SafeVector!ubyte encoding = BigInt.encode_locked(input);
		if (input != 0)
			BN_bin2bn(&encoding[0], encoding.size(), m_bn);
	}
	
	/*
	* OSSL_BN Constructor
	*/
	this(in ubyte* input, size_t length)
	{
		m_bn = BN_new();
		BN_bin2bn(input, length, m_bn);
	}
	
	/*
	* OSSL_BN Copy Constructor
	*/
	this(in OSSL_BN other)
	{
		m_bn = BN_dup(other.m_bn);
	}
	
	this(in OSSL_BN);
	
	/*
	* OSSL_BN Destructor
	*/
	~this()
	{
		BN_clear_free(m_bn);
	}
	
	
	BIGNUM* ptr() const { return m_bn; }
private:
	BIGNUM* m_bn;
};

/**
* Lightweight OpenSSL BN_CTX wrapper. For internal use only.
*/
class OSSL_BN_CTX
{
public:
	void opAssign(in OSSL_BN_CTX)
	{
		m_ctx = BN_CTX_new();
	}
	
	this()
	{
		m_ctx = BN_CTX_new();
	}
	
	this(in OSSL_BN_CTX)
	{
		m_ctx = BN_CTX_new();
	}
	
	~this()
	{
		BN_CTX_free(m_ctx);
	}
	
	BN_CTX* ptr() const { return m_ctx; }
	
private:
	BN_CTX* m_ctx;
};


package:

/**
* RC4 as implemented by OpenSSL
*/
class RC4_OpenSSL : StreamCipher
{
public:
	void clear() { clear_mem(&state, 1); }
	
	/*
	* Return the name of this type
	*/
	string name() const
	{
		if (SKIP == 0)		return "RC4";
		if (SKIP == 256) 	return "MARK-4";
		else				return "RC4_skip(" ~ std.conv.to!string(SKIP) ~ ")";
	}
	
	StreamCipher clone() const { return new RC4_OpenSSL(SKIP); }
	
	Key_Length_Specification key_spec() const
	{
		return Key_Length_Specification(1, 32);
	}		
	
	this(size_t s = 0) { SKIP = s; clear(); }
	
	~this() { clear(); }
private:
	/*
	* RC4 Encryption
	*/
	void cipher(in ubyte* input, ubyte* output, size_t length)
	{
		RC4(&state, length, input, output);
	}
	
	/*
	* RC4 Key Schedule
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		RC4_set_key(&state, length, key);
		ubyte dummy = 0;
		for (size_t i = 0; i != SKIP; ++i)
			RC4(&state, 1, &dummy, &dummy);
	}
	
	const size_t SKIP;
	RC4_KEY state;
};

/*
* EVP Block Cipher
*/
class EVP_BlockCipher : BlockCipher
{
public:
	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		const EVP_CIPHER* algo = EVP_CIPHER_CTX_cipher(&encrypt);
		
		EVP_CIPHER_CTX_cleanup(&encrypt);
		EVP_CIPHER_CTX_cleanup(&decrypt);
		EVP_CIPHER_CTX_init(&encrypt);
		EVP_CIPHER_CTX_init(&decrypt);
		EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
		EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);
		EVP_CIPHER_CTX_set_padding(&encrypt, 0);
		EVP_CIPHER_CTX_set_padding(&decrypt, 0);
	}
	
	string name() const { return cipher_name; }
	/*
	* Return a clone of this object
	*/
	BlockCipher clone() const
	{
		return new EVP_BlockCipher(EVP_CIPHER_CTX_cipher(&encrypt),
		                           cipher_name,
		                           cipher_key_spec.minimum_keylength(),
		                           cipher_key_spec.maximum_keylength(),
		                           cipher_key_spec.keylength_multiple());
	}
	
	size_t block_size() const { return block_sz; }
	/*
	* EVP Block Cipher Constructor
	*/
	this(const EVP_CIPHER* algo,
	     in string algo_name)
	{
		block_sz = EVP_CIPHER_block_size(algo);
		cipher_key_spec = EVP_CIPHER_key_length(algo);
		cipher_name = algo_name;
		if (EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
			throw new Invalid_Argument("EVP_BlockCipher: Non-ECB EVP was passed in");
		
		EVP_CIPHER_CTX_init(&encrypt);
		EVP_CIPHER_CTX_init(&decrypt);
		
		EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
		EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);
		
		EVP_CIPHER_CTX_set_padding(&encrypt, 0);
		EVP_CIPHER_CTX_set_padding(&decrypt, 0);
	}
	
	
	/*
	* EVP Block Cipher Constructor
	*/
	this(const EVP_CIPHER* algo,
	     in string algo_name,
	     size_t key_min, size_t key_max,
	     size_t key_mod) 
	{
		block_sz = EVP_CIPHER_block_size(algo);
		cipher_key_spec = Key_Length_Specification(key_min, key_max, key_mod);
		cipher_name = algo_name;
		if (EVP_CIPHER_mode(algo) != EVP_CIPH_ECB_MODE)
			throw new Invalid_Argument("EVP_BlockCipher: Non-ECB EVP was passed in");
		
		EVP_CIPHER_CTX_init(&encrypt);
		EVP_CIPHER_CTX_init(&decrypt);
		
		EVP_EncryptInit_ex(&encrypt, algo, 0, 0, 0);
		EVP_DecryptInit_ex(&decrypt, algo, 0, 0, 0);
		
		EVP_CIPHER_CTX_set_padding(&encrypt, 0);
		EVP_CIPHER_CTX_set_padding(&decrypt, 0);
	}
	
	
	Key_Length_Specification key_spec() const { return cipher_key_spec; }
	
	/*
	* EVP Block Cipher Destructor
	*/
	~this()
	{
		EVP_CIPHER_CTX_cleanup(&encrypt);
		EVP_CIPHER_CTX_cleanup(&decrypt);
	}
private:
	/*
	* Encrypt a block
	*/
	void encrypt_n(in ubyte* input, ubyte* output,
	               size_t blocks) const
	{
		int out_len = 0;
		EVP_EncryptUpdate(&encrypt, output, &out_len, input, blocks * block_sz);
	}
	
	/*
	* Decrypt a block
	*/
	void decrypt_n(in ubyte* input, ubyte* output,
	               size_t blocks) const
	{
		int out_len = 0;
		EVP_DecryptUpdate(&decrypt, output, &out_len, input, blocks * block_sz);
	}
	
	/*
	* Set the key
	*/
	void key_schedule(in ubyte* key, size_t length)
	{
		SafeVector!ubyte full_key = SafeVector!ubyte(key, key + length);
		
		if (cipher_name == "TripleDES" && length == 16)
		{
			full_key += Pair(key, 8);
		}
		else
			if (EVP_CIPHER_CTX_set_key_length(&encrypt, length) == 0 ||
			    EVP_CIPHER_CTX_set_key_length(&decrypt, length) == 0)
				throw new Invalid_Argument("EVP_BlockCipher: Bad key length for " ~
				                           cipher_name);
		
		if (cipher_name == "RC2")
		{
			EVP_CIPHER_CTX_ctrl(&encrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
			EVP_CIPHER_CTX_ctrl(&decrypt, EVP_CTRL_SET_RC2_KEY_BITS, length*8, 0);
		}
		
		EVP_EncryptInit_ex(&encrypt, 0, 0, &full_key[0], 0);
		EVP_DecryptInit_ex(&decrypt, 0, 0, &full_key[0], 0);
	}
	
	size_t block_sz;
	Key_Length_Specification cipher_key_spec;
	string cipher_name;
	EVP_CIPHER_CTX encrypt, decrypt;
};


string HANDLE_EVP_CIPHER(string NAME, alias EVP)()
{
	return `if (request.algo_name() == ` ~ NAME ~ ` && request.arg_count() == 0)
				return new EVP_BlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ NAME ~ `);`;
}


string HANDLE_EVP_CIPHER_KEYLEN(string NAME, alias EVP, ubyte MIN, ubyte MAX, ubyte MOD)() {
	return `if (request.algo_name() == ` ~ NAME ~ ` && request.arg_count() == 0)
				return new EVP_BlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ 
		NAME ~ `, ` ~ MIN.stringof ~ `, ` ~ MAX.stringof ~ `, ` ~ MOD.stringof ~ `);`;
}

/*
* EVP Hash Function
*/
class EVP_HashFunction : HashFunction
{
public:
	/*
	* Clear memory of sensitive data
	*/
	void clear()
	{
		const EVP_MD* algo = EVP_MD_CTX_md(&md);
		EVP_DigestInit_ex(&md, algo, 0);
	}
	
	string name() const { return algo_name; }
	/*
	* Return a clone of this object
	*/
	HashFunction clone() const
	{
		const EVP_MD* algo = EVP_MD_CTX_md(&md);
		return new EVP_HashFunction(algo, name());
	}
	
	size_t output_length() const
	{
		return EVP_MD_size(EVP_MD_CTX_md(&md));
	}
	
	size_t hash_block_size() const
	{
		return EVP_MD_block_size(EVP_MD_CTX_md(&md));
	}
	/*
	* Create an EVP hash function
	*/
	this(const EVP_MD* algo,
	     in string name)
	{
		algo_name = name;
		EVP_MD_CTX_init(&md);
		EVP_DigestInit_ex(&md, algo, 0);
	}
	/*
	* Destroy an EVP hash function
	*/
	~this()
	{
		EVP_MD_CTX_cleanup(&md);
	}
	
private:
	
	/*
* Update an EVP Hash Calculation
*/
	void add_data(in ubyte* input, size_t length)
	{
		EVP_DigestUpdate(&md, input, length);
	}
	/*
	* Finalize an EVP Hash Calculation
	*/
	void final_result(ubyte* output)
	{
		EVP_DigestFinal_ex(&md, output, 0);
		const EVP_MD* algo = EVP_MD_CTX_md(&md);
		EVP_DigestInit_ex(&md, algo, 0);
	}
	
	string algo_name;
	EVP_MD_CTX md;
};