/*
* OpenSSL Engine
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.engine.openssl_engine;

import botan.constants;
static if (BOTAN_HAS_ENGINE_OPENSSL):

import botan.engine.engine;
import botan.pubkey.pk_keys;
import botan.rng.rng;
import botan.block.block_cipher;
import botan.internal.bn_wrap;
import botan.math.bigint.bigint;
import botan.utils.parsing;
import deimos.openssl.rc4;
import deimos.openssl.evp;

static if (BOTAN_HAS_RSA)  import botan.pubkey.algo.rsa;
static if (BOTAN_HAS_DSA)  import botan.pubkey.algo.dsa;
static if (BOTAN_HAS_ECDSA) {
	import botan.pubkey.algo.ecdsa;
	import openssl.ecdsa;
}
static if (BOTAN_HAS_DIFFIE_HELLMAN) import botan.pubkey.algo.dh;

/**
* OpenSSL Engine
*/
final class OpenSSL_Engine : Engine
{
public:
	string provider_name() const { return "openssl"; }

	Key_Agreement get_key_agreement_op(in Private_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_DIFFIE_HELLMAN) {
			if (const DH_PrivateKey dh = cast(const DH_PrivateKey)(key))
				return new OSSL_DH_KA_Operation(dh);
		}
		
		return 0;
	}

	Signature get_signature_op(in Private_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PrivateKey s = cast(const RSA_PrivateKey)(key))
				return new OSSL_RSA_Private_Operation(s);
		}
		
		static if (BOTAN_HAS_DSA) {
			if (const DSA_PrivateKey s = cast(const DSA_PrivateKey)(key))
				return new OSSL_DSA_Signature_Operation(s);
		}
		
		return 0;
	}

	Verification get_verify_op(in Public_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PublicKey s = cast(const RSA_PublicKey)(key))
				return new OSSL_RSA_Public_Operation(s);
		}
		
		static if (BOTAN_HAS_DSA) {
			if (const DSA_PublicKey s = cast(const DSA_PublicKey)(key))
				return new OSSL_DSA_Verification_Operation(s);
		}
		
		return 0;
	}

	Encryption get_encryption_op(in Public_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PublicKey s = cast(const RSA_PublicKey)(key))
				return new OSSL_RSA_Public_Operation(s);
		}
		
		return 0;
	}

	Decryption get_decryption_op(in Private_Key key, RandomNumberGenerator) const
	{
		static if (BOTAN_HAS_RSA) {
			if (const RSA_PrivateKey s = cast(const RSA_PrivateKey)(key))
				return new OSSL_RSA_Private_Operation(s);
		}
		
		return 0;
	}

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
			if (request.algo_name == "RC5")
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
		if (request.algo_name == "RC4")
			return new RC4_OpenSSL(request.arg_as_integer(0, 0));
		if (request.algo_name == "RC4_drop")
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
			if (request.algo_name == "SHA-160")
				return new EVP_HashFunction(EVP_sha1(), "SHA-160");
		}
		
		version(OPENSSL_NO_SHA256){} else {
			if (request.algo_name == "SHA-224")
				return new EVP_HashFunction(EVP_sha224(), "SHA-224");
			if (request.algo_name == "SHA-256")
				return new EVP_HashFunction(EVP_sha256(), "SHA-256");
		}
		
		version(OPENSSL_NO_SHA512) {} else {
			if (request.algo_name == "SHA-384")
				return new EVP_HashFunction(EVP_sha384(), "SHA-384");
			if (request.algo_name == "SHA-512")
				return new EVP_HashFunction(EVP_sha512(), "SHA-512");
		}
		
		version(OPENSSL_NO_MD2) {} else {
			if (request.algo_name == "MD2")
				return new EVP_HashFunction(EVP_md2(), "MD2");
		}
		
		version(OPENSSL_NO_MD4) {} else {
			if (request.algo_name == "MD4")
				return new EVP_HashFunction(EVP_md4(), "MD4");
		}
		
		version(OPENSSL_NO_MD5) {} else {
			if (request.algo_name == "MD5")
				return new EVP_HashFunction(EVP_md5(), "MD5");
		}
		
		version(OPENSSL_NO_RIPEMD) {} else {
			if (request.algo_name == "RIPEMD-160")
				return new EVP_HashFunction(EVP_ripemd160(), "RIPEMD-160");
		}
		
		return 0;
	}
}

package:

/*
* OpenSSL Modular Exponentiator
*/
final class OpenSSL_Modular_Exponentiator : Modular_Exponentiator
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
		return new OpenSSL_Modular_Exponentiator(this); 
	}
	
	this(in BigInt n) {
		mod = n;
	}
private:
	OSSL_BN base, exp, mod;
	OSSL_BN_CTX ctx;
}

import openssl.bn;
/**
* Lightweight OpenSSL BN wrapper. For internal use only.
*/
struct OSSL_BN
{
public:
	/*
	* OpenSSL to BigInt Conversions
	*/
	BigInt to_bigint() const
	{
		Secure_Vector!ubyte output = Secure_Vector!ubyte(bytes());
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
	
	
	Secure_Vector!ubyte to_bytes() const
	{ 
		return BigInt.encode_locked(to_bigint()); 
	}
	
	OSSL_BN opAssign(in OSSL_BN other)
	{
		BN_copy(m_bn, other.m_bn);
		return this;
	}
	
	/*
	* OSSL_BN Constructor
	*/
	this(in BigInt input = 0)
	{
		m_bn = BN_new();
		Secure_Vector!ubyte encoding = BigInt.encode_locked(input);
		if (input != 0)
			BN_bin2bn(&encoding[0], encoding.length, m_bn);
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
}

/**
* Lightweight OpenSSL BN_CTX wrapper. For internal use only.
*/
struct OSSL_BN_CTX
{
public:
	OSSL_BN_CTX opAssign(in OSSL_BN_CTX bn)
	{
		m_ctx = bn.m_ctx;
		return this;
	}
	
	this(BN_CTX* ctx = null)
	{
		if (ctx)
			m_ctx = ctx;
		else
			m_ctx = BN_CTX_new();
	}

	this(in OSSL_BN_CTX bn)
	{
		m_ctx = bn.m_ctx;
	}
	
	~this()
	{
		BN_CTX_free(m_ctx);
	}
	
	BN_CTX* ptr() const { return m_ctx; }
	
private:
	BN_CTX* m_ctx;
}


package:

/**
* RC4 as implemented by OpenSSL
*/
final class RC4_OpenSSL : StreamCipher
{
public:
	void clear() { clear_mem(&state, 1); }
	
	/*
	* Return the name of this type
	*/
	@property string name() const
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
}

/*
* EVP Block Cipher
*/
final class EVP_BlockCipher : BlockCipher
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
	
	@property string name() const { return cipher_name; }
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
	
	@property size_t block_size() const { return block_sz; }
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
		Secure_Vector!ubyte full_key = Secure_Vector!ubyte(key, key + length);
		
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
}


string HANDLE_EVP_CIPHER(string NAME, alias EVP)()
{
	return `if (request.algo_name == ` ~ NAME ~ ` && request.arg_count() == 0)
				return new EVP_BlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ NAME ~ `);`;
}


string HANDLE_EVP_CIPHER_KEYLEN(string NAME, alias EVP, ubyte MIN, ubyte MAX, ubyte MOD)() {
	return `if (request.algo_name == ` ~ NAME ~ ` && request.arg_count() == 0)
				return new EVP_BlockCipher(` ~ __traits(identifier, EVP).stringof ~ `(), ` ~ 
		NAME ~ `, ` ~ MIN.stringof ~ `, ` ~ MAX.stringof ~ `, ` ~ MOD.stringof ~ `);`;
}

/*
* EVP Hash Function
*/
final class EVP_HashFunction : HashFunction
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
	
	@property string name() const { return algo_name; }
	/*
	* Return a clone of this object
	*/
	HashFunction clone() const
	{
		const EVP_MD* algo = EVP_MD_CTX_md(&md);
		return new EVP_HashFunction(algo, name);
	}
	
	@property size_t output_length() const
	{
		return EVP_MD_size(EVP_MD_CTX_md(&md));
	}
	
	@property size_t hash_block_size() const
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
}



package:

static if (BOTAN_HAS_DIFFIE_HELLMAN) {
	final class OSSL_DH_KA_Operation : Key_Agreement
	{
	public:
		this(in DH_PrivateKey dh) 
		{
			x = dh.get_x();
			p = dh.group_p();
		}
		
		Secure_Vector!ubyte agree(in ubyte* w, size_t w_len)
		{
			OSSL_BN i = OSSL_BN(w, w_len);
			OSSL_BN r;
			BN_mod_exp(r.ptr(), i.ptr(), x.ptr(), p.ptr(), ctx.ptr());
			return r.to_bytes();
		}
		
	private:
		const OSSL_BN x, p;
		OSSL_BN_CTX ctx;
	}
}

static if (BOTAN_HAS_DSA) {
	
	final class OSSL_DSA_Signature_Operation : Signature
	{
	public:
		this(in DSA_PrivateKey dsa) 
		{
			x = dsa.get_x();
			p = dsa.group_p();
			q = dsa.group_q();
			g = dsa.group_g();
			q_bits = dsa.group_q().bits();
		}
		
		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }
		
		Secure_Vector!ubyte
			sign(in ubyte* msg, size_t msg_len,
			     RandomNumberGenerator rng)
		{
			const size_t q_bytes = (q_bits + 7) / 8;
			
			rng.add_entropy(msg, msg_len);
			
			BigInt k_bn;
			do
				k_bn.randomize(rng, q_bits);
			while(k_bn >= q.to_bigint());
			
			OSSL_BN i = OSSL_BN(msg, msg_len);
			OSSL_BN k = OSSL_BN(k_bn);
			
			OSSL_BN r;
			BN_mod_exp(r.ptr(), g.ptr(), k.ptr(), p.ptr(), ctx.ptr());
			BN_nnmod(r.ptr(), r.ptr(), q.ptr(), ctx.ptr());
			
			BN_mod_inverse(k.ptr(), k.ptr(), q.ptr(), ctx.ptr());
			
			OSSL_BN s;
			BN_mul(s.ptr(), x.ptr(), r.ptr(), ctx.ptr());
			BN_add(s.ptr(), s.ptr(), i.ptr());
			BN_mod_mul(s.ptr(), s.ptr(), k.ptr(), q.ptr(), ctx.ptr());
			
			if (BN_is_zero(r.ptr()) || BN_is_zero(s.ptr()))
				throw new Internal_Error("OpenSSL_DSA_Op::sign: r or s was zero");
			
			Secure_Vector!ubyte output = Secure_Vector!ubyte(2*q_bytes);
			r.encode(&output[0], q_bytes);
			s.encode(&output[q_bytes], q_bytes);
			return output;
		}
		
	private:
		const OSSL_BN x, p, q, g;
		const OSSL_BN_CTX ctx;
		size_t q_bits;
	}
	
	
	final class OSSL_DSA_Verification_Operation : Verification
	{
	public:
		this(in DSA_PublicKey dsa)
		{
			y = dsa.get_y();
			p = dsa.group_p();
			q = dsa.group_q();
			g = dsa.group_g();
			q_bits = dsa.group_q().bits();
		}
		
		size_t message_parts() const { return 2; }
		size_t message_part_size() const { return (q_bits + 7) / 8; }
		size_t max_input_bits() const { return q_bits; }
		
		bool with_recovery() const { return false; }
		
		bool verify(in ubyte* msg, size_t msg_len,
		            in ubyte* sig, size_t sig_len)
		{
			const size_t q_bytes = q.bytes();
			
			if (sig_len != 2*q_bytes || msg_len > q_bytes)
				return false;
			
			OSSL_BN r = OSSL_BN(sig, q_bytes);
			OSSL_BN s = OSSL_BN(sig + q_bytes, q_bytes);
			OSSL_BN i = OSSL_BN(msg, msg_len);
			
			if (BN_is_zero(r.ptr()) || BN_cmp(r.ptr(), q.ptr()) >= 0)
				return false;
			if (BN_is_zero(s.ptr()) || BN_cmp(s.ptr(), q.ptr()) >= 0)
				return false;
			
			if (BN_mod_inverse(s.ptr(), s.ptr(), q.ptr(), ctx.ptr()) == 0)
				return false;
			
			OSSL_BN si;
			BN_mod_mul(si.ptr(), s.ptr(), i.ptr(), q.ptr(), ctx.ptr());
			BN_mod_exp(si.ptr(), g.ptr(), si.ptr(), p.ptr(), ctx.ptr());
			
			OSSL_BN sr;
			BN_mod_mul(sr.ptr(), s.ptr(), r.ptr(), q.ptr(), ctx.ptr());
			BN_mod_exp(sr.ptr(), y.ptr(), sr.ptr(), p.ptr(), ctx.ptr());
			
			BN_mod_mul(si.ptr(), si.ptr(), sr.ptr(), p.ptr(), ctx.ptr());
			BN_nnmod(si.ptr(), si.ptr(), q.ptr(), ctx.ptr());
			
			if (BN_cmp(si.ptr(), r.ptr()) == 0)
				return true;
			return false;
		}
		
	private:
		const OSSL_BN y, p, q, g;
		const OSSL_BN_CTX ctx;
		size_t q_bits;
	}
	
	
	static if (BOTAN_HAS_RSA) {
		
		final class OSSL_RSA_Private_Operation : Signature, Decryption
		{
		public:
			this(in RSA_PrivateKey rsa)
			{
				mod = rsa.get_n();
				p = rsa.get_p();
				q = rsa.get_q();
				d1 = rsa.get_d1();
				d2 = rsa.get_d2();
				c = rsa.get_c();
				n_bits = rsa.get_n().bits();
			}
			
			size_t max_input_bits() const { return (n_bits - 1); }
			
			Secure_Vector!ubyte sign(in ubyte* msg, size_t msg_len,
			                      RandomNumberGenerator)
			{
				BigInt m = BigInt(msg, msg_len);
				BigInt x = private_op(m);
				return BigInt.encode_1363(x, (n_bits + 7) / 8);
			}
			
			Secure_Vector!ubyte decrypt(in ubyte* msg, size_t msg_len)
			{
				BigInt m = BigInt(msg, msg_len);
				return BigInt.encode_locked(private_op(m));
			}
			
		private:
			BigInt private_op(in BigInt m) const
			{
				OSSL_BN j1, j2, h(m);
				
				BN_mod_exp(j1.ptr(), h.ptr(), d1.ptr(), p.ptr(), ctx.ptr());
				BN_mod_exp(j2.ptr(), h.ptr(), d2.ptr(), q.ptr(), ctx.ptr());
				BN_sub(h.ptr(), j1.ptr(), j2.ptr());
				BN_mod_mul(h.ptr(), h.ptr(), c.ptr(), p.ptr(), ctx.ptr());
				BN_mul(h.ptr(), h.ptr(), q.ptr(), ctx.ptr());
				BN_add(h.ptr(), h.ptr(), j2.ptr());
				return h.to_bigint();
			}
			
			const OSSL_BN mod, p, q, d1, d2, c;
			const OSSL_BN_CTX ctx;
			size_t n_bits;
		}
		
		
		final class OSSL_RSA_Public_Operation : Verification, Encryption
		{
		public:
			this(in RSA_PublicKey rsa) 
			{
				n = rsa.get_n();
				e = rsa.get_e();
				mod = rsa.get_n();
			}
			
			size_t max_input_bits() const { return (n.bits() - 1); }
			bool with_recovery() const { return true; }
			
			Secure_Vector!ubyte encrypt(in ubyte* msg, size_t msg_len,
			                         RandomNumberGenerator)
			{
				BigInt m(msg, msg_len);
				return BigInt.encode_1363(public_op(m), n.bytes());
			}
			
			Secure_Vector!ubyte verify_mr(in ubyte* msg, size_t msg_len)
			{
				BigInt m(msg, msg_len);
				return BigInt.encode_locked(public_op(m));
			}
			
		private:
			BigInt public_op(in BigInt m) const
			{
				if (m >= n)
					throw new Invalid_Argument("RSA public op - input is too large");
				
				OSSL_BN m_bn = OSSL_BN(m), r;
				BN_mod_exp(r.ptr(), m_bn.ptr(), e.ptr(), mod.ptr(), ctx.ptr());
				return r.to_bigint();
			}
			
			const ref BigInt n;
			const OSSL_BN e, mod;
			const OSSL_BN_CTX ctx;
		}
		
	}
	
}