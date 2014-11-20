/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.modes.aead.aead;
import botan.modes.cipher_mode;
import botan.block.block_cipher;
import botan.libstate.libstate;

static if (BOTAN_HAS_AEAD_CCM) import botan.modes.aead.ccm;
static if (BOTAN_HAS_AEAD_EAX) import botan.modes.aead.eax;
static if (BOTAN_HAS_AEAD_GCM) import botan.modes.aead.gcm;
static if (BOTAN_HAS_AEAD_SIV) import botan.modes.aead.siv;
static if (BOTAN_HAS_AEAD_OCB) import botan.modes.aead.ocb;

/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class AEAD_Mode : Cipher_Mode
{
public:
	final override bool authenticated() const { return true; }

	/**
	* Set associated data that is not included in the ciphertext but
	* that should be authenticated. Must be called after set_key
	* and before finish.
	*
	* Unless reset by another call, the associated data is kept
	* between messages. Thus, if the AD does not change, calling
	* once (after set_key) is the optimum.
	*
	* @param ad the associated data
	* @param ad_len length of add in bytes
	*/
	abstract void set_associated_data(in ubyte* ad, size_t ad_len);

	final void set_associated_data_vec(Alloc)(in Vector!( ubyte, Alloc ) ad)
	{
		set_associated_data(ad.ptr, ad.length);
	}

	/**
	* Default AEAD nonce size (a commonly supported value among AEAD
	* modes, and large enough that random collisions are unlikely).
	*/
	final override size_t default_nonce_length() const { return 12; }

	/**
	* Return the size of the authentication tag used (in bytes)
	*/
	abstract size_t tag_size() const;
}

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
AEAD_Mode get_aead(in string algo_spec, Cipher_Dir direction)
{
	Algorithm_Factory af = global_state().algorithm_factory();
	
	const Vector!string algo_parts = splitter(algo_spec, '/');
	if (algo_parts.empty)
		throw new Invalid_Algorithm_Name(algo_spec);
	
	if (algo_parts.length < 2)
		return null;
	
	const string cipher_name = algo_parts[0];
	const BlockCipher cipher = af.prototype_block_cipher(cipher_name);
	if (!cipher)
		return null;
	
	const Vector!string mode_info = parse_algorithm_name(algo_parts[1]);
	
	if (mode_info.empty)
		return null;
	
	const string mode_name = mode_info[0];
	
	const size_t tag_size = (mode_info.length > 1) ? to!uint(mode_info[1]) : cipher.block_size;
	
	static if (BOTAN_HAS_AEAD_CCM) {
		if (mode_name == "CCM-8")
		{
			if (direction == ENCRYPTION)
				return new CCM_Encryption(cipher.clone(), 8, 3);
			else
				return new CCM_Decryption(cipher.clone(), 8, 3);
		}
		
		if (mode_name == "CCM" || mode_name == "CCM-8")
		{
			const size_t L = (mode_info.length > 2) ? to!uint(mode_info[2]) : 3;
			
			if (direction == ENCRYPTION)
				return new CCM_Encryption(cipher.clone(), tag_size, L);
			else
				return new CCM_Decryption(cipher.clone(), tag_size, L);
		}
	}
	
	static if (BOTAN_HAS_AEAD_EAX) {
		if (mode_name == "EAX")
		{
			if (direction == ENCRYPTION)
				return new EAX_Encryption(cipher.clone(), tag_size);
			else
				return new EAX_Decryption(cipher.clone(), tag_size);
		}
	}
	
	static if (BOTAN_HAS_AEAD_SIV) {
		if (mode_name == "SIV")
		{
			assert(tag_size == 16, "Valid tag size for SIV");
			if (direction == ENCRYPTION)
				return new SIV_Encryption(cipher.clone());
			else
				return new SIV_Decryption(cipher.clone());
		}
	}
	
	static if (BOTAN_HAS_AEAD_GCM) {
		if (mode_name == "GCM")
		{
			if (direction == ENCRYPTION)
				return new GCM_Encryption(cipher.clone(), tag_size);
			else
				return new GCM_Decryption(cipher.clone(), tag_size);
		}
	}

	static if (BOTAN_HAS_AEAD_OCB) {
		if (mode_name == "OCB")
		{
			if (direction == ENCRYPTION)
				return new OCB_Encryption(cipher.clone(), tag_size);
			else
				return new OCB_Decryption(cipher.clone(), tag_size);
		}
	}
	
	return null;
}

static if (BOTAN_TEST):

import botan.test;
import botan.codec.hex;
import core.atomic;
size_t g_tests_ran;

size_t aead_test(string algo, string input, string expected, string nonce_hex, string ad_hex, string key_hex)
{
	atomicOp!"+="(g_tests_ran, 1);
	const auto nonce = hex_decode_locked(nonce_hex);
	const auto ad = hex_decode_locked(ad_hex);
	const auto key = hex_decode_locked(key_hex);
	
	Unique!Cipher_Mode enc = get_aead(algo, ENCRYPTION);
	Unique!Cipher_Mode dec = get_aead(algo, DECRYPTION);
	
	if (!enc || !dec)
		throw new Exception("Unknown AEAD " ~ algo);
	
	enc.set_key(key);
	dec.set_key(key);
	
	if (auto aead_enc = cast(AEAD_Mode)(*enc))
		aead_enc.set_associated_data_vec(ad);
	if (auto aead_dec = cast(AEAD_Mode)(*dec))
		aead_dec.set_associated_data_vec(ad);
	
	size_t fail = 0;
	
	const auto pt = hex_decode_locked(input);
	const auto expected_ct = hex_decode_locked(expected);
	
	auto vec = pt;
	enc.start_vec(nonce);
	// should first update if possible
	enc.finish(vec);
	
	if (vec != expected_ct)
	{
		writeln(algo ~ " got ct " ~ hex_encode(vec) ~ " expected " ~ expected);
		writeln(algo ~ " \n");
		++fail;
	}
	
	vec = expected_ct;
	
	dec.start_vec(nonce);
	dec.finish(vec);
	
	if (vec != pt)
	{
		writeln(algo ~ " got pt " ~ hex_encode(vec) ~ " expected " ~ input);
		++fail;
	}
	
	if (enc.authenticated())
	{
		vec = expected_ct;
		vec[0] ^= 1;
		dec.start_vec(nonce);
		try
		{
			dec.finish(vec);
			writeln(algo ~ " accepted message with modified message");
			++fail;
		}
		catch {}
		
		if (nonce.length)
		{
			auto bad_nonce = nonce;
			bad_nonce[0] ^= 1;
			vec = expected_ct;
			
			dec.start_vec(bad_nonce);
			
			try
			{
				dec.finish(vec);
				writeln(algo ~ " accepted message with modified nonce");
				++fail;
			}
			catch {}
		}
		
		if (auto aead_dec = cast(AEAD_Mode)(*dec))
		{
			auto bad_ad = ad;
			
			if (ad.length)
				bad_ad[0] ^= 1;
			else
				bad_ad.push_back(0);
			
			aead_dec.set_associated_data_vec(bad_ad);
			
			vec = expected_ct;
			dec.start_vec(nonce);
			
			try
			{
				dec.finish(vec);
				writeln(algo ~ " accepted message with modified AD");
				++fail;
			}
			catch {}
		}
	}
	
	return fail;
}

unittest
{
	auto test = (string input)
	{
		File vec = File(input, "r");
		
		return run_tests_bb(vec, "AEAD", "Out", true,
		                    (string[string] m)
		                    {
			return aead_test(m["AEAD"], m["In"], m["Out"],
			m["Nonce"], m["AD"], m["Key"]);
		});
	};
	
	size_t fails = run_tests_in_dir("test_data/aead", test);

	test_report("aead", g_tests_ran, fails);
}
