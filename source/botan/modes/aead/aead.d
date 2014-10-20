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
		override bool authenticated() const { return true; }

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

		void set_associated_data_vec(Alloc)(in Vector!( ubyte, Alloc ) ad)
		{
			set_associated_data(&ad[0], ad.length);
		}

		/**
		* Default AEAD nonce size (a commonly supported value among AEAD
		* modes, and large enough that random collisions are unlikely).
		*/
		override size_t default_nonce_length() const { return 12; }

		/**
		* Return the size of the authentication tag used (in bytes)
		*/
		abstract size_t tag_size() const;
};

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
AEAD_Mode* get_aead(in string algo_spec, Cipher_Dir direction)
{
	AlgorithmFactory af = global_state().algorithm_factory();
	
	const Vector!string algo_parts = splitter(algo_spec, '/');
	if (algo_parts.empty())
		throw new Invalid_Algorithm_Name(algo_spec);
	
	if (algo_parts.length < 2)
		return null;
	
	const string cipher_name = algo_parts[0];
	const BlockCipher cipher = af.prototype_block_cipher(cipher_name);
	if (!cipher)
		return null;
	
	const Vector!string mode_info = parse_algorithm_name(algo_parts[1]);
	
	if (mode_info.empty())
		return null;
	
	const string mode_name = mode_info[0];
	
	const size_t tag_size = (mode_info.length > 1) ? to_uint(mode_info[1]) : cipher.block_size();
	
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
			const size_t L = (mode_info.length > 2) ? to_uint(mode_info[2]) : 3;
			
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
			BOTAN_ASSERT(tag_size == 16, "Valid tag size for SIV");
			if (direction == ENCRYPTION)
				return new SIV_Encryption(cipher.clone());
			else
				return new SIV_Decryption(cipher.clone());
		}
	}
	
	static if (BOTAN_HAS_AEAD_GCM)
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
