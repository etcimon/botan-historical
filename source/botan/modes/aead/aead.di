/*
* Interface for AEAD modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/cipher_mode.h>
/**
* Interface for AEAD (Authenticated Encryption with Associated Data)
* modes. These modes provide both encryption and message
* authentication, and can authenticate additional per-message data
* which is not included in the ciphertext (for instance a sequence
* number).
*/
class AEAD_Mode : public Cipher_Mode
{
	public:
		bool authenticated() const override { return true; }

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
		abstract void set_associated_data(in byte* ad, size_t ad_len);

		void set_associated_data_vec(Alloc)(in Vector!( byte, Alloc ) ad)
		{
			set_associated_data(&ad[0], ad.size());
		}

		/**
		* Default AEAD nonce size (a commonly supported value among AEAD
		* modes, and large enough that random collisions are unlikely).
		*/
		size_t default_nonce_length() const override { return 12; }

		/**
		* Return the size of the authentication tag used (in bytes)
		*/
		abstract size_t tag_size() const;
};

/**
* Get an AEAD mode by name (eg "AES-128/GCM" or "Serpent/EAX")
*/
AEAD_Mode* get_aead(in string name, Cipher_Dir direction);