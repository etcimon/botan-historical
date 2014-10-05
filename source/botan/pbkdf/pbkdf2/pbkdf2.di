/*
* PBKDF2
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pbkdf;
import botan.mac;
/**
* PKCS #5 PBKDF2
*/
class PKCS5_PBKDF2 : public PBKDF
{
	public:
		string name() const override
		{
			return "PBKDF2(" ~ mac.name() ~ ")";
		}

		PBKDF clone() const override
		{
			return new PKCS5_PBKDF2(mac.clone());
		}

		Pair!(size_t, OctetString)
			key_derivation(size_t output_len,
								in string passphrase,
								in byte* salt, size_t salt_len,
								size_t iterations,
								std::chrono::milliseconds msec) const override;

		/**
		* Create a PKCS #5 instance using the specified message auth code
		* @param mac_fn the MAC object to use as PRF
		*/
		PKCS5_PBKDF2(MessageAuthenticationCode mac_fn) : mac(mac_fn) {}
	private:
		Unique!MessageAuthenticationCode mac;
};