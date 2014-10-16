/*
* PBKDF2
* (C) 1999-2007,2012 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pbkdf;
import botan.mac.mac;
/**
* PKCS #5 PBKDF2
*/
class PKCS5_PBKDF2 : PBKDF
{
public:
	override string name() const
	{
		return "PBKDF2(" ~ mac.name() ~ ")";
	}

	override PBKDF clone() const
	{
		return new PKCS5_PBKDF2(mac.clone());
	}

	override Pair!(size_t, OctetString)
		key_derivation(size_t output_len,
							in string passphrase,
							in ubyte* salt, size_t salt_len,
							size_t iterations,
							 std::chrono::milliseconds msec) const;

	/**
	* Create a PKCS #5 instance using the specified message auth code
	* @param mac_fn the MAC object to use as PRF
	*/
	PKCS5_PBKDF2(MessageAuthenticationCode mac_fn) : mac(mac_fn) {}
private:
	Unique!MessageAuthenticationCode mac;
};