/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.kdf1;
/*
* KDF1 Key Derivation Mechanism
*/
SafeVector!ubyte KDF1::derive(size_t,
										  in ubyte* secret, size_t secret_len,
										  in ubyte* P, size_t P_len) const
{
	hash.update(secret, secret_len);
	hash.update(P, P_len);
	return hash.flush();
}

}
