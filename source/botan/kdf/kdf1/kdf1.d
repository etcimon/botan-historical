/*
* KDF1
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/kdf1.h>
/*
* KDF1 Key Derivation Mechanism
*/
SafeVector!byte KDF1::derive(size_t,
										  in byte[] secret, size_t secret_len,
										  in byte[] P, size_t P_len) const
{
	hash->update(secret, secret_len);
	hash->update(P, P_len);
	return hash->flush();
}

}
