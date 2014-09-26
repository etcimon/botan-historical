/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/eme.h>
/*
* Encode a message
*/
SafeVector!byte EME::encode(in byte* msg, size_t msg_len,
										 size_t key_bits,
										 RandomNumberGenerator& rng) const
{
	return pad(msg, msg_len, key_bits, rng);
}

/*
* Encode a message
*/
SafeVector!byte EME::encode(in SafeVector!byte msg,
										 size_t key_bits,
										 RandomNumberGenerator& rng) const
{
	return pad(&msg[0], msg.size(), key_bits, rng);
}

/*
* Decode a message
*/
SafeVector!byte EME::decode(in byte* msg, size_t msg_len,
										 size_t key_bits) const
{
	return unpad(msg, msg_len, key_bits);
}

/*
* Decode a message
*/
SafeVector!byte EME::decode(in SafeVector!byte msg,
										 size_t key_bits) const
{
	return unpad(&msg[0], msg.size(), key_bits);
}

}
