/*
* EME Base Class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.eme;
/*
* Encode a message
*/
SafeVector!ubyte EME::encode(in ubyte* msg, size_t msg_len,
										 size_t key_bits,
										 RandomNumberGenerator rng) const
{
	return pad(msg, msg_len, key_bits, rng);
}

/*
* Encode a message
*/
SafeVector!ubyte EME::encode(in SafeVector!ubyte msg,
										 size_t key_bits,
										 RandomNumberGenerator rng) const
{
	return pad(&msg[0], msg.size(), key_bits, rng);
}

/*
* Decode a message
*/
SafeVector!ubyte EME::decode(in ubyte* msg, size_t msg_len,
										 size_t key_bits) const
{
	return unpad(msg, msg_len, key_bits);
}

/*
* Decode a message
*/
SafeVector!ubyte EME::decode(in SafeVector!ubyte msg,
										 size_t key_bits) const
{
	return unpad(&msg[0], msg.size(), key_bits);
}

}
