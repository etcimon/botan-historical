/*
* Stream Cipher
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.stream_cipher;
void StreamCipher::set_iv(const byte[], size_t iv_len)
{
	if (iv_len)
		throw new Invalid_Argument("The stream cipher " + name() +
									  " does not support resyncronization");
}

bool StreamCipher::valid_iv_length(size_t iv_len) const
{
	return (iv_len == 0);
}

}
