/*
* ChaCha20
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.stream.stream_cipher;
/**
* DJB's ChaCha (http://cr.yp.to/chacha.html)
*/
class ChaCha : StreamCipher
{
	public:
		void cipher(in ubyte* input, ubyte* output);

		void set_iv(in ubyte* iv, size_t iv_len);

		bool valid_iv_length(size_t iv_len) const
		{ return (iv_len == 8); }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(16, 32, 16);
		}

		void clear();
		string name() const;

		StreamCipher clone() const { return new ChaCha; }
	package:
		abstract void chacha(ubyte output[64], const uint input[16]);
	private:
		void key_schedule(in ubyte* key, size_t length);

		SafeVector!uint m_state;
		SafeVector!ubyte m_buffer;
		size_t m_position = 0;
};