/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.stream.stream_cipher;
/**
* DJB's Salsa20 (and XSalsa20)
*/
class Salsa20 : StreamCipher
{
	public:
		void cipher(in ubyte* input, ubyte* output);

		void set_iv(in ubyte* iv, size_t iv_len);

		bool valid_iv_length(size_t iv_len) const
		{ return (iv_len == 8 || iv_len == 24); }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(16, 32, 16);
		}

		void clear();
		string name() const;
		StreamCipher clone() const { return new Salsa20; }
	private:
		void key_schedule(in ubyte* key, size_t length);

		SafeVector!uint m_state;
		SafeVector!ubyte m_buffer;
		size_t m_position;
};