/*
* Salsa20 / XSalsa20
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/stream_cipher.h>
/**
* DJB's Salsa20 (and XSalsa20)
*/
class Salsa20 : public StreamCipher
{
	public:
		void cipher(in byte[] input, ref byte[] output);

		void set_iv(in byte[] iv, size_t iv_len);

		bool valid_iv_length(size_t iv_len) const
		{ return (iv_len == 8 || iv_len == 24); }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(16, 32, 16);
		}

		void clear();
		string name() const;
		StreamCipher* clone() const { return new Salsa20; }
	private:
		void key_schedule(in byte[] key);

		secure_vector<u32bit> m_state;
		SafeArray!byte m_buffer;
		size_t m_position;
};