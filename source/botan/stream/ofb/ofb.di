/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.stream_cipher;
import botan.block_cipher;
/**
* Output Feedback Mode
*/
class OFB : StreamCipher
{
	public:
		void cipher(in ubyte* input, ubyte* output);

		void set_iv(in ubyte* iv, size_t iv_len);

		bool valid_iv_length(size_t iv_len) const
		{ return (iv_len <= m_cipher.block_size()); }

		Key_Length_Specification key_spec() const
		{
			return m_cipher.key_spec();
		}

		string name() const;

		OFB* clone() const
		{ return new OFB(m_cipher.clone()); }

		void clear();

		/**
		* @param cipher the underlying block cipher to use
		*/
		OFB(BlockCipher cipher);
	private:
		void key_schedule(in ubyte* key, size_t length);

		Unique!BlockCipher m_cipher;
		SafeVector!ubyte m_buffer;
		size_t m_buf_pos;
};