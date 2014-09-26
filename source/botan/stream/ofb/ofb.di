/*
* OFB Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/stream_cipher.h>
#include <botan/block_cipher.h>
/**
* Output Feedback Mode
*/
class OFB : public StreamCipher
{
	public:
		void cipher(in byte* input, byte* output);

		void set_iv(in byte* iv, size_t iv_len);

		bool valid_iv_length(size_t iv_len) const
		{ return (iv_len <= m_cipher->block_size()); }

		Key_Length_Specification key_spec() const
		{
			return m_cipher->key_spec();
		}

		string name() const;

		OFB* clone() const
		{ return new OFB(m_cipher->clone()); }

		void clear();

		/**
		* @param cipher the underlying block cipher to use
		*/
		OFB(BlockCipher* cipher);
	private:
		void key_schedule(in byte* key, size_t length);

		std::unique_ptr<BlockCipher> m_cipher;
		SafeVector!byte m_buffer;
		size_t m_buf_pos;
};