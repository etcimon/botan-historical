/*
* CTR-BE Mode
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
import botan.stream_cipher;
/**
* CTR-BE (Counter mode, big-endian)
*/
class CTR_BE : public StreamCipher
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

		CTR_BE* clone() const
		{ return new CTR_BE(m_cipher->clone()); }

		void clear();

		/**
		* @param cipher the underlying block cipher to use
		*/
		CTR_BE(BlockCipher* cipher);
	private:
		void key_schedule(in byte* key, size_t length);
		void increment_counter();

		std::unique_ptr<BlockCipher> m_cipher;
		SafeVector!byte m_counter, m_pad;
		size_t m_pad_pos;
};