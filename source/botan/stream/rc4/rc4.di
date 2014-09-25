/*
* RC4
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/stream_cipher.h>
#include <botan/types.h>
/**
* RC4 stream cipher
*/
class RC4 : public StreamCipher
{
	public:
		void cipher(in byte[] input, ref byte[] output);

		void clear();
		string name() const;

		StreamCipher* clone() const { return new RC4(SKIP); }

		Key_Length_Specification key_spec() const
		{
			return Key_Length_Specification(1, 256);
		}

		/**
		* @param skip skip this many initial bytes in the keystream
		*/
		RC4(size_t skip = 0);

		~RC4() { clear(); }
	private:
		void key_schedule(const byte[], size_t);
		void generate();

		const size_t SKIP;

		byte X, Y;
		SafeArray!byte state;

		SafeArray!byte buffer;
		size_t position;
};