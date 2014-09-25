/*
* The Skein-512 hash function
* (C) 2009,2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/hash.h>
#include <botan/threefish.h>
#include <string>
#include <memory>
/**
* Skein-512, a SHA-3 candidate
*/
class Skein_512 : public HashFunction
{
	public:
		/**
		* @param output_bits the output size of Skein in bits
		* @param personalization is a string that will paramaterize the
		* hash output
		*/
		Skein_512(size_t output_bits = 512,
					 in string personalization = "");

		size_t hash_block_size() const { return 64; }
		size_t output_length() const { return output_bits / 8; }

		HashFunction* clone() const;
		string name() const;
		void clear();
	private:
		enum type_code {
			SKEIN_KEY = 0,
			SKEIN_CONFIG = 4,
			SKEIN_PERSONALIZATION = 8,
			SKEIN_PUBLIC_KEY = 12,
			SKEIN_KEY_IDENTIFIER = 16,
			SKEIN_NONCE = 20,
			SKEIN_MSG = 48,
			SKEIN_OUTPUT = 63
	};

		void add_data(in byte[] input, size_t length);
		void final_result(ref byte[] output);

		void ubi_512(in byte[] msg, size_t msg_len);

		void initial_block();
		void reset_tweak(type_code type, bool final);

		string personalization;
		size_t output_bits;

		std::unique_ptr<Threefish_512> m_threefish;
		secure_vector<u64bit> T;
		SafeArray!byte buffer;
		size_t buf_pos;
};