/*
* PKCS #5 v2.0 PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.pbe;
import botan.block_cipher;
import botan.mac;
import botan.pipe;
import chrono;
/**
* PKCS #5 v2.0 PBE
*/
class PBE_PKCS5v20 : public PBE
{
	public:
		OID get_oid() const;

		Vector!( byte ) encode_params() const;

		string name() const;

		void write(in byte* buf, size_t buf_len);
		void start_msg();
		void end_msg();

		/**
		* Load a PKCS #5 v2.0 encrypted stream
		* @param params the PBES2 parameters
		* @param passphrase the passphrase to use for decryption
		*/
		PBE_PKCS5v20(in Vector!byte params,
						 in string passphrase);

		/**
		* @param cipher the block cipher to use
		* @param mac the MAC to use
		* @param passphrase the passphrase to use for encryption
		* @param msec how many milliseconds to run the PBKDF
		* @param rng a random number generator
		*/
		PBE_PKCS5v20(BlockCipher* cipher,
						 MessageAuthenticationCode* mac,
						 in string passphrase,
						 std::chrono::milliseconds msec,
						 RandomNumberGenerator& rng);

		~this();
	private:
		void flush_pipe(bool);

		Cipher_Dir direction;
		BlockCipher* block_cipher;
		MessageAuthenticationCode* m_prf;
		SafeVector!byte salt, key, iv;
		size_t iterations, key_length;
		Pipe pipe;
};