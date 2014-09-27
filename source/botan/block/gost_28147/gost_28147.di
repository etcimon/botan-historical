/*
* GOST 28147-89
* (C) 1999-2009 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.block_cipher;
/**
* The GOST 28147-89 block cipher uses a set of 4 bit Sboxes, however
* the standard does not actually define these Sboxes; they are
* considered a local configuration issue. Several different sets are
* used.
*/
class GOST_28147_89_Params
{
	public:
		/**
		* @param row the row
		* @param col the column
		* @return sbox entry at this row/column
		*/
		byte sbox_entry(size_t row, size_t col) const;

		/**
		* @return name of this parameter set
		*/
		string param_name() const { return name; }

		/**
		* Default GOST parameters are the ones given in GOST R 34.11 for
		* testing purposes; these sboxes are also used by Crypto++, and,
		* at least according to Wikipedia, the Central Bank of Russian
		* Federation
		* @param name of the parameter set
		*/
		GOST_28147_89_Params(in string name = "R3411_94_TestParam");
	private:
		const byte* sboxes;
		string name;
};

/**
* GOST 28147-89
*/
class GOST_28147_89 : public Block_Cipher_Fixed_Params<8, 32>
{
	public:
		void encrypt_n(byte* input, byte* output, size_t blocks) const;
		void decrypt_n(byte* input, byte* output, size_t blocks) const;

		void clear();

		string name() const;
		BlockCipher* clone() const { return new GOST_28147_89(SBOX); }

		/**
		* @param params the sbox parameters to use
		*/
		GOST_28147_89(in GOST_28147_89_Params params);
	private:
		GOST_28147_89(in Vector!( uint ) other_SBOX) :
			SBOX(other_SBOX), EK(8) {}

		void key_schedule(in byte*, size_t);

		/*
		* The sbox is not secret, this is just a larger expansion of it
		* which we generate at runtime for faster execution
		*/
		Vector!( uint ) SBOX;

		secure_vector!uint EK;
};