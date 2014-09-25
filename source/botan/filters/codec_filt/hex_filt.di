/*
* Hex Encoder/Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/filter.h>
/**
* Converts arbitrary binary data to hex strings, optionally with
* newlines inserted
*/
class Hex_Encoder : public Filter
{
	public:
		/**
		* Whether to use uppercase or lowercase letters for the encoded string.
		*/
		enum Case { Uppercase, Lowercase };

		string name() const { return "Hex_Encoder"; }

		void write(in byte[] input);
		void end_msg();

		/**
		* Create a hex encoder.
		* @param the_case the case to use in the encoded strings.
		*/
		Hex_Encoder(Case the_case);

		/**
		* Create a hex encoder.
		* @param newlines should newlines be used
		* @param line_length if newlines are used, how long are lines
		* @param the_case the case to use in the encoded strings
		*/
		Hex_Encoder(bool newlines = false,
						size_t line_length = 72,
						Case the_case = Uppercase);
	private:
		void encode_and_send(const byte[], size_t);

		const Case casing;
		const size_t line_length;
		std::vector<byte> in, out;
		size_t position, counter;
};

/**
* Converts hex strings to bytes
*/
class Hex_Decoder : public Filter
{
	public:
		string name() const { return "Hex_Decoder"; }

		void write(const byte[], size_t);
		void end_msg();

		/**
		* Construct a Hex Decoder using the specified
		* character checking.
		* @param checking the checking to use during decoding.
		*/
		Hex_Decoder(Decoder_Checking checking = NONE);
	private:
		const Decoder_Checking checking;
		std::vector<byte> in, out;
		size_t position;
};