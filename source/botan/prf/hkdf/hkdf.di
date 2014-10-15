/*
* HKDF
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.mac;
import botan.hash.hash;
/**
* HKDF, see @rfc 5869 for details
*/
class HKDF
{
	public:
		HKDF(MessageAuthenticationCode extractor,
			  MessageAuthenticationCode prf) :
			m_extractor(extractor), m_prf(prf) {}

		HKDF(MessageAuthenticationCode prf) :
			m_extractor(prf), m_prf(m_extractor.clone()) {}

		void start_extract(in ubyte* salt, size_t salt_len);
		void extract(in ubyte* input, size_t input_len);
		void finish_extract();

		/**
		* Only call after extract
		* @param output_len must be less than 256*hashlen
		*/
		void expand(ubyte* output, size_t output_len,
						in ubyte* info, size_t info_len);

		string name() const;

		void clear();
	private:
		Unique!MessageAuthenticationCode m_extractor;
		Unique!MessageAuthenticationCode m_prf;
};