/*
* ECDSA Signature
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/bigint.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
/**
* Class representing an ECDSA signature
*/
class ECDSA_Signature
{
	public:
		friend class ECDSA_Signature_Decoder;

		ECDSA_Signature() {}
		ECDSA_Signature(const BigInt& r, const BigInt& s) :
			m_r(r), m_s(s) {}

		ECDSA_Signature(in Array!byte ber);

		const BigInt& get_r() const { return m_r; }
		const BigInt& get_s() const { return m_s; }

		/**
		* return the r||s
		*/
		std::vector<byte> get_concatenation() const;

		std::vector<byte> DER_encode() const;

		bool operator==(const ECDSA_Signature& other) const
		{
			return (get_r() == other.get_r() && get_s() == other.get_s());
		}

	private:
		BigInt m_r;
		BigInt m_s;
};

inline bool operator!=(const ECDSA_Signature& lhs, const ECDSA_Signature& rhs)
{
	return !(lhs == rhs);
}

ECDSA_Signature decode_concatenation(in Array!byte concatenation);