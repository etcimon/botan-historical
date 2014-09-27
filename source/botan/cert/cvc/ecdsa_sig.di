/*
* ECDSA Signature
* (C) 2007 Falko Strenzke, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.bigint;
import botan.der_enc;
import botan.ber_dec;
/**
* Class representing an ECDSA signature
*/
class ECDSA_Signature
{
	public:
		friend class ECDSA_Signature_Decoder;

		ECDSA_Signature() {}
		ECDSA_Signature(in BigInt r, ref const BigInt s) :
			m_r(r), m_s(s) {}

		ECDSA_Signature(in Vector!byte ber);

		ref const BigInt get_r() const { return m_r; }
		ref const BigInt get_s() const { return m_s; }

		/**
		* return the r||s
		*/
		Vector!( byte ) get_concatenation() const;

		Vector!( byte ) DER_encode() const;

		bool operator==(in ECDSA_Signature other) const
		{
			return (get_r() == other.get_r() && get_s() == other.get_s());
		}

	private:
		BigInt m_r;
		BigInt m_s;
};

 bool operator!=(in ECDSA_Signature lhs, const ECDSA_Signature& rhs)
{
	return !(lhs == rhs);
}

ECDSA_Signature decode_concatenation(in Vector!byte concatenation);