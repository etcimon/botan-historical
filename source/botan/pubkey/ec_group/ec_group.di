/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.point_gfp;
import botan.curve_gfp;
import botan.asn1.asn1_oid;
/**
* This class represents elliptic curce domain parameters
*/
enum EC_Group_Encoding {
	EC_DOMPAR_ENC_EXPLICIT = 0,
	EC_DOMPAR_ENC_IMPLICITCA = 1,
	EC_DOMPAR_ENC_OID = 2
};

/**
* Class representing an elliptic curve
*/
class EC_Group
{
	public:

		/**
		* Construct Domain paramers from specified parameters
		* @param curve elliptic curve
		* @param base_point a base point
		* @param order the order of the base point
		* @param cofactor the cofactor
		*/
		EC_Group(in CurveGFp curve,
					const PointGFp& base_point,
					ref const BigInt order,
					ref const BigInt cofactor) :
			curve(curve),
			base_point(base_point),
			order(order),
			cofactor(cofactor),
			oid("")
		{}

		/**
		* Decode a BER encoded ECC domain parameter set
		* @param ber_encoding the bytes of the BER encoding
		*/
		EC_Group(in Vector!ubyte ber_encoding);

		/**
		* Create an EC domain by OID (or throw new if unknown)
		* @param oid the OID of the EC domain to create
		*/
		EC_Group(in OID oid);

		/**
		* Create an EC domain from PEM encoding (as from PEM_encode), or
		* from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
		* @param pem_or_oid PEM-encoded data, or an OID
		*/
		EC_Group(in string pem_or_oid = "");

		/**
		* Create the DER encoding of this domain
		* @param form of encoding to use
		* @returns bytes encododed as DER
		*/
		Vector!ubyte DER_encode(EC_Group_Encoding form) const;

		/**
		* Return the PEM encoding (always in explicit form)
		* @return string containing PEM data
		*/
		string PEM_encode() const;

		/**
		* Return domain parameter curve
		* @result domain parameter curve
		*/
		const CurveGFp& get_curve() const { return curve; }

		/**
		* Return domain parameter curve
		* @result domain parameter curve
		*/
		const PointGFp& get_base_point() const { return base_point; }

		/**
		* Return the order of the base point
		* @result order of the base point
		*/
		ref const BigInt get_order() const { return order; }

		/**
		* Return the cofactor
		* @result the cofactor
		*/
		ref const BigInt get_cofactor() const { return cofactor; }

		bool initialized() const { return !base_point.is_zero(); }

		/**
		* Return the OID of these domain parameters
		* @result the OID
		*/
		string get_oid() const { return oid; }

		bool operator==(in EC_Group other) const
		{
			return ((get_curve() == other.get_curve()) &&
					  (get_base_point() == other.get_base_point()) &&
					  (get_order() == other.get_order()) &&
					  (get_cofactor() == other.get_cofactor()));
		}

		/**
		* Return PEM representation of named EC group
		*/
		static string PEM_for_named_group(in string name);

	private:
		CurveGFp curve;
		PointGFp base_point;
		BigInt order, cofactor;
		string oid;
};

 bool operator!=(in EC_Group lhs,
							  const EC_Group& rhs)
{
	return !(lhs == rhs);
}

// For compatability with 1.8
typedef EC_Group EC_Domain_Params;