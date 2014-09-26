/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_obj.h>
#include <string>
#include <vector>
/**
* This class represents ASN.1 object identifiers.
*/
class OID : public ASN1_Object
{
	public:
		void encode_into(class DER_Encoder) const;
		void decode_from(class BER_Decoder);

		/**
		* Find out whether this OID is empty
		* @return true is no OID value is set
		*/
		bool empty() const { return id.size() == 0; }

		/**
		* Get this OID as list (vector) of its components.
		* @return vector representing this OID
		*/
		const Vector!( uint )& get_id() const { return id; }

		/**
		* Get this OID as a string
		* @return string representing this OID
		*/
		string as_string() const;

		/**
		* Compare two OIDs.
		* @return true if they are equal, false otherwise
		*/
		bool operator==(in OID) const;

		/**
		* Reset this instance to an empty OID.
		*/
		void clear();

		/**
		* Add a component to this OID.
		* @param new_comp the new component to add to the end of this OID
		* @return reference to *this
		*/
		OID& operator+=(uint new_comp);

		/**
		* Construct an OID from a string.
		* @param str a string in the form "a.b.c" etc., where a,b,c are numbers
		*/
		OID(in string str = "");
	private:
		Vector!( uint ) id;
};

/**
* Append another component onto the OID.
* @param oid the OID to add the new component to
* @param new_comp the new component to add
*/
OID operator+(in OID oid, uint new_comp);

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is not equal to b
*/
bool operator!=(in OID a, const OID& b);

/**
* Compare two OIDs.
* @param a the first OID
* @param b the second OID
* @return true if a is lexicographically smaller than b
*/
bool operator<(in OID a, const OID& b);