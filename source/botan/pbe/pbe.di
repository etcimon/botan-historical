/*
* PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.filters.filter;
import botan.rng;
/**
* Password Based Encryption (PBE) Filter.
*/
class PBE : Filter
{
	public:
		/**
		* DER encode the params (the number of iterations and the salt value)
		* @return encoded params
		*/
		abstract Vector!ubyte encode_params() const;

		/**
		* Get this PBE's OID.
		* @return object identifier
		*/
		abstract OID get_oid() const;
};