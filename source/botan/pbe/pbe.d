/*
* PBE
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pbe.pbe;

import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.filters.filter;
import botan.rng.rng;
import botan.utils.types;

/**
* Password Based Encryption (PBE) Filter.
*/
abstract class PBE : Filter, Filterable
{
public:
    /**
    * DER encode the params (the number of iterations and the salt value)
    * @return encoded params
    */
    abstract Vector!ubyte encodeParams() const;

    /**
    * Get this PBE's OID.
    * @return object identifier
    */
    abstract OID getOid() const;

	override void write(const(ubyte)* input, size_t len) {
		super.write(input, len);
	}

	override void setNext(Filter* filters, size_t size) {
		super.setNext(filters, size);
	}
}
