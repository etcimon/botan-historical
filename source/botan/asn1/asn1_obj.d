/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.asn1_obj;
import botan.der_enc;
import botan.ber_dec;
import botan.data_src;
import botan.parsing;
/*
* BER Decoding Exceptions
*/
BER_Decoding_Error::BER_Decoding_Error(in string str) :
	Decoding_Error("BER: " + str) {}

BER_Bad_Tag::BER_Bad_Tag(in string str, ASN1_Tag tag) :
		BER_Decoding_Error(str + ": " + std::to_string(tag)) {}

BER_Bad_Tag::BER_Bad_Tag(in string str,
								 ASN1_Tag tag1, ASN1_Tag tag2) :
	BER_Decoding_Error(str + ": " + std::to_string(tag1) + "/" + std::to_string(tag2)) {}

namespace ASN1 {

/*
* Put some arbitrary bytes into a SEQUENCE
*/
Vector!byte put_in_sequence(in Vector!byte contents)
{
	return DER_Encoder()
		.start_cons(SEQUENCE)
			.raw_bytes(contents)
		.end_cons()
	.get_contents_unlocked();
}

/*
* Convert a BER object into a string object
*/
string to_string(in BER_Object obj)
{
	return string(cast(string)(obj.value[0]),
							 obj.value.size());
}

/*
* Do heuristic tests for BER data
*/
bool maybe_BER(DataSource& source)
{
	byte first_byte;
	if (!source.peek_byte(first_byte))
		throw new Stream_IO_Error("ASN1::maybe_BER: Source was empty");

	if (first_byte == (SEQUENCE | CONSTRUCTED))
		return true;
	return false;
}

}

}
