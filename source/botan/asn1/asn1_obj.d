/*
* ASN.1 Internals
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

module botan.asn1.asn1_obj;

public import botan.asn1.der_enc;
public import botan.asn1.ber_dec;
public import botan.asn1.alg_id;
public import botan.filters.data_src;
import botan.utils.parsing;
import botan.utils.memory.zeroize;
import botan.utils.exceptn;
import std.conv : to;

/**
* ASN.1 Type and Class Tags
*/
enum ASN1_Tag {
	UNIVERSAL			= 0x00,
	APPLICATION			= 0x40,
	CONTEXT_SPECIFIC	= 0x80,
	
	CONSTRUCTED			= 0x20,

	PRIVATE				= ASN1_Tag.CONSTRUCTED | ASN1_Tag.CONTEXT_SPECIFIC,

	EOC					= 0x00,
	BOOLEAN				= 0x01,
	INTEGER				= 0x02,
	BIT_STRING			= 0x03,
	OCTET_STRING		= 0x04,
	NULL_TAG			= 0x05,
	OBJECT_ID			= 0x06,
	ENUMERATED			= 0x0A,
	SEQUENCE			= 0x10,
	SET					= 0x11,

	UTF8_STRING			= 0x0C,
	NUMERIC_STRING		= 0x12,
	PRINTABLE_STRING	= 0x13,
	T61_STRING			= 0x14,
	IA5_STRING			= 0x16,
	VISIBLE_STRING		= 0x1A,
	BMP_STRING			= 0x1E,

	UTC_TIME			= 0x17,
	GENERALIZED_TIME	= 0x18,

	NO_OBJECT			= 0xFF00,
	DIRECTORY_STRING	= 0xFF01
}

/**
* Basic ASN.1 Object Interface
*/
class ASN1_Object
{

public:
	/**
	* Encode whatever this object is into to
	* @param to the DER_Encoder that will be written to
	*/
	abstract void encode_into(DER_Encoder to) const;

	/**
	* Decode whatever this object is from from
	* @param from the BER_Decoder that will be read from
	*/
	abstract void decode_from(BER_Decoder from);

	~this() {}
}

/**
* BER Encoded Object
*/
struct BER_Object
{
public:
	/*
	* Check a type invariant on BER data
	*/
	void assert_is_a(ASN1_Tag type_tag, ASN1_Tag class_tag)
	{
		if (this.type_tag != type_tag || this.class_tag != class_tag)
			throw new BER_Decoding_Error("Tag mismatch when decoding got " ~
			                             to!string(this.type_tag) ~ "/" ~
			                             to!string(this.class_tag) ~ " expected " ~
			                             to!string(type_tag) ~ "/" ~
			                             to!string(class_tag));
	}

	/*
	* Convert a BER object into a string object
	*/
	string toString()
	{
		return value[];
	}

	ASN1_Tag type_tag, class_tag;
	Secure_Vector!ubyte value;
}

/**
* General BER Decoding Error Exception
*/
class BER_Decoding_Error : Decoding_Error
{
	this(in string str) {
		super("BER: " ~ str);
	}
}

/**
* Exception For Incorrect BER Taggings
*/
class BER_Bad_Tag : BER_Decoding_Error
{

	/*
	* BER Decoding Exceptions
	*/
	this(in string str, ASN1_Tag tag) {
		super(str ~ ": " ~ to!string(tag));
	}

	/*
	* BER Decoding Exceptions
	*/
	this(in string str, ASN1_Tag tag1, ASN1_Tag tag2) {
		super(str ~ ": " ~ to!string(tag1) ~ "/" ~ to!string(tag2));
	}
}
	
/*
* Put some arbitrary bytes into a ASN1_Tag.SEQUENCE
*/
Vector!ubyte put_in_sequence(in Vector!ubyte contents)
{
	return DER_Encoder()
		.start_cons(ASN1_Tag.SEQUENCE)
			.raw_bytes(contents)
			.end_cons()
			.get_contents_unlocked();
}

/**
* Heuristics tests; is this object possibly BER?
* @param src a data source that will be peeked at but not modified
*/
bool maybe_BER(DataSource source)
{
	ubyte first_byte;
	if (!source.peek_byte(first_byte))
		throw new Stream_IO_Error("asn1_obj.maybe_BER: Source was empty");
	
	if (first_byte == (ASN1_Tag.SEQUENCE | ASN1_Tag.CONSTRUCTED))
		return true;
	return false;
}