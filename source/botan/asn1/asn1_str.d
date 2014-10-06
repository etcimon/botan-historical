/*
* ASN.1 string type
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.asn1_str;

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.charset;
import botan.parsing;

class DER_Encoder;
class BER_Decoder;

/**
* Simple String
*/
class ASN1_String : ASN1_Object
{
public:
	import botan.utils.mixins;
	mixin USE_STRUCT_INIT!();

	/*
	* DER encode an ASN1_String
	*/
	void encode_into(DER_Encoder encoder = DER_Encoder()) const
	{
		string value = iso_8859();
		if (tagging() == ASN1_Tag.UTF8_STRING)
			value = Charset.transcode(value, LATIN1_CHARSET, UTF8_CHARSET);
		encoder.add_object(tagging(), ASN1_Tag.UNIVERSAL, value);
	}

	/*
	* Decode a BER encoded ASN1_String
	*/
	void decode_from(BER_Decoder source = BER_Decoder())
	{
		BER_Object obj = source.get_next_object();
		
		Character_Set charset_is;
		
		if (obj.type_tag == ASN1_Tag.BMP_STRING)
			charset_is = UCS2_CHARSET;
		else if (obj.type_tag == ASN1_Tag.UTF8_STRING)
			charset_is = UTF8_CHARSET;
		else
			charset_is = LATIN1_CHARSET;
		
		*this = ASN1_String(
			Charset.transcode(asn1.to_string(obj), charset_is, LOCAL_CHARSET),
			obj.type_tag);
	}

	/*
	* Return this string in local encoding
	*/
	string value() const
	{
		return Charset.transcode(iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
	}


	/*
	* Return this string in ISO 8859-1 encoding
	*/
	string iso_8859() const
	{
		return iso_8859_str;
	}

	/*
	* Return the type of this string object
	*/
	ASN1_Tag tagging() const
	{
		return tag;
	}

	this(in string str, ASN1_Tag t)
	{
		tag = t;
		iso_8859_str = Charset.transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		
		if (tag == ASN1_Tag.DIRECTORY_STRING)
			tag = choose_encoding(iso_8859_str, "latin1");
		
		if (tag != ASN1_Tag.NUMERIC_STRING &&
		    tag != ASN1_Tag.PRINTABLE_STRING &&
		    tag != ASN1_Tag.VISIBLE_STRING &&
		    tag != ASN1_Tag.T61_STRING &&
		    tag != ASN1_Tag.IA5_STRING &&
		    tag != ASN1_Tag.UTF8_STRING &&
		    tag != ASN1_Tag.BMP_STRING)
			throw new Invalid_Argument("ASN1_String: Unknown string type " ~
			                           std.conv.to!string(tag));
	}

	this(in string str)
	{
		iso_8859_str = Charset.transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		tag = choose_encoding(iso_8859_str, "latin1");
	}
private:
	string iso_8859_str;
	ASN1_Tag tag;
};

/*
* Choose an encoding for the string
*/
ASN1_Tag choose_encoding(in string str,
                         in string type)
{
	immutable ubyte[256] IS_PRINTABLE = [
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
		0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00 ];
	
	for (size_t i = 0; i != str.size(); ++i)
	{
		if (!IS_PRINTABLE[cast(ubyte)(str[i])])
		{
			if (type == "utf8")	return ASN1_Tag.UTF8_STRING;
			if (type == "latin1") return ASN1_Tag.T61_STRING;
			throw new Invalid_Argument("choose_encoding: Bad string type " ~ type);
		}
	}
	return ASN1_Tag.PRINTABLE_STRING;
}








