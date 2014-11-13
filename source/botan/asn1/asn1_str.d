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
import botan.utils.charset;
import botan.utils.parsing;
import botan.utils.types;

alias ASN1_String = FreeListRef!ASN1_String_Impl;

/**
* Simple String
*/
final class ASN1_String_Impl : ASN1_Object
{
public:

	/*
	* DER encode an ASN1_String
	*/
	void encode_into(DER_Encoder encoder) const
	{
		string value = iso_8859();
		if (tagging() == ASN1_Tag.UTF8_STRING)
			value = transcode(value, LATIN1_CHARSET, UTF8_CHARSET);
		encoder.add_object(tagging(), ASN1_Tag.UNIVERSAL, value);
	}

	/*
	* Decode a BER encoded ASN1_String
	*/
	void decode_from(BER_Decoder source)
	{
		BER_Object obj = source.get_next_object();
		
		Character_Set charset_is;
		
		if (obj.type_tag == ASN1_Tag.BMP_STRING)
			charset_is = UCS2_CHARSET;
		else if (obj.type_tag == ASN1_Tag.UTF8_STRING)
			charset_is = UTF8_CHARSET;
		else
			charset_is = LATIN1_CHARSET;
		
		initialize(
			transcode(asn1.toString(obj), charset_is, LOCAL_CHARSET),
			obj.type_tag);
	}

	/*
	* Return this string in local encoding
	*/
	string value() const
	{
		return transcode(m_iso_8859_str, LATIN1_CHARSET, LOCAL_CHARSET);
	}


	/*
	* Return this string in ISO 8859-1 encoding
	*/
	string iso_8859() const
	{
		return m_iso_8859_str;
	}

	/*
	* Return the type of this string object
	*/
	ASN1_Tag tagging() const
	{
		return m_tag;
	}

	this(in string str, ASN1_Tag t)
	{
		initialize(str, t);
	}

	this(in string str)
	{
		m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		m_tag = choose_encoding(m_iso_8859_str, "latin1");
	}


private:
	void initialize(in string str, ASN1_Tag t) {
		m_tag = t;
		m_iso_8859_str = transcode(str, LOCAL_CHARSET, LATIN1_CHARSET);
		
		if (m_tag == ASN1_Tag.DIRECTORY_STRING)
			m_tag = choose_encoding(m_iso_8859_str, "latin1");
		
		if (m_tag != ASN1_Tag.NUMERIC_STRING &&
		    m_tag != ASN1_Tag.PRINTABLE_STRING &&
		    m_tag != ASN1_Tag.VISIBLE_STRING &&
		    m_tag != ASN1_Tag.T61_STRING &&
		    m_tag != ASN1_Tag.IA5_STRING &&
		    m_tag != ASN1_Tag.UTF8_STRING &&
		    m_tag != ASN1_Tag.BMP_STRING)
			throw new Invalid_Argument("ASN1_String: Unknown string type " ~
			                           to!string(m_tag));
	}

	string m_iso_8859_str;
	ASN1_Tag m_tag;
}

/*
* Choose an encoding for the string
*/
ASN1_Tag choose_encoding(in string str,
                         in string type)
{
	__gshared immutable bool[256] IS_PRINTABLE = [
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, true, false, false, false,
		false, false, false, false, true, true, false, true, true, true, true, true,
		true, true, true, true, true, true, true, true, true, true, true, false,
		false, true, false, true, false, true, true, true, true, true, true, true,
		true, true, true, true, true, true, true, true, true, true, true, true,
		true, true, true, true, true, true, true, false, false, false, false, false,
		false, true, true, true, true, true, true, true, true, true, true, true,
		true, true, true, true, true, true, true, true, true, true, true, true,
		true, true, true, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false, false, false, false, false, false, false, false, false,
		false, false, false, false ];
	
	foreach (immutable(char) c; str)
	{
		if (!IS_PRINTABLE[cast(size_t) c])
		{
			if (type == "utf8")	return ASN1_Tag.UTF8_STRING;
			if (type == "latin1") return ASN1_Tag.T61_STRING;
			throw new Invalid_Argument("choose_encoding: Bad string type " ~ type);
		}
	}
	return ASN1_Tag.PRINTABLE_STRING;
}
