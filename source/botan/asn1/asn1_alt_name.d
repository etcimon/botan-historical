/*
* Common ASN.1 Objects
* (C) 1999-2007 Jack Lloyd
*	  2007 Yves Jerschow
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.asn1_alt_name;

import botan.asn1.asn1_obj;
import botan.asn1.asn1_str;
import botan.asn1.asn1_oid;
import botan.asn1.asn1_alt_name;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.asn1.oid_lookup.oids;
import botan.internal.stl_util;
import botan.charset;
import botan.parsing;
import botan.loadstor;
import map;

class DER_Encoder;
class BER_Decoder;
/**
* Alternative Name
*/
class AlternativeName : ASN1_Object
{
public:
	import botan.utils.mixins;
	mixin USE_STRUCT_INIT!();
	/*
	* DER encode an AlternativeName extension
	*/
	void encode_into(DER_Encoder der) const
	{
		der.start_cons(ASN1_Tag.SEQUENCE);
		
		encode_entries(der, alt_info, "RFC822", ASN1_Tag(1));
		encode_entries(der, alt_info, "DNS", ASN1_Tag(2));
		encode_entries(der, alt_info, "URI", ASN1_Tag(6));
		encode_entries(der, alt_info, "IP", ASN1_Tag(7));
		
		for (auto i = othernames.begin(); i != othernames.end(); ++i)
		{
			der.start_explicit(0)
				.encode(i.first)
					.start_explicit(0)
					.encode(i.second)
					.end_explicit()
					.end_explicit();
		}
		
		der.end_cons();
	}

	/*
	* Decode a BER encoded AlternativeName
	*/
	void decode_from(BER_Decoder source = BER_Decoder())
	{
		BER_Decoder names = source.start_cons(ASN1_Tag.SEQUENCE);
		
		while(names.more_items())
		{
			BER_Object obj = names.get_next_object();
			if ((obj.class_tag != ASN1_Tag.CONTEXT_SPECIFIC) &&
			    (obj.class_tag != (ASN1_Tag.CONTEXT_SPECIFIC | CONSTRUCTED)))
				continue;
			
			const ASN1_Tag tag = obj.type_tag;
			
			if (tag == 0)
			{
				BER_Decoder othername(obj.value);
				
				OID oid;
				othername.decode(oid);
				if (othername.more_items())
				{
					BER_Object othername_value_outer = othername.get_next_object();
					othername.verify_end();
					
					if (othername_value_outer.type_tag != ASN1_Tag(0) ||
					    othername_value_outer.class_tag !=
					    (ASN1_Tag.CONTEXT_SPECIFIC | CONSTRUCTED)
					    )
						throw new Decoding_Error("Invalid tags on otherName value");
					
					BER_Decoder othername_value_inner(othername_value_outer.value);
					
					BER_Object value = othername_value_inner.get_next_object();
					othername_value_inner.verify_end();
					
					const ASN1_Tag value_type = value.type_tag;
					
					if (is_string_type(value_type) && value.class_tag == ASN1_Tag.UNIVERSAL)
						add_othername(oid, asn1.to_string(value), value_type);
				}
			}
			else if (tag == 1 || tag == 2 || tag == 6)
			{
				const string value = Charset.transcode(asn1.to_string(obj),
				                                        LATIN1_CHARSET,
				                                        LOCAL_CHARSET);
				
				if (tag == 1) add_attribute("RFC822", value);
				if (tag == 2) add_attribute("DNS", value);
				if (tag == 6) add_attribute("URI", value);
			}
			else if (tag == 7)
			{
				if (obj.value.size() == 4)
				{
					const uint ip = load_be!uint(&obj.value[0], 0);
					add_attribute("IP", ipv4_to_string(ip));
				}
			}
			
		}
	}


	/*
	* Return all of the alternative names
	*/
	MultiMap!(string, string) contents() const
	{
		MultiMap!(string, string) names;
		
		for (auto i = alt_info.begin(); i != alt_info.end(); ++i)
			multimap_insert(names, i.first, i.second);
		
		for (auto i = othernames.begin(); i != othernames.end(); ++i)
			multimap_insert(names, oids.lookup(i.first), i.second.value());
		
		return names;
	}

	/*
	* Add an attribute to an alternative name
	*/
	void add_attribute(in string type,
	                   in string str)
	{
		if (type == "" || str == "")
			return;
		
		auto range = alt_info.equal_range(type);
		for (auto j = range.first; j != range.second; ++j)
			if (j.second == str)
				return;
		
		multimap_insert(alt_info, type, str);
	}
	
	/*
	* Get the attributes of this alternative name
	*/
	MultiMap!(string, string) get_attributes() const
	{
		return alt_info;
	}

	/*
	* Add an OtherName field
	*/
	void add_othername(in OID oid, in string value,
	                   ASN1_Tag type)
	{
		if (value == "")
			return;
		multimap_insert(othernames, oid, ASN1_String(value, type));
	}

	/*
	* Get the otherNames
	*/
	MultiMap!(OID, ASN1_String) get_othernames() const
	{
		return othernames;
	}

	/*
	* Return if this object has anything useful
	*/
	bool has_items() const
	{
		return (alt_info.size() > 0 || othernames.size() > 0);
	}

	/*
	* Create an AlternativeName
	*/
	this(in string email_addr = "",
	     in string uri = "",
	     in string dns = "",
	     in string ip = "")
	{
		add_attribute("RFC822", email_addr);
		add_attribute("DNS", dns);
		add_attribute("URI", uri);
		add_attribute("IP", ip);
	}

private:
	MultiMap!(string, string) alt_info;
	MultiMap!(OID, ASN1_String) othernames;
};



/*
* Check if type is a known ASN.1 string type
*/
bool is_string_type(ASN1_Tag tag)
{
	return (tag == ASN1_Tag.NUMERIC_STRING ||
	        tag == ASN1_Tag.PRINTABLE_STRING ||
	        tag == ASN1_Tag.VISIBLE_STRING ||
	        tag == ASN1_Tag.T61_STRING ||
	        tag == ASN1_Tag.IA5_STRING ||
	        tag == ASN1_Tag.UTF8_STRING ||
	        tag == ASN1_Tag.BMP_STRING);
}


/*
* DER encode an AlternativeName entry
*/
void encode_entries(DER_Encoder encoder = DER_Encoder(),
                    ref const MultiMap!(string, string) attr,
                    in string type, ASN1_Tag tagging)
{
	auto range = attr.equal_range(type);
	
	for (auto i = range.first; i != range.second; ++i)
	{
		if (type == "RFC822" || type == "DNS" || type == "URI")
		{
			ASN1_String asn1_string(i.second, IA5_STRING);
			encoder.add_object(tagging, ASN1_Tag.CONTEXT_SPECIFIC, asn1_string.iso_8859());
		}
		else if (type == "IP")
		{
			const uint ip = string_to_ipv4(i.second);
			ubyte[4] ip_buf;
			store_be(ip, ip_buf);
			encoder.add_object(tagging, ASN1_Tag.CONTEXT_SPECIFIC, ip_buf, 4);
		}
	}
}