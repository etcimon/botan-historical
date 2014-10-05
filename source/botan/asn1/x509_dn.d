/*
* X.509 Distinguished Name
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.x509_dn;

import botan.asn1.asn1_obj;
import botan.asn1.asn1_oid;
import botan.asn1.asn1_str;
import botan.asn1.x509_dn;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.parsing;
import botan.internal.stl_util;
import botan.asn1.oid_lookup.oids;
import ostream;
import map;
import iosfwd;

/**
* Distinguished Name
*/
class X509_DN : public ASN1_Object
{
public:
	/*
	* DER encode a DistinguishedName
	*/
	void encode_into(DER_Encoder der) const
	{
		auto dn_info = get_attributes();
		
		der.start_cons(ASN1_Tag.SEQUENCE);
		
		if (!dn_bits.empty())
			der.raw_bytes(dn_bits);
		else
		{
			do_ava(der, dn_info, ASN1_Tag.PRINTABLE_STRING, "X520.Country");
			do_ava(der, dn_info, ASN1_Tag.DIRECTORY_STRING, "X520.State");
			do_ava(der, dn_info, ASN1_Tag.DIRECTORY_STRING, "X520.Locality");
			do_ava(der, dn_info, ASN1_Tag.DIRECTORY_STRING, "X520.Organization");
			do_ava(der, dn_info, ASN1_Tag.DIRECTORY_STRING, "X520.OrganizationalUnit");
			do_ava(der, dn_info, ASN1_Tag.DIRECTORY_STRING, "X520.CommonName");
			do_ava(der, dn_info, ASN1_Tag.PRINTABLE_STRING, "X520.SerialNumber");
		}
		
		der.end_cons();
	}

	/*
	* Decode a BER encoded DistinguishedName
	*/
	void decode_from(BER_Decoder source)
	{
		Vector!ubyte bits;
		
		source.start_cons(ASN1_Tag.SEQUENCE)
			.raw_bytes(bits)
				.end_cons();
		
		BER_Decoder sequence(bits);
		
		while(sequence.more_items())
		{
			BER_Decoder rdn = sequence.start_cons(ASN1_Tag.SET);
			
			while(rdn.more_items())
			{
				OID oid;
				ASN1_String str;
				
				rdn.start_cons(ASN1_Tag.SEQUENCE)
					.decode(oid)
						.decode(str)
						.verify_end()
						.end_cons();
				
				add_attribute(oid, str.value());
			}
		}
		
		dn_bits = bits;
	}

	/*
	* Get the attributes of this X509_DN
	*/
	MultiMap!(OID, string) get_attributes() const
	{
		MultiMap!(OID, string) retval;
		for (auto i = dn_info.begin(); i != dn_info.end(); ++i)
			multimap_insert(retval, i.first, i.second.value());
		return retval;
	}

	/*
	* Get a single attribute type
	*/
	Vector!string get_attribute(in string attr) const
	{
		const OID oid = oids.lookup(deref_info_field(attr));
		
		auto range = dn_info.equal_range(oid);
		
		Vector!string values;
		for (auto i = range.first; i != range.second; ++i)
			values.push_back(i.second.value());
		return values;
	}

	/*
	* Get the contents of this X.500 Name
	*/
	MultiMap!(string, string) contents() const
	{
		MultiMap!(string, string) retval;
		for (auto i = dn_info.begin(); i != dn_info.end(); ++i)
			multimap_insert(retval, oids.lookup(i.first), i.second.value());
		return retval;
	}


	/*
	* Add an attribute to a X509_DN
	*/
	void add_attribute(in string type,
	                   in string str)
	{
		OID oid = oids.lookup(type);
		add_attribute(oid, str);
	}

	/*
	* Add an attribute to a X509_DN
	*/
	void add_attribute(in OID oid, in string str)
	{
		if (str == "")
			return;
		
		auto range = dn_info.equal_range(oid);
		for (auto i = range.first; i != range.second; ++i)
			if (i.second.value() == str)
				return;
		
		multimap_insert(dn_info, oid, ASN1_String(str));
		dn_bits.clear();
	}

	/*
	* Deref aliases in a subject/issuer info request
	*/
	static string deref_info_field(in string info)
	{
		if (info == "Name" || info == "CommonName") 	return "X520.CommonName";
		if (info == "SerialNumber")					 	return "X520.SerialNumber";
		if (info == "Country")							return "X520.Country";
		if (info == "Organization")					  	return "X520.Organization";
		if (info == "Organizational Unit" || info == "OrgUnit")
			return "X520.OrganizationalUnit";
		if (info == "Locality")							return "X520.Locality";
		if (info == "State" || info == "Province")  	return "X520.State";
		if (info == "Email")							return "RFC822";
		return info;
	}

	/*
	* Return the BER encoded data, if any
	*/
	Vector!ubyte get_bits() const
	{
		return dn_bits;
	}

	/*
	* Create an empty X509_DN
	*/
	this()
	{
	}
	
	/*
	* Create an X509_DN
	*/
	this(in MultiMap!(OID, string) args)
	{
		for (auto i = args.begin(); i != args.end(); ++i)
			add_attribute(i.first, i.second);
	}
	
	/*
	* Create an X509_DN
	*/
	this(in MultiMap!(string, string) args)
	{
		for (auto i = args.begin(); i != args.end(); ++i)
			add_attribute(oids.lookup(i.first), i.second);
	}

	/*
	* Compare two X509_DNs for equality
	*/
	bool opEquals(ref const X509_DN dn2)
	{
		auto attr1 = dn1.get_attributes();
		auto attr2 = dn2.get_attributes();
		
		if (attr1.size() != attr2.size()) return false;
		
		auto p1 = attr1.begin();
		auto p2 = attr2.begin();
		
		while(true)
		{
			if (p1 == attr1.end() && p2 == attr2.end())
				break;
			if (p1 == attr1.end())		return false;
			if (p2 == attr2.end())		return false;
			if (p1.first != p2.first) return false;
			if (!x500_name_cmp(p1.second, p2.second))
				return false;
			++p1;
			++p2;
		}
		return true;
	}

	/*
	* Compare two X509_DNs for inequality
	*/
	bool opCmp(string op)(ref const X509_DN dn2)
		if (op == "!=")
	{
		return !(this == dn2);
	}

	/*
	* Induce an arbitrary ordering on DNs
	*/
	bool opBinary(string op)(ref const X509_DN dn2)
		if (op == "<")
	{
		auto attr1 = get_attributes();
		auto attr2 = dn2.get_attributes();
		
		if (attr1.size() < attr2.size()) return true;
		if (attr1.size() > attr2.size()) return false;
		
		for (auto p1 = attr1.begin(); p1 != attr1.end(); ++p1)
		{
			auto p2 = attr2.find(p1.first);
			if (p2 == attr2.end())		 return false;
			if (p1.second > p2.second) return false;
			if (p1.second < p2.second) return true;
		}
		return false;
	}


	
	X509_DN opBinary(string op, T)(ref T output)
		if (op == "<<")
	{
		MultiMap!(string, string) contents = dn.contents();

		foreach(pair; contents)
		{
			output << to_short_form(pair.first) << "=" << pair.second << ' ';
		}
		return output;
	}

private:
	MultiMap!(OID, ASN1_String) dn_info;
	Vector!ubyte dn_bits;
};

/*
* DER encode a RelativeDistinguishedName
*/
void do_ava(DER_Encoder encoder,
            ref const MultiMap!(OID, string) dn_info,
            ASN1_Tag string_type, in string oid_str,
            bool must_exist = false)
{
	const OID oid = oids.lookup(oid_str);
	const bool exists = (dn_info.find(oid) != dn_info.end());
	
	if (!exists && must_exist)
		throw new Encoding_Error("X509_DN: No entry for " ~ oid_str);
	if (!exists) return;
	
	auto range = dn_info.equal_range(oid);
	
	for (auto i = range.first; i != range.second; ++i)
	{
		encoder.start_cons(ASN1_Tag.SET)
			.start_cons(ASN1_Tag.SEQUENCE)
				.encode(oid)
				.encode(ASN1_String(i.second, string_type))
				.end_cons()
				.end_cons();
	}
}

string to_short_form(in string long_id)
{
	if (long_id == "X520.CommonName")
		return "CN";
	
	if (long_id == "X520.Organization")
		return "O";
	
	if (long_id == "X520.OrganizationalUnit")
		return "OU";
	
	return long_id;
}