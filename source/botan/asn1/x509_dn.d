/*
* X.509 Distinguished Name
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.x509_dn;

public import botan.asn1.asn1_obj;
public import botan.asn1.asn1_oid;
public import botan.asn1.asn1_str;
public import botan.asn1.x509_dn;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.utils.types;
import botan.utils.multimap;
import botan.asn1.oid_lookup.oids;
import botan.utils.hashmap;
import std.array : Appender;

alias X509_DN = FreeListRef!X509_DN_Impl;

/**
* Distinguished Name
*/
final class X509_DN_Impl : ASN1_Object
{
public:
	/*
	* DER encode a DistinguishedName
	*/
	void encode_into(DER_Encoder der) const
	{
		auto dn_info = get_attributes();
		
		der.start_cons(ASN1_Tag.SEQUENCE);
		
		if (!m_dn_bits.empty)
			der.raw_bytes(m_dn_bits);
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
		
		while (sequence.more_items())
		{
			BER_Decoder rdn = sequence.start_cons(ASN1_Tag.SET);
			
			while (rdn.more_items())
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
		
		m_dn_bits = bits;
	}

	/*
	* Get the attributes of this X509_DN
	*/
	MultiMap!(OID, string) get_attributes() const
	{
		MultiMap!(OID, string) retval;
		foreach (oid, asn1_str; m_dn_info)
			retval.insert(oid, asn1_str.value());
		return retval;
	}

	/*
	* Get a single attribute type
	*/
	Vector!string get_attribute(in string attr) const
	{
		const OID oid = oids.lookup(deref_info_field(attr));
		
		auto range = m_dn_info.equal_range(oid);
		
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
		foreach (key, value; m_dn_info)
			retval.insert(oids.lookup(key), value.value());
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

		bool exists;
		m_dn_info.equal_range(oid, (string name) {
			if (name == str)
				exists = true;
		});

		if (!exists) {
			m_dn_info.insert(oid, ASN1_String(str));
			m_dn_bits.clear();
		}
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
		return m_dn_bits;
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
		foreach (oid, val; args)
			add_attribute(oid, val);
	}
	
	/*
	* Create an X509_DN
	*/
	this(in MultiMap!(string, string) args)
	{
		foreach (key, val; args)
			add_attribute(oids.lookup(key), val);
	}

	/*
	* Compare two X509_DNs for equality
	*/
	bool opEquals(in X509_DN dn2)
	{
		Vector!(Pair!(OID, string)) attr1;
		Vector!(Pair!(OID, string)) attr2;

		{
			MultiMap!(OID, string) map1 = get_attributes();
			MultiMap!(OID, string) map2 = dn2.get_attributes();
			foreach (oid, val; map1) {
				attr1 ~= Pair(oid, val);
			}

			foreach (oid, val; map2) {
				attr2 ~= Pair(oid, val);
			}
		}

		if (attr1.length != attr2.length) return false;

		auto p1 = attr1.ptr;
		auto p2 = attr2.ptr;

		while (true)
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
	bool opCmp(string op)(const X509_DN dn2)
		if (op == "!=")
	{
		return !(this == dn2);
	}

	/*
	* Induce an arbitrary ordering on DNs
	*/
	bool opBinary(string op)(const X509_DN dn2)
		if (op == "<")
	{
		auto attr1 = get_attributes();
		auto attr2 = dn2.get_attributes();
		
		if (attr1.length < attr2.length) return true;
		if (attr1.length > attr2.length) return false;

		foreach (key, value; attr1) {
			auto value2 = attr2.get(key);
			if (value2 == null) return false;
			if (value > value2) return false;
			if (value < value2) return true;
		}
		return false;
	}

	string toString()
	{
		Appender!string output;
		MultiMap!(string, string) contents = dn.contents();

		foreach(key, val; contents)
		{
			output ~= to_short_form(key) ~ "=" ~ val ~ ' ';
		}
		return output.data;
	}

private:
	MultiMap!(OID, ASN1_String) m_dn_info;
	Vector!ubyte m_dn_bits;
}

/*
* DER encode a RelativeDistinguishedName
*/
void do_ava(DER_Encoder encoder = DER_Encoder(),
            in MultiMap!(OID, string) dn_info,
            ASN1_Tag string_type, in string oid_str,
            bool must_exist = false)
{
	const OID oid = oids.lookup(oid_str);
	const bool exists = (dn_info.get(oid) != null);

	if (!exists && must_exist)
		throw new Encoding_Error("X509_DN: No entry for " ~ oid_str);
	if (!exists) return;

	dn_info.equal_range(oid, (string val) {
		 encoder.start_cons(ASN1_Tag.SET)
				.start_cons(ASN1_Tag.SEQUENCE)
				.encode(oid)
				.encode(ASN1_String(val, string_type))
				.end_cons()
				.end_cons();

	});
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