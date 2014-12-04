/*
* Common ASN.1 Objects
* (C) 1999-2007 Jack Lloyd
*      2007 Yves Jerschow
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
import botan.asn1.oids;
import botan.utils.containers.multimap;
import botan.utils.charset;
import botan.utils.parsing;
import botan.utils.loadstor;
import botan.utils.types;
import botan.utils.containers.hashmap;

alias AlternativeName = FreeListRef!AlternativeNameImpl;

/**
* Alternative Name
*/
final class AlternativeNameImpl : ASN1Object
{
public:
    /*
    * DER encode an AlternativeName extension
    */
    void encodeInto(DEREncoder der) const
    {
        der.startCons(ASN1Tag.SEQUENCE);
        
        encodeEntries(der, m_alt_info, "RFC822", ASN1Tag(1));
        encodeEntries(der, m_alt_info, "DNS", ASN1Tag(2));
        encodeEntries(der, m_alt_info, "URI", ASN1Tag(6));
        encodeEntries(der, m_alt_info, "IP", ASN1Tag(7));
        
        foreach (oid, asn1_str; m_othernames)
        {
            der.startExplicit(0)
               .encode(oid)
               .startExplicit(0)
               .encode(asn1_str)
               .endExplicit()
               .endExplicit();
        }
        
        der.endCons();
    }

    /*
    * Decode a BER encoded AlternativeName
    */
    void decodeFrom(BERDecoder source)
    {
        BERDecoder names = source.startCons(ASN1Tag.SEQUENCE);
        
        while (names.moreItems())
        {
            BERObject obj = names.getNextObject();
            if ((obj.class_tag != ASN1Tag.CONTEXT_SPECIFIC) &&
                (obj.class_tag != (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED)))
                continue;
            
            const ASN1Tag tag = obj.type_tag;
            
            if (tag == 0)
            {
                auto othername = BERDecoder(obj.value);
                
                OID oid;
                othername.decode(oid);
                if (othername.moreItems())
                {
                    BERObject othername_value_outer = othername.getNextObject();
                    othername.verifyEnd();
                    
                    if (othername_value_outer.type_tag != ASN1Tag(0) ||
                        othername_value_outer.class_tag != (ASN1Tag.CONTEXT_SPECIFIC | ASN1Tag.CONSTRUCTED))
                        throw new DecodingError("Invalid tags on otherName value");
                    
                    auto othername_value_inner = BERDecoder(othername_value_outer.value);
                    
                    BERObject value = othername_value_inner.getNextObject();
                    othername_value_inner.verifyEnd();
                    
                    const ASN1Tag value_type = value.type_tag;
                    
                    if (is_string_type(value_type) && value.class_tag == ASN1Tag.UNIVERSAL)
                        add_othername(oid, value.toString(), value_type);
                }
            }
            else if (tag == 1 || tag == 2 || tag == 6)
            {
                const string value = transcode(obj.toString(),
                                               LATIN1_CHARSET,
                                               LOCAL_CHARSET);
                
                if (tag == 1) add_attribute("RFC822", value);
                if (tag == 2) add_attribute("DNS", value);
                if (tag == 6) add_attribute("URI", value);
            }
            else if (tag == 7)
            {
                if (obj.value.length == 4)
                {
                    const uint ip = loadBigEndian!uint(obj.value.ptr, 0);
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

        foreach (k, v; m_alt_info) {
            names.insert(k, v);
        }

        foreach (oid, asn1_str; m_othernames)
            names.insert(ids.lookup(key), asn1_str.value());
        
        return names;
    }

    /*
    * Add an attribute to an alternative name
    */
    void addAttribute(in string type, in string str)
    {
        if (type == "" || str == "")
            return;

        bool exists;
        m_alt_info.equalRange(type, 
                               (string val) { 
                                    if (val == str)
                                        exists = true;
                                });

        if (!exists)
            m_alt_info.insert(type, str);
    }
    
    /*
    * Get the attributes of this alternative name
    */
    MultiMap!(string, string) getAttributes() const
    {
        return m_alt_info;
    }

    /*
    * Add an OtherName field
    */
    void addOthername(in OID oid, in string value, ASN1Tag type)
    {
        if (value == "")
            return;
        m_othernames.insert(oid, ASN1String(value, type));
    }

    /*
    * Get the otherNames
    */
    MultiMap!(OID, ASN1String) getOthernames() const
    {
        return m_othernames;
    }

    /*
    * Return if this object has anything useful
    */
    bool hasItems() const
    {
        return (m_alt_info.length > 0 || m_othernames.length > 0);
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
    MultiMap!(string, string) m_alt_info;
    MultiMap!(OID, ASN1String) m_othernames;
}



/*
* Check if type is a known ASN.1 string type
*/
bool isStringType(ASN1Tag tag)
{
    return (tag == ASN1Tag.NUMERIC_STRING ||
            tag == ASN1Tag.PRINTABLE_STRING ||
            tag == ASN1Tag.VISIBLE_STRING ||
            tag == ASN1Tag.T61_STRING ||
            tag == ASN1Tag.IA5_STRING ||
            tag == ASN1Tag.UTF8_STRING ||
            tag == ASN1Tag.BMP_STRING);
}


/*
* DER encode an AlternativeName entry
*/
void encodeEntries(DEREncoder encoder = DEREncoder(),
                    in MultiMap!(string, string) attr,
                    in string type, ASN1Tag tagging)
{
    attr.equalRange(type, (string alt_name) {
    
        if (type == "RFC822" || type == "DNS" || type == "URI")
        {
            ASN1String asn1_string = ASN1String(alt_name, IA5_STRING);
            encoder.addObject(tagging, ASN1Tag.CONTEXT_SPECIFIC, asn1_string.iso8859());
        }
        else if (type == "IP")
        {
            const uint ip = string_to_ipv4(alt_name);
            ubyte[4] ip_buf;
            storeBigEndian(ip, ip_buf);
            encoder.addObject(tagging, ASN1Tag.CONTEXT_SPECIFIC, ip_buf.ptr, 4);
        }
    });
}