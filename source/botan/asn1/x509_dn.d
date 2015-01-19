/*
* X.509 Distinguished Name
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.x509_dn;

import botan.constants;
public import botan.asn1.asn1_obj;
public import botan.asn1.asn1_oid;
public import botan.asn1.asn1_str;
public import botan.asn1.x509_dn;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.parsing;
import botan.utils.types;
import botan.utils.containers.multimap;
import botan.asn1.oids;
import botan.utils.containers.hashmap;
import std.array : Appender;

alias X509DN = FreeListRef!X509DNImpl;

/**
* Distinguished Name
*/
final class X509DNImpl : ASN1Object
{
public:
    /*
    * DER encode a DistinguishedName
    */
    override void encodeInto(ref DEREncoder der) const
    {
        auto dn_info = getAttributes();
        
        der.startCons(ASN1Tag.SEQUENCE);
        
        if (!m_dn_bits.empty)
            der.rawBytes(m_dn_bits);
        else
        {
            doAva(der, dn_info, ASN1Tag.PRINTABLE_STRING, "X520.Country");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.State");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.Locality");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.Organization");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.OrganizationalUnit");
            doAva(der, dn_info, ASN1Tag.DIRECTORY_STRING, "X520.CommonName");
            doAva(der, dn_info, ASN1Tag.PRINTABLE_STRING, "X520.SerialNumber");
        }
        
        der.endCons();
    }

    /*
    * Decode a BER encoded DistinguishedName
    */
    override void decodeFrom(BERDecoder source)
    {
        Vector!ubyte bits;
        
        source.startCons(ASN1Tag.SEQUENCE)
            .rawBytes(bits)
                .endCons();
        
        BERDecoder sequence = BERDecoder(bits);
        
        while (sequence.moreItems())
        {
            BERDecoder rdn = sequence.startCons(ASN1Tag.SET);
            
            while (rdn.moreItems())
            {
                OID oid;
                ASN1String str = ASN1String();
                
                rdn.startCons(ASN1Tag.SEQUENCE)
                        .decode(oid)
                        .decode(str)
                        .verifyEnd()
                        .endCons();
                
                addAttribute(oid, str.value());
            }
        }
        
        m_dn_bits = bits;
    }

    /*
    * Get the attributes of this X509DN
    */
    MultiMap!(OID, string) getAttributes() const
    {
        MultiMap!(OID, string) retval;
        foreach (const ref OID oid, const ref ASN1String asn1_str; m_dn_info)
            retval.insert(oid, asn1_str.value());
        return retval;
    }

    /*
    * Get a single attribute type
    */
    Vector!string getAttribute(in string attr) const
    {
        const OID oid = OIDS.lookup(derefInfoField(attr));
        
        auto range = m_dn_info.equalRange(oid);
        
        Vector!string values;
        foreach (const ref ASN1String asn1_string; range)
            values.pushBack(asn1_string.value());
        return values;
    }

    /*
    * Get the contents of this X.500 Name
    */
    MultiMap!(string, string) contents() const
    {
        MultiMap!(string, string) retval;
        foreach (const ref OID key, const ref ASN1String value; m_dn_info)
            retval.insert(OIDS.lookup(key), value.value());
        return retval;
    }


    /*
    * Add an attribute to a X509DN
    */
    void addAttribute(in string type, in string str)
    {
        logTrace("Add X509DN Attribute Type: ", type, ", Value: ", str);
        OID oid = OIDS.lookup(type);
        addAttribute(oid, str);
    }

    /*
    * Add an attribute to a X509DN
    */
    void addAttribute(in OID oid, in string str)
    {
        if (str == "")
            return;

        logTrace("Add X509DN Attribute Type: ", OIDS.lookup(oid), ", Value: ", str);
        bool exists;
        void search_func(in ASN1String name) {
            if (name.value() == str)
                exists = true;
        }
        m_dn_info.equalRange(oid, &search_func);

        if (!exists) {
            m_dn_info.insert(oid, ASN1String(str));
            m_dn_bits.clear();
        }
    }

    /*
    * Deref aliases in a subject/issuer info request
    */
    static string derefInfoField(in string info)
    {
        if (info == "Name" || info == "CommonName")         return "X520.CommonName";
        if (info == "SerialNumber")                         return "X520.SerialNumber";
        if (info == "Country")                              return "X520.Country";
        if (info == "Organization")                         return "X520.Organization";
        if (info == "Organizational Unit" || info == "OrgUnit")
            return "X520.OrganizationalUnit";
        if (info == "Locality")                             return "X520.Locality";
        if (info == "State" || info == "Province")          return "X520.State";
        if (info == "Email")                                return "RFC822";
        return info;
    }

    /*
    * Return the BER encoded data, if any
    */
    const(Vector!ubyte) getBits() const
    {
        return m_dn_bits;
    }

    /*
    * Create an empty X509DN
    */
    this()
    {
    }
    
    /*
    * Create an X509DN
    */
    this(in MultiMap!(OID, string) args)
    {
        foreach (const ref OID oid, const ref string val; args)
            addAttribute(oid, val);
    }
    
    /*
    * Create an X509DN
    */
    this(in MultiMap!(string, string) args)
    {
        foreach (const ref string key, const ref string val; args)
            addAttribute(OIDS.lookup(key), val);
    }

    /*
    * Compare two X509DNs for equality
    */
    bool opEquals(in X509DN dn2) const
    {
        bool equals = true;

        Pair!(OID, string)[] attr1;
        Pair!(OID, string)[] attr2;

        scope(exit) {
            if (attr1) freeArray(attr1); 
            if (attr2) freeArray(attr2);
            logTrace("Equals? ", equals);
        }

        {
            MultiMap!(OID, string) map1 = getAttributes();
            MultiMap!(OID, string) map2 = dn2.getAttributes();

            attr1 = allocArray!(Pair!(OID, string))(map1.length);
            attr2 = allocArray!(Pair!(OID, string))(map2.length);

            size_t i;
            foreach (const ref OID oid, const ref string val; map1) {
                attr1[i] = makePair(oid.dup, val);
                i++;
            }
            i=0;
            foreach (const ref OID oid, const ref string val; map2) {
                attr2[i] = makePair(oid.dup, val);
                i++;
            }
        }

        if (attr1.length != attr2.length) return false;

        auto p1 = attr1.ptr;
        auto p2 = attr2.ptr;

        auto p1max = (attr1.ptr + attr1.length);
        auto p2max = (attr2.ptr + attr2.length);

        while (true)
        {
            if (p1 == p1max && p2 == p2max)
                break;
            if (p1 == p1max)  {
                equals = false;
                break;
            }
            if (p2 == p2max) {
                equals = false;
                break;
            }
            if (!p1.first && !p2.first) {
                break;
            }

            if (!p1.first || !p2.first) {
                equals = false;
                break;
            }
            if (p1.first != p2.first) {
                equals = false;
                return false;
            }

            if (!x500NameCmp(p1.second, p2.second)) {
                equals = false;
                return false;
            }
            ++p1;
            ++p2;
        }
        return equals;
    }

    /*
    * Compare two X509DNs for inequality
    */
    int opCmp(const X509DN dn2) const
    {
        if (this == dn2)
            return 0;
        else if (this.isSmallerThan(dn2))
            return -1;
        else
            return 1;
    }

    /*
    * Induce an arbitrary ordering on DNs
    */
    bool isSmallerThan(const X509DN dn2) const
    {
        const auto attr1 = getAttributes();
        const auto attr2 = dn2.getAttributes();
        
        if (attr1.length < attr2.length) return true;
        if (attr1.length > attr2.length) return false;

        foreach (const ref OID key, const ref string value; attr1) {
            const auto value2 = attr2.get(key);
            if (value2 == null) return false;
            if (value > value2) return false;
            if (value < value2) return true;
        }
        return false;
    }

    override string toString()
    {
        Appender!string output;
        MultiMap!(string, string) contents = contents();

        foreach(const ref string key, const ref string val; contents)
        {
            output ~= toShortForm(key) ~ "=" ~ val ~ ' ';
        }
        return output.data;
    }

private:
    MultiMap!(OID, ASN1String) m_dn_info;
    Vector!ubyte m_dn_bits;
}

/*
* DER encode a RelativeDistinguishedName
*/
void doAva(DEREncoder encoder,
           in MultiMap!(OID, string) dn_info,
           ASN1Tag string_type, in string oid_str,
           bool must_exist = false)
{
    const OID oid = OIDS.lookup(oid_str);
    const bool exists = (dn_info.get(oid) != null);

    if (!exists && must_exist)
        throw new EncodingError("X509DN: No entry for " ~ oid_str);
    if (!exists) return;

    dn_info.equalRange(oid, (in string val) {
                 encoder.startCons(ASN1Tag.SET)
                .startCons(ASN1Tag.SEQUENCE)
                .encode(oid)
                .encode(ASN1String(val, string_type))
                .endCons()
                .endCons();

    });
}

string toShortForm(in string long_id)
{
    if (long_id == "X520.CommonName")
        return "CN";
    
    if (long_id == "X520.Organization")
        return "O";
    
    if (long_id == "X520.OrganizationalUnit")
        return "OU";
    
    return long_id;
}