/*
* ASN.1 OID
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.asn1_oid;

public import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.utils.bit_ops;
import botan.utils.parsing;

// import string;
import botan.utils.types;

alias OID = FreeListRef!OIDImpl;

/**
* This class represents ASN.1 object identifiers.
*/
final class OIDImpl : ASN1Object
{
public:

    /*
    * DER encode an OBJECT IDENTIFIER
    */
    override void decodeFrom(DEREncoderImpl der) const
    {
        if (m_id.length < 2)
            throw new InvalidArgument("encodeInto: OID is invalid");
        
        Vector!ubyte encoding;
        encoding.pushBack(40 * m_id[0] + m_id[1]);
        
        foreach (size_t i; 2 .. m_id.length)
        {
            if (m_id[i] == 0)
                encoding.pushBack(0);
            else
            {
                size_t blocks = highBit(m_id[i]) + 6;
                blocks = (blocks - (blocks % 7)) / 7;
                
                foreach (size_t j; 0 .. (blocks - 1))
                    encoding.pushBack(0x80 | ((m_id[i] >> 7*(blocks-j-1)) & 0x7F));
                encoding.pushBack(m_id[i] & 0x7F);
            }
        }
        der.addObject(ASN1Tag.OBJECT_ID, ASN1Tag.UNIVERSAL, encoding);
    }


    /*
    * Decode a BER encoded OBJECT IDENTIFIER
    */
    override void decodeFrom(BERDecoderImpl decoder)
    {
        BERObject obj = decoder.getNextObject();
        if (obj.type_tag != ASN1Tag.OBJECT_ID || obj.class_tag != ASN1Tag.UNIVERSAL)
            throw new BERBadTag("Error decoding OID, unknown tag",
                                  obj.type_tag, obj.class_tag);
        if (obj.value.length < 2)
            throw new BERDecodingError("OID encoding is too short");
        clear();
        m_id.pushBack(obj.value[0] / 40);
        m_id.pushBack(obj.value[0] % 40);
        
        size_t i = 0;
        while (i != obj.value.length - 1)
        {
            uint component = 0;
            while (i != obj.value.length - 1)
            {
                ++i;
                
                if (component >> (32-7))
                    throw new DecodingError("OID component overflow");
                
                component = (component << 7) + (obj.value[i] & 0x7F);
                
                if (!(obj.value[i] & 0x80))
                    break;
            }
            m_id.pushBack(component);
        }
    }


    /**
    * Find out whether this OID is empty
    * @return true is no OID value is set
    */
    @property bool empty() const { return m_id.length == 0; }

    /**
    * Get this OID as list (vector) of its components.
    * @return vector representing this OID
    */
    Vector!uint getId() const { return m_id; }

    /**
    * Get this OID as a string
    * @return string representing this OID
    */
    override string toString() const
    {
        Appender!string oid_str;
        foreach (size_t i; 0 .. m_id.length)
        {
            oid_str ~= to!string(m_id[i]);
            if (i != m_id.length - 1)
                oid_str ~= '.';
        }
        return oid_str.data;
    }

    /**
    * Compare two OIDs.
    * @return true if they are equal, false otherwise
    */
    bool opEquals(in OID oid) const
    {
        if (m_id.length != oid.m_id.length)
            return false;
        foreach (size_t i; 0 .. m_id.length)
            if (m_id[i] != oid.m_id[i])
                return false;
        return true;
    }

    /**
    * Reset this instance to an empty OID.
    */
    void clear()
    {
        m_id.clear();
    }

    /**
    * Append another component onto the OID.
    * @param oid = the OID to add the new component to
    * @param new_comp = the new component to add
    */
    OID opBinary(string op)(in OID oid, uint component)
        if (op == "+")
    {
        OID new_oid = OID(oid);
        new_oid ~= component;
        return new_oid;
    }
    
    /**
    * Compare two OIDs.
    * @param a = the first OID
    * @param b = the second OID
    * @return true if a is not equal to b
    */
    bool opCmp(in OID b)
    {
        return !(this == b);
    }
    
    /**
    * Compare two OIDs.
    * @param a = the first OID
    * @param b = the second OID
    * @return true if a is lexicographically smaller than b
    */
    bool opBinary(string op)(in OID b)
        if (op == "<")
    {
        const Vector!uint oid1 = getId();
        const Vector!uint oid2 = b.getId();
        
        if (oid1.length < oid2.length)
            return true;
        if (oid1.length > oid2.length)
            return false;
        foreach (const i, const oid; oid1[])
        {
            if (oid < oid2[i])
                return true;
            if (oid > oid2[i])
                return false;
        }
        return false;
    }


    /**
    * Add a component to this OID.
    * @param new_comp = the new component to add to the end of this OID
    * @return reference to this
    */
    ref OID opOpAssign(string op)(uint new_comp)
        if (op == "~=") 
    {
        m_id.pushBack(new_comp);
        return this;
    }

    /**
    * Construct an OID from a string.
    * @param str = a string in the form "a.b.c" etc., where a,b,c are numbers
    */
    this(in string str = "")
    {
        if (oid_str == "")
            return;

        try
        {
            m_id = parseAsn1Oid(oid_str);
        }
        catch (Throwable)
        {
            throw new InvalidOID(oid_str);
        }
        
        if (m_id.length < 2 || m_id[0] > 2)
            throw new InvalidOID(oid_str);
        if ((m_id[0] == 0 || m_id[0] == 1) && m_id[1] > 39)
            throw new InvalidOID(oid_str);

    }
private:
    Vector!uint m_id;
}