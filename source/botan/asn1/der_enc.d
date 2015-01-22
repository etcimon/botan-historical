/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.der_enc;

import botan.constants;
static if (BOTAN_HAS_PUBLIC_KEY_CRYPTO):

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.math.bigint.bigint;
import botan.utils.get_byte;
import botan.utils.parsing;
import botan.utils.bit_ops;
import botan.utils.types;
import std.algorithm;

import botan.utils.types;


/**
* General DER Encoding Object
*/
struct DEREncoder
{
public:
    Array!ubyte getContentsUnlocked()
    {
        logTrace("DEREncoder.getContentsUnlocked");
        return unlock(getContents()); 
    }

    /*
    * Return the encoded m_contents
    */
    SecureArray!ubyte getContents()
    {
        if (m_subsequences.length != 0)
            throw new InvalidState("DEREncoder: Sequence hasn't been marked done");
        
        SecureArray!ubyte output;
        std.algorithm.swap(output, m_contents);
        return output;
    }
    
    /*
    * Start a new ASN.1 ASN1Tag.SEQUENCE/SET/EXPLICIT
    */
    ref DEREncoder startCons(ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.UNIVERSAL)
    {
        m_subsequences.pushBack(DERSequence(m_type_tag, m_class_tag));
        return this;
    }
    
    /*
    * Finish the current ASN.1 ASN1Tag.SEQUENCE/SET/EXPLICIT
    */
    ref DEREncoder endCons()
    {
        if (m_subsequences.empty)
            throw new InvalidState("endCons: No such sequence");
        
        SecureArray!ubyte seq = m_subsequences[m_subsequences.length-1].getContents();
        m_subsequences.popBack();
        rawBytes(seq);
        return this;
    }
    
    /*
    * Start a new ASN.1 EXPLICIT encoding
    */
    ref DEREncoder startExplicit(ushort type_no)
    {
        ASN1Tag m_type_tag = cast(ASN1Tag)(type_no);
        
        if (m_type_tag == ASN1Tag.SET)
            throw new InternalError("DEREncoder.startExplicit(SET); cannot perform");
        
        return startCons(m_type_tag, ASN1Tag.CONTEXT_SPECIFIC);
    }
    
    /*
    * Finish the current ASN.1 EXPLICIT encoding
    */
    ref DEREncoder endExplicit()
    {
        return endCons();
    }
    
    /*
    * Write raw bytes into the stream
    */
	ref DEREncoder rawBytes(int ALLOC)(auto const ref Vector!(ubyte, ALLOC) val)
	{
		return rawBytes(val.ptr, val.length);
	}

	ref DEREncoder rawBytes(int ALLOC)(auto const ref FreeListRef!(Vector!(ubyte, ALLOC)) val)
	{
		return rawBytes(val.ptr, val.length);
	}
       
    /*
    * Write raw bytes into the stream
    */
    ref DEREncoder rawBytes(const(ubyte)* bytes, size_t length)
    {
        if (m_subsequences.length)
            m_subsequences[m_subsequences.length-1].addBytes(bytes, length);
        else
            m_contents ~= bytes[0 .. length];
        
        return this;
    }
    
    /*
    * Encode a NULL object
    */
    ref DEREncoder encodeNull()
    {
        return addObject(ASN1Tag.NULL_TAG, ASN1Tag.UNIVERSAL, null, 0);
    }
    
    /*
    * DER encode a BOOLEAN
    */
    ref DEREncoder encode(bool is_true)
    {
        return encode(is_true, ASN1Tag.BOOLEAN, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * DER encode a small INTEGER
    */
    ref DEREncoder encode(size_t n)
    {
        return encode(BigInt(n), ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * DER encode a small INTEGER
    */
    ref DEREncoder encode()(auto ref BigInt n)
    {
        return encode(n, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * DER encode an OCTET STRING or BIT STRING
    */
    ref DEREncoder encode(const ref SecureVector!ubyte bytes, ASN1Tag real_type)
    {
        return encode(bytes.ptr, bytes.length, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * DER encode an OCTET STRING or BIT STRING
    */
    ref DEREncoder encode(const ref Vector!ubyte bytes, ASN1Tag real_type)
    {
        return encode(bytes.ptr, bytes.length, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * Encode this object
    */
    ref DEREncoder encode(const(ubyte)* bytes, size_t length, ASN1Tag real_type)
    {
        return encode(bytes, length, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * DER encode a BOOLEAN
    */
    ref DEREncoder encode(bool is_true, ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        ubyte val = is_true ? 0xFF : 0x00;
        return addObject(m_type_tag, m_class_tag, &val, 1);
    }
    
    /*
    * DER encode a small INTEGER
    */
    ref DEREncoder encode(size_t n, ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        return encode(BigInt(n), m_type_tag, m_class_tag);
    }
    
    /*
    * DER encode an INTEGER
    */
    ref DEREncoder encode()(auto ref BigInt n, ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        if (n == 0)
            return addObject(m_type_tag, m_class_tag, 0);
        
        bool extra_zero = (n.bits() % 8 == 0);
        SecureVector!ubyte m_contents = SecureVector!ubyte(extra_zero + n.bytes());
        BigInt.encode(&m_contents[extra_zero], n);
        if (n < 0)
        {
            foreach (size_t i; 0 .. m_contents.length)
                m_contents[i] = ~m_contents[i];
            for (size_t i = m_contents.length; i > 0; --i)
                if (++m_contents[i-1])
                    break;
        }
        
        return addObject(m_type_tag, m_class_tag, m_contents);
    }
    
    /*
    * DER encode an OCTET STRING or BIT STRING
    */
    ref DEREncoder encode(int ALLOC)(auto const ref FreeListRef!(Vector!(ubyte, ALLOC)) bytes,
                          			 ASN1Tag real_type,
                         			 ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        return encode(bytes.ptr, bytes.length, real_type, m_type_tag, m_class_tag);
    }
    
    /*
    * DER encode an OCTET STRING or BIT STRING
    */
    ref DEREncoder encode(int ALLOC)(auto const ref Vector!(ubyte, ALLOC) bytes,
                         			 ASN1Tag real_type,
                         			 ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        return encode(bytes.ptr, bytes.length, real_type, m_type_tag, m_class_tag);
    }
    
    /*
    * DER encode an OCTET STRING or BIT STRING
    */
    ref DEREncoder encode(const(ubyte)* bytes, size_t length,
                          ASN1Tag real_type,
                          ASN1Tag m_type_tag, ASN1Tag m_class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        if (real_type != ASN1Tag.OCTET_STRING && real_type != ASN1Tag.BIT_STRING)
            throw new InvalidArgument("DEREncoder: Invalid tag for ubyte/bit string");
        
        if (real_type == ASN1Tag.BIT_STRING)
        {
            SecureVector!ubyte encoded;
            encoded.pushBack(0);
            encoded ~= bytes[0 .. length];
            return addObject(m_type_tag, m_class_tag, encoded);
        }
        else
            return addObject(m_type_tag, m_class_tag, bytes, length);
    }

    /*
    * Request for an object to encode itself
    */
    ref DEREncoder encode(in ASN1Object obj)
    {
        obj.encodeInto(this);
        return this;
    }

    /*
    * Conditionally write some values to the stream
    */
    ref DEREncoder encodeIf (bool cond, DEREncoder codec)
    {
        if (cond)
            return rawBytes(codec.getContents());
        return this;
    }
    
    ref DEREncoder encodeIf (bool cond, in ASN1Object obj)
    {
        if (cond)
            encode(obj);
        return this;
    }

    ref DEREncoder encodeOptional(T)(in T value, in T default_value = T.init)
    {
        if (value != default_value)
            encode(value);
        return this;
    }

    ref DEREncoder encodeList(T, int Alloc)(const ref Vector!(T, Alloc) values)
    {
        foreach (const value; values[])
            encode(value);
        return this;
    }

    /*
    * Write the encoding of the ubyte(s)
    */
    ref DEREncoder addObject(ASN1Tag m_type_tag, ASN1Tag m_class_tag, in string rep_str)
    {
        const(ubyte)* rep = cast(const(ubyte)*)(rep_str.ptr);
        const size_t rep_len = rep_str.length;
        return addObject(m_type_tag, m_class_tag, rep, rep_len);
    }

    /*
    * Write the encoding of the ubyte(s)
    */
    ref DEREncoder addObject(ASN1Tag m_type_tag, ASN1Tag m_class_tag, const(ubyte)* rep, size_t length)
    {
        SecureVector!ubyte buffer;
        buffer ~= encodeTag(m_type_tag, m_class_tag);
        buffer ~= encodeLength(length);
        buffer ~= rep[0 .. length];
        
        return rawBytes(buffer);
    }

    /*
    * Write the encoding of the ubyte
    */
    ref DEREncoder addObject(ASN1Tag m_type_tag, ASN1Tag m_class_tag, ubyte rep)
    {
        return addObject(m_type_tag, m_class_tag, &rep, 1);
    }


    ref DEREncoder addObject(int ALLOC)(ASN1Tag m_type_tag, ASN1Tag m_class_tag, 
										auto const ref FreeListRef!(Vector!(ubyte, ALLOC)) rep)
    {
        return addObject(m_type_tag, m_class_tag, rep.ptr, rep.length);
    }

    ref DEREncoder addObject(int ALLOC)(ASN1Tag m_type_tag, ASN1Tag m_class_tag, 
										auto const ref Vector!(ubyte, ALLOC) rep)
    {
        return addObject(m_type_tag, m_class_tag, rep.ptr, rep.length);
    }
private:
    alias DERSequence = FreeListRef!DERSequenceImpl;
    class DERSequenceImpl
    {
    public:
        /*
        * Return the type and class taggings
        */
        const(ASN1Tag) tagOf() const
        {
            return m_type_tag | m_class_tag;
        }

        /*
        * Return the encoded ASN1Tag.SEQUENCE/SET
        */
        SecureArray!ubyte getContents()
        {
            const ASN1Tag real_class_tag = m_class_tag | ASN1Tag.CONSTRUCTED;
            
            if (m_type_tag == ASN1Tag.SET)
            {    // sort?
                auto set_contents = m_set_contents[];
                sort!("a < b", SwapStrategy.stable)(set_contents);
                foreach (SecureArray!ubyte data; set_contents)
                    m_contents ~= data;
                m_set_contents.clear();
            }
            
            SecureArray!ubyte result;
            result ~= encodeTag(m_type_tag, real_class_tag);
            result ~= encodeLength(m_contents.length);
            result ~= m_contents;
            m_contents.clear();
            
            return result;
        }

        /*
        * Add an encoded value to the ASN1Tag.SEQUENCE/SET
        */
        void addBytes(const(ubyte)* data, size_t length)
        {
            if (m_type_tag == ASN1Tag.SET)
                m_set_contents.pushBack(SecureArray!ubyte(data[0 .. length]));
            else
                m_contents ~= data[0 .. length];
        }

        /*
        * DERSequence Constructor
        */
        this(ASN1Tag t1, ASN1Tag t2)
        {
            m_type_tag = t1;
            m_class_tag = t2;
        }

    private:

        ASN1Tag m_type_tag;
        ASN1Tag m_class_tag;
        SecureArray!ubyte m_contents;
        Array!( SecureArray!ubyte ) m_set_contents;
    }

    SecureArray!ubyte m_contents;
    Array!DERSequence m_subsequences;
}

/*
* DER encode an ASN.1 type tag
*/
SecureArray!ubyte encodeTag(ASN1Tag m_type_tag, ASN1Tag m_class_tag)
{
    if ((m_class_tag | 0xE0) != 0xE0)
        throw new EncodingError("DEREncoder: Invalid class tag " ~
                                 to!string(m_class_tag));

	SecureArray!ubyte encoded_tag;
    if (m_type_tag <= 30)
        encoded_tag.pushBack(cast(ubyte)(m_type_tag | m_class_tag));
    else
    {
        size_t blocks = highBit(m_type_tag) + 6;
        blocks = (blocks - (blocks % 7)) / 7;
        
        encoded_tag.pushBack(m_class_tag | 0x1F);
        foreach (size_t i; 0 .. (blocks - 1))
            encoded_tag.pushBack(0x80 | ((m_type_tag >> 7*(blocks-i-1)) & 0x7F));
        encoded_tag.pushBack(m_type_tag & 0x7F);
    }
    
    return encoded_tag;
}

/*
* DER encode an ASN.1 length field
*/
SecureArray!ubyte encodeLength(size_t length)
{
	SecureArray!ubyte encoded_length;
    if (length <= 127)
        encoded_length.pushBack(cast(ubyte)(length));
    else
    {
        const size_t top_byte = significantBytes(length);
        
        encoded_length.pushBack(cast(ubyte)(0x80 | top_byte));
        
        for (size_t i = (length).sizeof - top_byte; i != (length).sizeof; ++i)
            encoded_length.pushBack(get_byte(i, length));
    }
    return encoded_length;
}