/*
* BER Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.ber_dec;

public import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.math.bigint.bigint;
import botan.utils.get_byte;
import botan.utils.types;
import botan.utils.memory.memory;

public:
/**
* BER Decoding Object
*/
struct BERDecoder
{
public:

    /*
    * Return the BER encoding of the next object
    */
    BERObject getNextObject()
    {
        BERObject next;
        
        if (m_pushed.type_tag != ASN1Tag.NO_OBJECT)
        {
            next = m_pushed;
            m_pushed.class_tag = m_pushed.type_tag = ASN1Tag.NO_OBJECT;
            return next;
        }
        
        decodeTag(*m_source, next.type_tag, next.class_tag);
        if (next.type_tag == ASN1Tag.NO_OBJECT)
            return next;
        
        size_t length = decodeLength(*m_source);
        next.value.resize(length);
        if (m_source.read(&next.value[0], length) != length)
            throw new BERDecodingError("Value truncated");
        
        if (next.type_tag == ASN1Tag.EOC && next.class_tag == ASN1Tag.UNIVERSAL)
            return getNextObject();
        
        return next;
    }

    
    Vector!ubyte getNextOctetString()
    {
        Vector!ubyte out_vec;
        decode(out_vec, ASN1Tag.OCTET_STRING);
        return out_vec;
    }

    
    /*
    * Push a object back into the stream
    */
    void pushBack(in BERObject obj)
    {
        if (m_pushed.type_tag != ASN1Tag.NO_OBJECT)
            throw new InvalidState("BERDecoder: Only one push back is allowed");
        m_pushed = obj;
    }

    
    /*
    * Check if more objects are there
    */
    bool moreItems() const
    {
        if (m_source.endOfData() && (m_pushed.type_tag == ASN1Tag.NO_OBJECT))
            return false;
        return true;
    }

    /*
    * Verify that no bytes remain in the m_source
    */
    BERDecoder verifyEnd()
    {
        if (!m_source.endOfData() || (m_pushed.type_tag != ASN1Tag.NO_OBJECT))
            throw new InvalidState("verify_end called, but data remains");
        return this;
    }

    /*
    * Discard all the bytes remaining in the m_source
    */
    BERDecoder discardRemaining()
    {
        ubyte buf;
        while (m_source.readByte(buf))
            continue;
        return this;
    }

    /*
    * Begin decoding a ASN1Tag.CONSTRUCTED type
    */
    BERDecoder startCons(ASN1Tag type_tag,
                             ASN1Tag class_tag = ASN1Tag.UNIVERSAL)
    {
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag | ASN1Tag.CONSTRUCTED);
        
        BERDecoder result = BERDecoder(&obj.value[0], obj.value.length);
        result.m_parent = &this;
        return result;
    }

    /*
    * Finish decoding a ASN1Tag.CONSTRUCTED type
    */
    BERDecoder endCons()
    {
        if (!m_parent)
            throw new InvalidState("endCons called with NULL m_parent");
        if (!m_source.endOfData())
            throw new DecodingError("endCons called with data left");
        return *m_parent;
    }
    

    
    BERDecoder getNext(ref BERObject ber)
    {
        ber = getNextObject();
        return this;
    }
        
    /*
    * Save all the bytes remaining in the m_source
    */
    BERDecoder rawBytes(SecureVector!ubyte output)
    {
        output.clear();
        ubyte buf;
        while (m_source.readByte(buf))
            output.pushBack(buf);
        return this;
    }
    
    BERDecoder rawBytes(ref Vector!ubyte output)
    {
        output.clear();
        ubyte buf;
        while (m_source.readByte(buf))
            output.pushBack(buf);
        return this;
    }

    /*
    * Decode a BER encoded NULL
    */
    BERDecoder decodeNull()
    {
        BERObject obj = getNextObject();
        obj.assertIsA(ASN1Tag.NULL_TAG, ASN1Tag.UNIVERSAL);
        if (obj.value.length)
            throw new BERDecodingError("NULL object had nonzero size");
        return this;
    }

    BERDecoder decode(T)(auto ref T obj)
    {
        obj.decodeFrom(this);

        return this;
    }

    /*
    * Request for an object to decode itself
    */
    BERDecoder decode(T : ASN1Object)(auto ref T obj, ASN1Tag type, ASN1Tag tag)
    {
        obj.decodeFrom(this);
        return this;
    }
    
    /*
    * Decode a BER encoded BOOLEAN
    */
    BERDecoder decode(ref bool output)
    {
        return decode(output, ASN1Tag.BOOLEAN, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * Decode a small BER encoded INTEGER
    */
    BERDecoder decode(ref size_t output)
    {
        return decode(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * Decode a BER encoded INTEGER
    */
    BERDecoder decode(ref BigInt output)
    {
        return decode(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    
    /*
    * Decode a BER encoded BOOLEAN
    */
    BERDecoder decode(ref bool output,
                      ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (obj.value.length != 1)
            throw new BERDecodingError("BER boolean value had invalid size");
        
        output = (obj.value[0]) ? true : false;
        return this;
    }
    
    /*
    * Decode a small BER encoded INTEGER
    */
    BERDecoder decode(ref size_t output,
                       ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        BigInt integer;
        decode(integer, type_tag, class_tag);
        
        if (integer.bits() > 32)
            throw new BERDecodingError("Decoded integer value larger than expected");
        
        output = 0;
        foreach (size_t i; 0 .. 4)
            output = (output << 8) | integer.byteAt(3-i);
        
        return this;
    }

    /*
    * Decode a BER encoded INTEGER
    */
    BERDecoder decode(BigInt output,
                      ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (obj.value.empty)
            output = BigInt(0);
        else
        {
            const bool negative = (obj.value[0] & 0x80) ? true : false;
            
            if (negative)
            {
                for (size_t i = obj.value.length; i > 0; --i)
                    if (obj.value[i-1]--)
                        break;
                foreach (size_t i; 0 .. obj.value.length)
                    obj.value[i] = ~obj.value[i];
            }
            
            output = BigInt(&obj.value[0], obj.value.length);
            
            if (negative)
                output.flipSign();
        }
        
        return this;
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    BERDecoder decode(SecureVector!ubyte output, ASN1Tag real_type)
    {
        return decode(output, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    BERDecoder decode(ref Vector!ubyte output, ASN1Tag real_type)
    {
        return decode(output, real_type, real_type, ASN1Tag.UNIVERSAL);
    }
    
    /*
    * BER decode a BIT STRING or OCTET STRING
    */
    BERDecoder decode(SecureVector!ubyte buffer,
                      ASN1Tag real_type,
                      ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        if (real_type != ASN1Tag.OCTET_STRING && real_type != ASN1Tag.BIT_STRING)
            throw new BERBadTag("Bad tag for {BIT,OCTET} STRING", real_type);
        
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (real_type == ASN1Tag.OCTET_STRING)
            buffer = obj.value;
        else
        {
            if (obj.value[0] >= 8)
                throw new BERDecodingError("Bad number of unused bits in BIT STRING");
            
            buffer.resize(obj.value.length - 1);
            copyMem(buffer.ptr, &obj.value[1], obj.value.length - 1);
        }
        return this;
    }
    
    BERDecoder decode(ref Vector!ubyte buffer,
                          ASN1Tag real_type,
                          ASN1Tag type_tag, ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        if (real_type != ASN1Tag.OCTET_STRING && real_type != ASN1Tag.BIT_STRING)
            throw new BERBadTag("Bad tag for {BIT,OCTET} STRING", real_type);
        
        BERObject obj = getNextObject();
        obj.assertIsA(type_tag, class_tag);
        
        if (real_type == ASN1Tag.OCTET_STRING)
            buffer = unlock(obj.value);
        else
        {
            if (obj.value[0] >= 8)
                throw new BERDecodingError("Bad number of unused bits in BIT STRING");
            
            buffer.resize(obj.value.length - 1);
            copyMem(buffer.ptr, &obj.value[1], obj.value.length - 1);
        }
        return this;
    }

    /*
    * Decode a small BER encoded INTEGER
    */
    ulong decodeConstrainedInteger(ASN1Tag type_tag,
                                   ASN1Tag class_tag,
                                   size_t T_bytes)
    {
        if (T_bytes > 8)
            throw new BERDecodingError("Can't decode small integer over 8 bytes");
        
        BigInt integer;
        decode(integer, type_tag, class_tag);
        
        if (integer.bits() > 8*T_bytes)
            throw new BERDecodingError("Decoded integer value larger than expected");
        
        ulong output = 0;
        foreach (size_t i; 0 .. 8)
            output = (output << 8) | integer.byteAt(7-i);
        
        return output;
    }
    

    
    BERDecoder decodeIntegerType(T)(ref T output)
    {
        return decodeIntegerType!T(output, ASN1Tag.INTEGER, ASN1Tag.UNIVERSAL);
    }
    
    BERDecoder decodeIntegerType(T)(ref T output,
                                    ASN1Tag type_tag,
                                    ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        output = cast(T) decodeConstrainedInteger(type_tag, class_tag, (output).sizeof);
        return this;
    }

    /*
    * Decode an OPTIONAL or DEFAULT element
    */
    BERDecoder decodeOptional(T)(auto ref T output,
                                     ASN1Tag type_tag,
                                     ASN1Tag class_tag,
                                     T default_value = T.init)
    {
        BERObject obj = getNextObject();
        
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            if ((class_tag & ASN1Tag.CONSTRUCTED) && (class_tag & ASN1Tag.CONTEXT_SPECIFIC))
                BERDecoder(obj.value).decode(output).verifyEnd();
            else
            {
                pushBack(obj);
                decode(output, type_tag, class_tag);

            }
        }
        else
        {
            output = default_value;
            pushBack(obj);
        }
        
        return this;
    }
    
    /*
    * Decode an OPTIONAL or DEFAULT element
    */
    BERDecoder decodeOptionalImplicit(T)(ref T output,
                                         ASN1Tag type_tag,
                                         ASN1Tag class_tag,
                                         ASN1Tag real_type,
                                         ASN1Tag real_class,
                                         T default_value = T.init)
    {
        BERObject obj = getNextObject();
        
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            obj.type_tag = real_type;
            obj.class_tag = real_class;
            pushBack(obj);
            decode(output, real_type, real_class);
        }
        else
        {
            output = default_value;
            pushBack(obj);
        }
        
        return this;
    }
    

    /*
    * Decode a list of homogenously typed values
    */
    BERDecoder decodeList(T, Alloc)(FreeListRef!(VectorImpl!(T, Alloc)) vec,
                                    ASN1Tag type_tag = ASN1Tag.SEQUENCE,
                                    ASN1Tag class_tag = ASN1Tag.UNIVERSAL)
    {
        BERDecoder list = startCons(type_tag, class_tag);
        
        while (list.moreItems())
        {
            T value;
            list.decode(value);
            vec.pushBack(value);
        }
        
        list.endCons();
        
        return this;
    }

    
    BERDecoder decodeAndCheck(T)(in T expected,
                                 in string error_msg)
    {
        T actual;
        decode(actual);
        
        if (actual != expected)
            throw new DecodingError(error_msg);
        
        return this;
    }
    
    /*
        * Decode an OPTIONAL string type
        */
    BERDecoder decodeOptionalString(Alloc)(FreeListRef!(VectorImpl!( ubyte, Alloc )) output,
                                           ASN1Tag real_type,
                                           ushort type_no,
                                           ASN1Tag class_tag = ASN1Tag.CONTEXT_SPECIFIC)
    {
        BERObject obj = getNextObject();
        
        ASN1Tag type_tag = cast(ASN1Tag)(type_no);
        
        if (obj.type_tag == type_tag && obj.class_tag == class_tag)
        {
            if ((class_tag & ASN1Tag.CONSTRUCTED) && (class_tag & ASN1Tag.CONTEXT_SPECIFIC))
                BERDecoder(obj.value).decode(output, real_type).verifyEnd();
            else
            {
                pushBack(obj);
                decode(output, real_type, type_tag, class_tag);
            }
        }
        else
        {
            output.clear();
            pushBack(obj);
        }
        
        return this;
    }
    
    //BERDecoder operator=(in BERDecoder);

    BERDecoder decodeOctetStringBigint(ref BigInt output)
    {
        SecureVector!ubyte out_vec;
        decode(out_vec, ASN1Tag.OCTET_STRING);
        output = BigInt.decode(out_vec.ptr, out_vec.length);
        return this;
    }

    /*
    * BERDecoder Constructor
    */
    this(DataSource src)
    {
        m_source = src;
        m_owns = false;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Constructor
    */
    this(const(ubyte)* data, size_t length)
    {
        m_source = new DataSourceMemory(data, length);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Constructor
    */
    this(in SecureVector!ubyte data)
    {
        m_source = new DataSourceMemory(data);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Constructor
    */
    this(in Vector!ubyte data)
    {
        m_source = new DataSourceMemory(data.ptr, data.length);
        m_owns = true;
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = null;
    }
    
    /*
    * BERDecoder Copy Constructor
    */
    this(BERDecoder other)
    {
        m_source = other.m_source;
        m_owns = false;
        if (other.m_owns)
        {
            other.m_owns = false;
            m_owns = true;
        }
        m_pushed.type_tag = m_pushed.class_tag = ASN1Tag.NO_OBJECT;
        m_parent = other.m_parent;
    }

protected:
    BERDecoder* m_parent;
    FreeListRef!DataSource m_source;
    BERObject m_pushed;
    bool m_owns;
}

private:
/*
* BER decode an ASN.1 type tag
*/
size_t decodeTag(DataSource ber, ref ASN1Tag type_tag, ref ASN1Tag class_tag)
{
    ubyte b;
    if (!ber.readByte(b))
    {
        class_tag = type_tag = ASN1Tag.NO_OBJECT;
        return 0;
    }
    
    if ((b & 0x1F) != 0x1F)
    {
        type_tag = cast(ASN1Tag)(b & 0x1F);
        class_tag = cast(ASN1Tag)(b & 0xE0);
        return 1;
    }
    
    size_t tag_bytes = 1;
    class_tag = cast(ASN1Tag)(b & 0xE0);
    
    size_t tag_buf = 0;
    while (true)
    {
        if (!ber.readByte(b))
            throw new BERDecodingError("Long-form tag truncated");
        if (tag_buf & 0xFF000000)
            throw new BERDecodingError("Long-form tag overflowed 32 bits");
        ++tag_bytes;
        tag_buf = (tag_buf << 7) | (b & 0x7F);
        if ((b & 0x80) == 0) break;
    }
    type_tag = cast(ASN1Tag)(tag_buf);
    return tag_bytes;
}

/*
* BER decode an ASN.1 length field
*/
size_t decodeLength(DataSource ber, ref size_t field_size)
{
    ubyte b;
    if (!ber.readByte(b))
        throw new BERDecodingError("Length field not found");
    field_size = 1;
    if ((b & 0x80) == 0)
        return b;
    
    field_size += (b & 0x7F);
    if (field_size == 1) return findEoc(ber);
    if (field_size > 5)
        throw new BERDecodingError("Length field is too large");
    
    size_t length = 0;
    
    foreach (size_t i; 0 .. (field_size - 1))
    {
        if (get_byte(0, length) != 0)
            throw new BERDecodingError("Field length overflow");
        if (!ber.readByte(b))
            throw new BERDecodingError("Corrupted length field");
        length = (length << 8) | b;
    }
    return length;
}

/*
* BER decode an ASN.1 length field
*/
size_t decodeLength(DataSource ber)
{
    size_t dummy;
    return decodeLength(ber, dummy);
}

/*
* Find the EOC marker
*/
size_t findEoc(DataSource ber)
{
    SecureVector!ubyte buffer = SecureVector!ubyte(DEFAULT_BUFFERSIZE);
    SecureVector!ubyte data;
    
    while (true)
    {
        const size_t got = ber.peek(buffer.ptr, buffer.length, data.length);
        if (got == 0)
            break;
        
        data ~= buffer[];
    }

    auto m_source = scoped!DataSourceMemory(data);
    data.clear();
    
    size_t length = 0;
    while (true)
    {
        ASN1Tag type_tag, class_tag;
        size_t tag_size = decodeTag(m_source.Scoped_payload, type_tag, class_tag);
        if (type_tag == ASN1Tag.NO_OBJECT)
            break;
        
        size_t length_size = 0;
        size_t item_size = decodeLength(m_source.Scoped_payload, length_size);
        m_source.discardNext(item_size);
        
        length += item_size + length_size + tag_size;
        
        if (type_tag == ASN1Tag.EOC)
            break;
    }
    return length;
}


