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

alias BER_Decoder = FreeListRef!BER_Decoder_Impl;

/**
* BER Decoding Object
*/
final class BER_Decoder_Impl
{
public:

	/*
	* Return the BER encoding of the next object
	*/
	BER_Object get_next_object()
	{
		BER_Object next;
		
		if (m_pushed.type_tag != ASN1_Tag.NO_OBJECT)
		{
			next = m_pushed;
			m_pushed.class_tag = m_pushed.type_tag = ASN1_Tag.NO_OBJECT;
			return next;
		}
		
		decode_tag(m_source, next.type_tag, next.class_tag);
		if (next.type_tag == ASN1_Tag.NO_OBJECT)
			return next;
		
		size_t length = decode_length(m_source);
		next.value.resize(length);
		if (m_source.read(&next.value[0], length) != length)
			throw new BER_Decoding_Error("Value truncated");
		
		if (next.type_tag == ASN1_Tag.EOC && next.class_tag == ASN1_Tag.UNIVERSAL)
			return get_next_object();
		
		return next;
	}

	
	Vector!ubyte get_next_octet_string()
	{
		Vector!ubyte out_vec;
		decode(out_vec, ASN1_Tag.OCTET_STRING);
		return out_vec;
	}

	
	/*
	* Push a object back into the stream
	*/
	void push_back(in BER_Object obj)
	{
		if (m_pushed.type_tag != ASN1_Tag.NO_OBJECT)
			throw new Invalid_State("BER_Decoder: Only one push back is allowed");
		m_pushed = obj;
	}

	
	/*
	* Check if more objects are there
	*/
	bool more_items() const
	{
		if (m_source.end_of_data() && (m_pushed.type_tag == ASN1_Tag.NO_OBJECT))
			return false;
		return true;
	}

	/*
	* Verify that no bytes remain in the m_source
	*/
	BER_Decoder verify_end()
	{
		if (!m_source.end_of_data() || (m_pushed.type_tag != ASN1_Tag.NO_OBJECT))
			throw new Invalid_State("verify_end called, but data remains");
		return this;
	}

	/*
	* Discard all the bytes remaining in the m_source
	*/
	BER_Decoder discard_remaining()
	{
		ubyte buf;
		while(m_source.read_byte(buf))
			continue;
		return this;
	}

	/*
	* Begin decoding a ASN1_Tag.CONSTRUCTED type
	*/
	BER_Decoder start_cons(ASN1_Tag type_tag,
	                       ASN1_Tag class_tag = ASN1_Tag.UNIVERSAL)
	{
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, ASN1_Tag(class_tag | ASN1_Tag.CONSTRUCTED));
		
		BER_Decoder result = new BER_Decoder(&obj.value[0], obj.value.length);
		result.m_parent = this;
		return result;
	}

	/*
	* Finish decoding a ASN1_Tag.CONSTRUCTED type
	*/
	BER_Decoder end_cons()
	{
		if (!m_parent)
			throw new Invalid_State("end_cons called with NULL m_parent");
		if (!m_source.end_of_data())
			throw new Decoding_Error("end_cons called with data left");
		return m_parent;
	}
	

	
	BER_Decoder get_next(ref BER_Object ber)
	{
		ber = get_next_object();
		return this;
	}
		
	/*
	* Save all the bytes remaining in the m_source
	*/
	BER_Decoder raw_bytes(Secure_Vector!ubyte output)
	{
		output.clear();
		ubyte buf;
		while(m_source.read_byte(buf))
			output.push_back(buf);
		return this;
	}
	
	BER_Decoder raw_bytes(ref Vector!ubyte output)
	{
		output.clear();
		ubyte buf;
		while(m_source.read_byte(buf))
			output.push_back(buf);
		return this;
	}

	/*
	* Decode a BER encoded NULL
	*/
	BER_Decoder decode_null()
	{
		BER_Object obj = get_next_object();
		obj.assert_is_a(ASN1_Tag.NULL_TAG, ASN1_Tag.UNIVERSAL);
		if (obj.value.length)
			throw new BER_Decoding_Error("NULL object had nonzero size");
		return this;
	}

	/*
	* Request for an object to decode itself
	*/
	BER_Decoder decode(ref ASN1_Object obj,
	                   ASN1_Tag, ASN1_Tag)
	{
		obj.decode_from(this);
		return this;
	}
	
	/*
	* Decode a BER encoded BOOLEAN
	*/
	BER_Decoder decode(ref bool output)
	{
		return decode(output, ASN1_Tag.BOOLEAN, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* Decode a small BER encoded INTEGER
	*/
	BER_Decoder decode(ref size_t output)
	{
		return decode(output, ASN1_Tag.INTEGER, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* Decode a BER encoded INTEGER
	*/
	BER_Decoder decode(ref BigInt output)
	{
		return decode(output, ASN1_Tag.INTEGER, ASN1_Tag.UNIVERSAL);
	}
	
	
	/*
	* Decode a BER encoded BOOLEAN
	*/
	BER_Decoder decode(ref bool output,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, class_tag);
		
		if (obj.value.length != 1)
			throw new BER_Decoding_Error("BER boolean value had invalid size");
		
		output = (obj.value[0]) ? true : false;
		return this;
	}
	
	/*
	* Decode a small BER encoded INTEGER
	*/
	BER_Decoder decode(ref size_t output,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		BigInt integer;
		decode(integer, type_tag, class_tag);
		
		if (integer.bits() > 32)
			throw new BER_Decoding_Error("Decoded integer value larger than expected");
		
		output = 0;
		foreach (size_t i; 0 .. 4)
			output = (output << 8) | integer.byte_at(3-i);
		
		return this;
	}
	/*
	* Decode a BER encoded INTEGER
	*/
	BER_Decoder decode(ref BigInt output,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, class_tag);
		
		if (obj.value.empty)
			output = 0;
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
				output.flip_sign();
		}
		
		return this;
	}
	
	/*
	* BER decode a BIT STRING or OCTET STRING
	*/
	BER_Decoder decode(Secure_Vector!ubyte output, ASN1_Tag real_type)
	{
		return decode(output, real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* BER decode a BIT STRING or OCTET STRING
	*/
	BER_Decoder decode(ref Vector!ubyte output, ASN1_Tag real_type)
	{
		return decode(output, real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* BER decode a BIT STRING or OCTET STRING
	*/
	BER_Decoder decode(Secure_Vector!ubyte buffer,
	                   ASN1_Tag real_type,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (real_type != ASN1_Tag.OCTET_STRING && real_type != ASN1_Tag.BIT_STRING)
			throw new BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);
		
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, class_tag);
		
		if (real_type == ASN1_Tag.OCTET_STRING)
			buffer = obj.value;
		else
		{
			if (obj.value[0] >= 8)
				throw new BER_Decoding_Error("Bad number of unused bits in BIT STRING");
			
			buffer.resize(obj.value.length - 1);
			copy_mem(&buffer[0], &obj.value[1], obj.value.length - 1);
		}
		return this;
	}
	
	BER_Decoder decode(ref Vector!ubyte buffer,
	                   ASN1_Tag real_type,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (real_type != ASN1_Tag.OCTET_STRING && real_type != ASN1_Tag.BIT_STRING)
			throw new BER_Bad_Tag("Bad tag for {BIT,OCTET} STRING", real_type);
		
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, class_tag);
		
		if (real_type == ASN1_Tag.OCTET_STRING)
			buffer = unlock(obj.value);
		else
		{
			if (obj.value[0] >= 8)
				throw new BER_Decoding_Error("Bad number of unused bits in BIT STRING");
			
			buffer.resize(obj.value.length - 1);
			copy_mem(&buffer[0], &obj.value[1], obj.value.length - 1);
		}
		return this;
	}

	/*
	* Decode a small BER encoded INTEGER
	*/
	ulong decode_constrained_integer(ASN1_Tag type_tag,
	                                 ASN1_Tag class_tag,
	                                 size_t T_bytes)
	{
		if (T_bytes > 8)
			throw new BER_Decoding_Error("Can't decode small integer over 8 bytes");
		
		BigInt integer;
		decode(integer, type_tag, class_tag);
		
		if (integer.bits() > 8*T_bytes)
			throw new BER_Decoding_Error("Decoded integer value larger than expected");
		
		ulong output = 0;
		foreach (size_t i; 0 .. 8)
			output = (output << 8) | integer.byte_at(7-i);
		
		return output;
	}
	

	
	BER_Decoder decode_integer_type(T)(ref T output)
	{
		return decode_integer_type!T(output, ASN1_Tag.INTEGER, ASN1_Tag.UNIVERSAL);
	}
	
	BER_Decoder decode_integer_type(T)(ref T output,
	                                   ASN1_Tag type_tag,
	                                   ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		output = decode_constrained_integer(type_tag, class_tag, (output).sizeof);
		return this;
	}
	
	/*
	* Decode an OPTIONAL or DEFAULT element
	*/
	BER_Decoder decode_optional(T)(ref T output,
	                               ASN1_Tag type_tag,
	                               ASN1_Tag class_tag,
	                               const ref T default_value = T.init)
	{
		BER_Object obj = get_next_object();
		
		if (obj.type_tag == type_tag && obj.class_tag == class_tag)
		{
			if ((class_tag & ASN1_Tag.CONSTRUCTED) && (class_tag & ASN1_Tag.CONTEXT_SPECIFIC))
				BER_Decoder(obj.value).decode(output).verify_end();
			else
			{
				push_back(obj);
				decode(output, type_tag, class_tag);
			}
		}
		else
		{
			output = default_value;
			push_back(obj);
		}
		
		return this;
	}
	
	/*
	* Decode an OPTIONAL or DEFAULT element
	*/
	BER_Decoder decode_optional_implicit(T)(
		ref T output,
		ASN1_Tag type_tag,
		ASN1_Tag class_tag,
		ASN1_Tag real_type,
		ASN1_Tag real_class,
		const ref T default_value = T.init)
	{
		BER_Object obj = get_next_object();
		
		if (obj.type_tag == type_tag && obj.class_tag == class_tag)
		{
			obj.type_tag = real_type;
			obj.class_tag = real_class;
			push_back(obj);
			decode(output, real_type, real_class);
		}
		else
		{
			output = default_value;
			push_back(obj);
		}
		
		return this;
	}
	

	/*
	* Decode a list of homogenously typed values
	*/
	BER_Decoder decode_list(T)(Vector!T vec,
	                           ASN1_Tag type_tag = ASN1_Tag.SEQUENCE,
	                           ASN1_Tag class_tag = ASN1_Tag.UNIVERSAL)
	{
		BER_Decoder list = start_cons(type_tag, class_tag);
		
		while(list.more_items())
		{
			T value;
			list.decode(value);
			vec.push_back(value);
		}
		
		list.end_cons();
		
		return this;
	}

	
	BER_Decoder decode_and_check(T)(in T expected,
	                                in string error_msg)
	{
		T actual;
		decode(actual);
		
		if (actual != expected)
			throw new Decoding_Error(error_msg);
		
		return this;
	}
	
	/*
		* Decode an OPTIONAL string type
		*/
	BER_Decoder decode_optional_string(Alloc)(Vector!( ubyte, Alloc ) output,
	                                          ASN1_Tag real_type,
	                                          ushort type_no,
	                                          ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		BER_Object obj = get_next_object();
		
		ASN1_Tag type_tag = cast(ASN1_Tag)(type_no);
		
		if (obj.type_tag == type_tag && obj.class_tag == class_tag)
		{
			if ((class_tag & ASN1_Tag.CONSTRUCTED) && (class_tag & ASN1_Tag.CONTEXT_SPECIFIC))
				BER_Decoder(obj.value).decode(output, real_type).verify_end();
			else
			{
				push_back(obj);
				decode(output, real_type, type_tag, class_tag);
			}
		}
		else
		{
			output.clear();
			push_back(obj);
		}
		
		return this;
	}
	
	//BER_Decoder operator=(in BER_Decoder);

	BER_Decoder decode_octet_string_bigint(ref BigInt output)
	{
		Secure_Vector!ubyte out_vec;
		decode(out_vec, ASN1_Tag.OCTET_STRING);
		output = BigInt.decode(&out_vec[0], out_vec.length);
		return this;
	}

	/*
	* BER_Decoder Constructor
	*/
	this(DataSource src)
	{
		m_source = src;
		m_owns = false;
		m_pushed.type_tag = m_pushed.class_tag = ASN1_Tag.NO_OBJECT;
		m_parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in ubyte* data, size_t length)
	{
		m_source = new DataSource_Memory(data, length);
		m_owns = true;
		m_pushed.type_tag = m_pushed.class_tag = ASN1_Tag.NO_OBJECT;
		m_parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in Secure_Vector!ubyte data)
	{
		m_source = new DataSource_Memory(data);
		m_owns = true;
		m_pushed.type_tag = m_pushed.class_tag = ASN1_Tag.NO_OBJECT;
		m_parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in Vector!ubyte data)
	{
		m_source = new DataSource_Memory(&data[0], data.length);
		m_owns = true;
		m_pushed.type_tag = m_pushed.class_tag = ASN1_Tag.NO_OBJECT;
		m_parent = null;
	}
	
	/*
	* BER_Decoder Copy Constructor
	*/
	this(in BER_Decoder other)
	{
		m_source = other.m_source;
		m_owns = false;
		if (other.m_owns)
		{
			other.m_owns = false;
			m_owns = true;
		}
		m_pushed.type_tag = m_pushed.class_tag = ASN1_Tag.NO_OBJECT;
		m_parent = other.m_parent;
	}

	/*
	* BER_Decoder Destructor
	*/
	~this()
	{
		if (m_owns)
			m_source.clear();
		else
			m_source.drop();
	}
private:
	BER_Decoder m_parent;
	Unique!DataSource m_source;
	BER_Object m_pushed;
	bool m_owns;
}

private:
/*
* BER decode an ASN.1 type tag
*/
size_t decode_tag(DataSource ber, ref ASN1_Tag type_tag, ref ASN1_Tag class_tag)
{
	ubyte b;
	if (!ber.read_byte(b))
	{
		class_tag = type_tag = ASN1_Tag.NO_OBJECT;
		return 0;
	}
	
	if ((b & 0x1F) != 0x1F)
	{
		type_tag = ASN1_Tag(b & 0x1F);
		class_tag = ASN1_Tag(b & 0xE0);
		return 1;
	}
	
	size_t tag_bytes = 1;
	class_tag = ASN1_Tag(b & 0xE0);
	
	size_t tag_buf = 0;
	while(true)
	{
		if (!ber.read_byte(b))
			throw new BER_Decoding_Error("Long-form tag truncated");
		if (tag_buf & 0xFF000000)
			throw new BER_Decoding_Error("Long-form tag overflowed 32 bits");
		++tag_bytes;
		tag_buf = (tag_buf << 7) | (b & 0x7F);
		if ((b & 0x80) == 0) break;
	}
	type_tag = ASN1_Tag(tag_buf);
	return tag_bytes;
}

/*
* BER decode an ASN.1 length field
*/
size_t decode_length(DataSource ber, ref size_t field_size)
{
	ubyte b;
	if (!ber.read_byte(b))
		throw new BER_Decoding_Error("Length field not found");
	field_size = 1;
	if ((b & 0x80) == 0)
		return b;
	
	field_size += (b & 0x7F);
	if (field_size == 1) return find_eoc(ber);
	if (field_size > 5)
		throw new BER_Decoding_Error("Length field is too large");
	
	size_t length = 0;
	
	foreach (size_t i; 0 .. (field_size - 1))
	{
		if (get_byte(0, length) != 0)
			throw new BER_Decoding_Error("Field length overflow");
		if (!ber.read_byte(b))
			throw new BER_Decoding_Error("Corrupted length field");
		length = (length << 8) | b;
	}
	return length;
}

/*
* BER decode an ASN.1 length field
*/
size_t decode_length(DataSource ber)
{
	size_t dummy;
	return decode_length(ber, dummy);
}

/*
* Find the EOC marker
*/
size_t find_eoc(DataSource ber)
{
	Secure_Vector!ubyte buffer = Secure_Vector!ubyte(DEFAULT_BUFFERSIZE);
	Secure_Vector!ubyte data;
	
	while(true)
	{
		const size_t got = ber.peek(&buffer[0], buffer.length, data.length);
		if (got == 0)
			break;
		
		data ~= buffer[];
	}

	auto m_source = scoped!DataSource_Memory(data);
	data.clear();
	
	size_t length = 0;
	while(true)
	{
		ASN1_Tag type_tag, class_tag;
		size_t tag_size = decode_tag(m_source.Scoped_payload, type_tag, class_tag);
		if (type_tag == ASN1_Tag.NO_OBJECT)
			break;
		
		size_t length_size = 0;
		size_t item_size = decode_length(m_source.scopedPayload, length_size);
		m_source.discard_next(item_size);
		
		length += item_size + length_size + tag_size;
		
		if (type_tag == ASN1_Tag.EOC)
			break;
	}
	return length;
}
