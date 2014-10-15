/*
* BER Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.ber_dec;

import botan.asn1.asn1_oid;
import botan.filters.data_src;
import botan.ber_dec;
import botan.bigint;
import botan.utils.get_byte;

/**
* BER Decoding Object
*/
class BER_Decoder
{
public:
	import botan.utils.mixins;
	mixin USE_STRUCT_INIT!();

	/*
	* Return the BER encoding of the next object
	*/
	BER_Object get_next_object()
	{
		BER_Object next;
		
		if (pushed.type_tag != ASN1_Tag.NO_OBJECT)
		{
			next = pushed;
			pushed.class_tag = pushed.type_tag = ASN1_Tag.NO_OBJECT;
			return next;
		}
		
		decode_tag(source, next.type_tag, next.class_tag);
		if (next.type_tag == ASN1_Tag.NO_OBJECT)
			return next;
		
		size_t length = decode_length(source);
		next.value.resize(length);
		if (source.read(&next.value[0], length) != length)
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
		if (pushed.type_tag != ASN1_Tag.NO_OBJECT)
			throw new Invalid_State("BER_Decoder: Only one push back is allowed");
		pushed = obj;
	}

	
	/*
	* Check if more objects are there
	*/
	bool more_items() const
	{
		if (source.end_of_data() && (pushed.type_tag == ASN1_Tag.NO_OBJECT))
			return false;
		return true;
	}

	/*
	* Verify that no bytes remain in the source
	*/
	BER_Decoder verify_end()
	{
		if (!source.end_of_data() || (pushed.type_tag != ASN1_Tag.NO_OBJECT))
			throw new Invalid_State("verify_end called, but data remains");
		return this;
	}

	/*
	* Discard all the bytes remaining in the source
	*/
	BER_Decoder discard_remaining()
	{
		ubyte buf;
		while(source.read_byte(buf))
			continue;
		return this;
	}

	/*
	* Begin decoding a CONSTRUCTED type
	*/
	BER_Decoder start_cons(ASN1_Tag type_tag,
	                       ASN1_Tag class_tag = ASN1_Tag.UNIVERSAL)
	{
		BER_Object obj = get_next_object();
		obj.assert_is_a(type_tag, ASN1_Tag(class_tag | ASN1_Tag.CONSTRUCTED));
		
		BER_Decoder result = new BER_Decoder(&obj.value[0], obj.value.size());
		result.parent = this;
		return result;
	}

	/*
	* Finish decoding a CONSTRUCTED type
	*/
	BER_Decoder end_cons()
	{
		if (!parent)
			throw new Invalid_State("end_cons called with NULL parent");
		if (!source.end_of_data())
			throw new Decoding_Error("end_cons called with data left");
		return (*parent);
	}
	

	
	BER_Decoder get_next(ref BER_Object ber)
	{
		ber = get_next_object();
		return this;
	}
		
	/*
	* Save all the bytes remaining in the source
	*/
	BER_Decoder raw_bytes(SafeVector!ubyte output)
	{
		output.clear();
		ubyte buf;
		while(source.read_byte(buf))
			output.push_back(buf);
		return this;
	}
	
	BER_Decoder raw_bytes(ref Vector!ubyte output)
	{
		output.clear();
		ubyte buf;
		while(source.read_byte(buf))
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
		if (obj.value.size())
			throw new BER_Decoding_Error("NULL object had nonzero size");
		return this;
	}

	/*
	* Request for an object to decode itself
	*/
	BER_Decoder decode(ref ASN1_Object obj,
	                   ASN1_Tag, ASN1_Tag)
	{
		obj.decode_from(*this);
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
		
		if (obj.value.size() != 1)
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
		for (size_t i = 0; i != 4; ++i)
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
		
		if (obj.value.empty())
			output = 0;
		else
		{
			const bool negative = (obj.value[0] & 0x80) ? true : false;
			
			if (negative)
			{
				for (size_t i = obj.value.size(); i > 0; --i)
					if (obj.value[i-1]--)
						break;
				for (size_t i = 0; i != obj.value.size(); ++i)
					obj.value[i] = ~obj.value[i];
			}
			
			output = BigInt(&obj.value[0], obj.value.size());
			
			if (negative)
				output.flip_sign();
		}
		
		return this;
	}
	
	/*
	* BER decode a BIT STRING or OCTET STRING
	*/
	BER_Decoder decode(SafeVector!ubyte output, ASN1_Tag real_type)
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
	BER_Decoder decode(SafeVector!ubyte buffer,
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
			
			buffer.resize(obj.value.size() - 1);
			copy_mem(&buffer[0], &obj.value[1], obj.value.size() - 1);
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
			
			buffer.resize(obj.value.size() - 1);
			copy_mem(&buffer[0], &obj.value[1], obj.value.size() - 1);
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
		for (size_t i = 0; i != 8; ++i)
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
		output = decode_constrained_integer(type_tag, class_tag, sizeof(output));
		return this;
	}
	
	/*
	* Decode an OPTIONAL or DEFAULT element
	*/
	BER_Decoder decode_optional(T)(ref T output,
	                               ASN1_Tag type_tag,
	                               ASN1_Tag class_tag,
	                               ref const T default_value = T.init)
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
		ref const T default_value = T.init)
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
		SafeVector!ubyte out_vec;
		decode(out_vec, ASN1_Tag.OCTET_STRING);
		output = BigInt.decode(&out_vec[0], out_vec.size());
		return this;
	}
	


	/*
	* BER_Decoder Constructor
	*/
	this(DataSource src)
	{
		source = src;
		owns = false;
		pushed.type_tag = pushed.class_tag = ASN1_Tag.NO_OBJECT;
		parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in ubyte* data, size_t length)
	{
		source = new DataSource_Memory(data, length);
		owns = true;
		pushed.type_tag = pushed.class_tag = ASN1_Tag.NO_OBJECT;
		parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in SafeVector!ubyte data)
	{
		source = new DataSource_Memory(data);
		owns = true;
		pushed.type_tag = pushed.class_tag = ASN1_Tag.NO_OBJECT;
		parent = null;
	}
	
	/*
	* BER_Decoder Constructor
	*/
	this(in Vector!ubyte data)
	{
		source = new DataSource_Memory(&data[0], data.size());
		owns = true;
		pushed.type_tag = pushed.class_tag = ASN1_Tag.NO_OBJECT;
		parent = null;
	}
	
	/*
	* BER_Decoder Copy Constructor
	*/
	this(in BER_Decoder other)
	{
		source = other.source;
		owns = false;
		if (other.owns)
		{
			other.owns = false;
			owns = true;
		}
		pushed.type_tag = pushed.class_tag = ASN1_Tag.NO_OBJECT;
		parent = other.parent;
	}

	/*
	* BER_Decoder Destructor
	*/
	~this()
	{
		if (owns)
			delete source;
		source = null;
	}
private:
	BER_Decoder parent;
	DataSource source;
	BER_Object pushed;
	bool owns;
};





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
	
	for (size_t i = 0; i != field_size - 1; ++i)
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
	SafeVector!ubyte buffer(DEFAULT_BUFFERSIZE), data;
	
	while(true)
	{
		const size_t got = ber.peek(&buffer[0], buffer.size(), data.size());
		if (got == 0)
			break;
		
		data += Pair(&buffer[0], got);
	}

	DataSource_Memory source = new DataSource_Memory(data);
	scope(exit) delete data;
	data.clear();
	
	size_t length = 0;
	while(true)
	{
		ASN1_Tag type_tag, class_tag;
		size_t tag_size = decode_tag(&source, type_tag, class_tag);
		if (type_tag == ASN1_Tag.NO_OBJECT)
			break;
		
		size_t length_size = 0;
		size_t item_size = decode_length(&source, length_size);
		source.discard_next(item_size);
		
		length += item_size + length_size + tag_size;
		
		if (type_tag == ASN1_Tag.EOC)
			break;
	}
	return length;
}
