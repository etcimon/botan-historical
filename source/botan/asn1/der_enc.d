/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1.asn1_obj;
import vector;
class BigInt;
class ASN1_Object;

/**
* General DER Encoding Object
*/
class DER_Encoder
{
	public:
		SafeVector!byte get_contents();

		Vector!byte get_contents_unlocked()
		{ return unlock(get_contents()); }

		DER_Encoder start_cons(ASN1_Tag type_tag,
								ASN1_Tag class_tag = UNIVERSAL);
		DER_Encoder end_cons();

		DER_Encoder start_explicit(ushort type_tag);
		DER_Encoder end_explicit();

		DER_Encoder raw_bytes(in byte* val, size_t len);
		DER_Encoder raw_bytes(in SafeVector!byte val);
		DER_Encoder raw_bytes(in Vector!byte val);

		DER_Encoder encode_null();
		DER_Encoder encode(bool b);
		DER_Encoder encode(size_t s);
		DER_Encoder encode(in BigInt n);
		DER_Encoder encode(in SafeVector!byte v, ASN1_Tag real_type);
		DER_Encoder encode(in Vector!byte v, ASN1_Tag real_type);
		DER_Encoder encode(in byte* val, size_t len, ASN1_Tag real_type);

		DER_Encoder encode(bool b,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode(size_t s,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode(in BigInt n,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode(in Vector!byte v,
							  ASN1_Tag real_type,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode(in SafeVector!byte v,
							  ASN1_Tag real_type,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode(in byte* v, size_t len,
							  ASN1_Tag real_type,
							  ASN1_Tag type_tag,
							  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		DER_Encoder encode_optional(T)(in T value, ref const T default_value)
		{
			if (value != default_value)
				encode(value);
			return this;
		}

		DER_Encoder encode_list(T)(in Vector!T values)
		{
			for (size_t i = 0; i != values.size(); ++i)
				encode(values[i]);
			return this;
		}

		DER_Encoder encode(in ASN1_Object obj);
		DER_Encoder encode_if (bool pred, DER_Encoder enc);
		DER_Encoder encode_if (bool pred, ref const ASN1_Object obj);

		DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
								in byte* rep, size_t length);

		DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
								in Vector!byte rep)
		{
			return add_object(type_tag, class_tag, &rep[0], rep.size());
		}

		DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
								in SafeVector!byte rep)
		{
			return add_object(type_tag, class_tag, &rep[0], rep.size());
		}

		DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
								in string str);

		DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
								byte val);

	private:
		class DER_Sequence
		{
			public:
				ASN1_Tag tag_of() const;
				SafeVector!byte get_contents();
				void add_bytes(const byte[], size_t);
				DER_Sequence(ASN1_Tag, ASN1_Tag);
			private:
				ASN1_Tag type_tag, class_tag;
				SafeVector!byte contents;
				Vector!(  SafeVector!byte  ) set_contents;
		};

		SafeVector!byte contents;
		Vector!( DER_Sequence ) subsequences;
};



import botan.der_enc;
import botan.asn1.asn1_obj;
import botan.bigint;
import botan.get_byte;
import botan.parsing;
import botan.internal.bit_ops;
import algorithm;

/*
* DER encode an ASN.1 type tag
*/
SafeVector!byte encode_tag(ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	if ((class_tag | 0xE0) != 0xE0)
		throw new Encoding_Error("DER_Encoder: Invalid class tag " ~
		                         std.conv.to!string(class_tag));
	
	SafeVector!byte encoded_tag;
	if (type_tag <= 30)
		encoded_tag.push_back(cast(byte)(type_tag | class_tag));
	else
	{
		size_t blocks = high_bit(type_tag) + 6;
		blocks = (blocks - (blocks % 7)) / 7;
		
		encoded_tag.push_back(class_tag | 0x1F);
		for (size_t i = 0; i != blocks - 1; ++i)
			encoded_tag.push_back(0x80 | ((type_tag >> 7*(blocks-i-1)) & 0x7F));
		encoded_tag.push_back(type_tag & 0x7F);
	}
	
	return encoded_tag;
}

/*
* DER encode an ASN.1 length field
*/
SafeVector!byte encode_length(size_t length)
{
	SafeVector!byte encoded_length;
	if (length <= 127)
		encoded_length.push_back(cast(byte)(length));
	else
	{
		const size_t top_byte = significant_bytes(length);
		
		encoded_length.push_back(cast(byte)(0x80 | top_byte));
		
		for (size_t i = sizeof(length) - top_byte; i != sizeof(length); ++i)
			encoded_length.push_back(get_byte(i, length));
	}
	return encoded_length;
}

}

/*
* Return the encoded SEQUENCE/SET
*/
SafeVector!byte DER_Encoder::DER_Sequence::get_contents()
{
	const ASN1_Tag real_class_tag = ASN1_Tag(class_tag | CONSTRUCTED);
	
	if (type_tag == SET)
	{
	std::sort(set_contents.begin(), set_contents.end());
		for (size_t i = 0; i != set_contents.size(); ++i)
			contents += set_contents[i];
		set_contents.clear();
	}
	
	SafeVector!byte result;
	result += encode_tag(type_tag, real_class_tag);
	result += encode_length(contents.size());
	result += contents;
	contents.clear();
	
	return result;
}

/*
* Add an encoded value to the SEQUENCE/SET
*/
void DER_Encoder::DER_Sequence::add_bytes(in byte* data, size_t length)
{
	if (type_tag == SET)
		set_contents.push_back(SafeVector!byte(data, data + length));
	else
		contents += Pair(data, length);
}

/*
* Return the type and class taggings
*/
ASN1_Tag DER_Encoder::DER_Sequence::tag_of() const
{
	return ASN1_Tag(type_tag | class_tag);
}

/*
* DER_Sequence Constructor
*/
DER_Encoder::DER_Sequence::DER_Sequence(ASN1_Tag t1, ASN1_Tag t2) :
type_tag(t1), class_tag(t2)
{
}

/*
* Return the encoded contents
*/
SafeVector!byte DER_Encoder::get_contents()
{
	if (subsequences.size() != 0)
		throw new Invalid_State("DER_Encoder: Sequence hasn't been marked done");
	
	SafeVector!byte output;
std::swap(output, contents);
	return output;
}

/*
* Start a new ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder DER_Encoder::start_cons(ASN1_Tag type_tag,
                                    ASN1_Tag class_tag)
{
	subsequences.push_back(DER_Sequence(type_tag, class_tag));
	return this;
}

/*
* Finish the current ASN.1 SEQUENCE/SET/EXPLICIT
*/
DER_Encoder DER_Encoder::end_cons()
{
	if (subsequences.empty())
		throw new Invalid_State("DER_Encoder::end_cons: No such sequence");
	
	SafeVector!byte seq = subsequences[subsequences.size()-1].get_contents();
	subsequences.pop_back();
	raw_bytes(seq);
	return this;
}

/*
* Start a new ASN.1 EXPLICIT encoding
*/
DER_Encoder DER_Encoder::start_explicit(ushort type_no)
{
	ASN1_Tag type_tag = cast(ASN1_Tag)(type_no);
	
	if (type_tag == SET)
		throw new Internal_Error("DER_Encoder.start_explicit(SET); cannot perform");
	
	return start_cons(type_tag, CONTEXT_SPECIFIC);
}

/*
* Finish the current ASN.1 EXPLICIT encoding
*/
DER_Encoder DER_Encoder::end_explicit()
{
	return end_cons();
}

/*
* Write raw bytes into the stream
*/
DER_Encoder DER_Encoder::raw_bytes(in SafeVector!byte val)
{
	return raw_bytes(&val[0], val.size());
}

DER_Encoder DER_Encoder::raw_bytes(in Vector!byte val)
{
	return raw_bytes(&val[0], val.size());
}

/*
* Write raw bytes into the stream
*/
DER_Encoder DER_Encoder::raw_bytes(in byte* bytes, size_t length)
{
	if (subsequences.size())
		subsequences[subsequences.size()-1].add_bytes(bytes, length);
	else
		contents += Pair(bytes, length);
	
	return this;
}

/*
* Encode a NULL object
*/
DER_Encoder DER_Encoder::encode_null()
{
	return add_object(NULL_TAG, UNIVERSAL, null, 0);
}

/*
* DER encode a BOOLEAN
*/
DER_Encoder DER_Encoder::encode(bool is_true)
{
	return encode(is_true, BOOLEAN, UNIVERSAL);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder DER_Encoder::encode(size_t n)
{
	return encode(BigInt(n), INTEGER, UNIVERSAL);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder DER_Encoder::encode(in BigInt n)
{
	return encode(n, INTEGER, UNIVERSAL);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder DER_Encoder::encode(in SafeVector!byte bytes,
                                ASN1_Tag real_type)
{
	return encode(&bytes[0], bytes.size(),
	real_type, real_type, UNIVERSAL);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder DER_Encoder::encode(in Vector!byte bytes,
                                ASN1_Tag real_type)
{
	return encode(&bytes[0], bytes.size(),
	real_type, real_type, UNIVERSAL);
}

/*
* Encode this object
*/
DER_Encoder DER_Encoder::encode(in byte* bytes, size_t length,
                                ASN1_Tag real_type)
{
	return encode(bytes, length, real_type, real_type, UNIVERSAL);
}

/*
* DER encode a BOOLEAN
*/
DER_Encoder DER_Encoder::encode(bool is_true,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	byte val = is_true ? 0xFF : 0x00;
	return add_object(type_tag, class_tag, &val, 1);
}

/*
* DER encode a small INTEGER
*/
DER_Encoder DER_Encoder::encode(size_t n,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	return encode(BigInt(n), type_tag, class_tag);
}

/*
* DER encode an INTEGER
*/
DER_Encoder DER_Encoder::encode(in BigInt n,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	if (n == 0)
		return add_object(type_tag, class_tag, 0);
	
	bool extra_zero = (n.bits() % 8 == 0);
	SafeVector!byte contents(extra_zero + n.bytes());
BigInt::encode(&contents[extra_zero], n);
	if (n < 0)
	{
		for (size_t i = 0; i != contents.size(); ++i)
			contents[i] = ~contents[i];
		for (size_t i = contents.size(); i > 0; --i)
			if (++contents[i-1])
				break;
	}
	
	return add_object(type_tag, class_tag, contents);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder DER_Encoder::encode(in SafeVector!byte bytes,
                                ASN1_Tag real_type,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	return encode(&bytes[0], bytes.size(),
	real_type, type_tag, class_tag);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder DER_Encoder::encode(in Vector!byte bytes,
                                ASN1_Tag real_type,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	return encode(&bytes[0], bytes.size(),
	real_type, type_tag, class_tag);
}

/*
* DER encode an OCTET STRING or BIT STRING
*/
DER_Encoder DER_Encoder::encode(in byte* bytes, size_t length,
                                ASN1_Tag real_type,
                                ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	if (real_type != OCTET_STRING && real_type != BIT_STRING)
		throw new Invalid_Argument("DER_Encoder: Invalid tag for byte/bit string");
	
	if (real_type == BIT_STRING)
	{
		SafeVector!byte encoded;
		encoded.push_back(0);
		encoded += Pair(bytes, length);
		return add_object(type_tag, class_tag, encoded);
	}
	else
		return add_object(type_tag, class_tag, bytes, length);
}

/*
* Conditionally write some values to the stream
*/
DER_Encoder DER_Encoder::encode_if (bool cond, DER_Encoder codec)
{
	if (cond)
		return raw_bytes(codec.get_contents());
	return this;
}

DER_Encoder DER_Encoder::encode_if (bool cond, const ASN1_Object& obj)
{
	if (cond)
		encode(obj);
	return this;
}

/*
* Request for an object to encode itself
*/
DER_Encoder DER_Encoder::encode(in ASN1_Object obj)
{
	obj.encode_into(*this);
	return this;
}

/*
* Write the encoding of the byte(s)
*/
DER_Encoder DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                    in byte* rep, size_t length)
{
	SafeVector!byte buffer;
	buffer += encode_tag(type_tag, class_tag);
	buffer += encode_length(length);
	buffer += Pair(rep, length);
	
	return raw_bytes(buffer);
}

/*
* Write the encoding of the byte(s)
*/
DER_Encoder DER_Encoder::add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
                                    in string rep_str)
{
	const byte* rep = cast(const byte*)(rep_str.data());
	const size_t rep_len = rep_str.size();
	return add_object(type_tag, class_tag, rep, rep_len);
}

/*
* Write the encoding of the byte
*/
DER_Encoder DER_Encoder::add_object(ASN1_Tag type_tag,
                                    ASN1_Tag class_tag, byte rep)
{
	return add_object(type_tag, class_tag, &rep, 1);
}
