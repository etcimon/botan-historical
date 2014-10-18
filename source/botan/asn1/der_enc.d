/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.asn1.der_enc;

import botan.asn1.asn1_obj;
import botan.asn1.der_enc;
import botan.math.bigint.bigint;
import botan.utils.get_byte;
import botan.parsing;
import botan.utils.bit_ops;
import std.algorithm;

import vector;

/**
* General DER Encoding Object
*/
class DER_Encoder
{
public:

	import botan.utils.mixins;
	mixin USE_STRUCT_INIT!();

	Vector!ubyte get_contents_unlocked()
	{ return unlock(get_contents()); }


	/*
	* Return the encoded contents
	*/
	SafeVector!ubyte get_contents()
	{
		if (subsequences.size() != 0)
			throw new Invalid_State("DER_Encoder: Sequence hasn't been marked done");
		
		SafeVector!ubyte output;
		std.algorithm.swap(output, contents);
		return output;
	}
	
	/*
	* Start a new ASN.1 ASN1_Tag.SEQUENCE/SET/EXPLICIT
	*/
	DER_Encoder start_cons(ASN1_Tag type_tag,
	                       ASN1_Tag class_tag)
	{
		subsequences.push_back(DER_Sequence(type_tag, class_tag));
		return this;
	}
	
	/*
	* Finish the current ASN.1 ASN1_Tag.SEQUENCE/SET/EXPLICIT
	*/
	DER_Encoder end_cons()
	{
		if (subsequences.empty())
			throw new Invalid_State("end_cons: No such sequence");
		
		SafeVector!ubyte seq = subsequences[subsequences.size()-1].get_contents();
		subsequences.pop_back();
		raw_bytes(seq);
		return this;
	}
	
	/*
	* Start a new ASN.1 EXPLICIT encoding
	*/
	DER_Encoder start_explicit(ushort type_no)
	{
		ASN1_Tag type_tag = cast(ASN1_Tag)(type_no);
		
		if (type_tag == ASN1_Tag.SET)
			throw new Internal_Error("DER_Encoder.start_explicit(SET); cannot perform");
		
		return start_cons(type_tag, ASN1_Tag.CONTEXT_SPECIFIC);
	}
	
	/*
	* Finish the current ASN.1 EXPLICIT encoding
	*/
	DER_Encoder end_explicit()
	{
		return end_cons();
	}
	
	/*
	* Write raw bytes into the stream
	*/
	DER_Encoder raw_bytes(in SafeVector!ubyte val)
	{
		return raw_bytes(&val[0], val.size());
	}
	
	DER_Encoder raw_bytes(in Vector!ubyte val)
	{
		return raw_bytes(&val[0], val.size());
	}
	
	/*
	* Write raw bytes into the stream
	*/
	DER_Encoder raw_bytes(in ubyte* bytes, size_t length)
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
	DER_Encoder encode_null()
	{
		return add_object(ASN1_Tag.NULL_TAG, ASN1_Tag.UNIVERSAL, null, 0);
	}
	
	/*
	* DER encode a BOOLEAN
	*/
	DER_Encoder encode(bool is_true)
	{
		return encode(is_true, ASN1_Tag.BOOLEAN, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode a small INTEGER
	*/
	DER_Encoder encode(size_t n)
	{
		return encode(BigInt(n), ASN1_Tag.INTEGER, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode a small INTEGER
	*/
	DER_Encoder encode(in BigInt n)
	{
		return encode(n, ASN1_Tag.INTEGER, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in SafeVector!ubyte bytes,
	                   ASN1_Tag real_type)
	{
		return encode(&bytes[0], bytes.size(),
		real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in Vector!ubyte bytes,
	                   ASN1_Tag real_type)
	{
		return encode(&bytes[0], bytes.size(),
		real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* Encode this object
	*/
	DER_Encoder encode(in ubyte* bytes, size_t length,
	                   ASN1_Tag real_type)
	{
		return encode(bytes, length, real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode a BOOLEAN
	*/
	DER_Encoder encode(bool is_true,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		ubyte val = is_true ? 0xFF : 0x00;
		return add_object(type_tag, class_tag, &val, 1);
	}
	
	/*
	* DER encode a small INTEGER
	*/
	DER_Encoder encode(size_t n,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(BigInt(n), type_tag, class_tag);
	}
	
	/*
	* DER encode an INTEGER
	*/
	DER_Encoder encode(in BigInt n,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (n == 0)
			return add_object(type_tag, class_tag, 0);
		
		bool extra_zero = (n.bits() % 8 == 0);
		SafeVector!ubyte contents = SafeVector!ubyte(extra_zero + n.bytes());
		BigInt.encode(&contents[extra_zero], n);
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
	DER_Encoder encode(in SafeVector!ubyte bytes,
	                   ASN1_Tag real_type,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(&bytes[0], bytes.size(),
		real_type, type_tag, class_tag);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in Vector!ubyte bytes,
	                   ASN1_Tag real_type,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(&bytes[0], bytes.size(),
		real_type, type_tag, class_tag);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in ubyte* bytes, size_t length,
	                   ASN1_Tag real_type,
	                   ASN1_Tag type_tag, ASN1_Tag class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (real_type != ASN1_Tag.OCTET_STRING && real_type != ASN1_Tag.BIT_STRING)
			throw new Invalid_Argument("DER_Encoder: Invalid tag for ubyte/bit string");
		
		if (real_type == ASN1_Tag.BIT_STRING)
		{
			SafeVector!ubyte encoded;
			encoded.push_back(0);
			encoded += Pair(bytes, length);
			return add_object(type_tag, class_tag, encoded);
		}
		else
			return add_object(type_tag, class_tag, bytes, length);
	}

	/*
	* Request for an object to encode itself
	*/
	DER_Encoder encode(in ASN1_Object obj)
	{
		obj.encode_into(this);
		return this;
	}

	/*
	* Conditionally write some values to the stream
	*/
	DER_Encoder encode_if (bool cond, DER_Encoder codec)
	{
		if (cond)
			return raw_bytes(codec.get_contents());
		return this;
	}
	
	DER_Encoder encode_if (bool cond, const ref ASN1_Object obj)
	{
		if (cond)
			encode(obj);
		return this;
	}

	DER_Encoder encode_optional(T)(in T value, const ref T default_value = T.init)
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

	/*
	* Write the encoding of the ubyte(s)
	*/
	DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
	                       in string rep_str)
	{
		const ubyte* rep = cast(const ubyte*)(rep_str.data());
		const size_t rep_len = rep_str.size();
		return add_object(type_tag, class_tag, rep, rep_len);
	}

	/*
	* Write the encoding of the ubyte(s)
	*/
	DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
	                       in ubyte* rep, size_t length)
	{
		SafeVector!ubyte buffer;
		buffer += encode_tag(type_tag, class_tag);
		buffer += encode_length(length);
		buffer += Pair(rep, length);
		
		return raw_bytes(buffer);
	}

	/*
	* Write the encoding of the ubyte
	*/
	DER_Encoder add_object(ASN1_Tag type_tag,
	                       ASN1_Tag class_tag, ubyte rep)
	{
		return add_object(type_tag, class_tag, &rep, 1);
	}


	DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
							in Vector!ubyte rep)
	{
		return add_object(type_tag, class_tag, &rep[0], rep.size());
	}

	DER_Encoder add_object(ASN1_Tag type_tag, ASN1_Tag class_tag,
							in SafeVector!ubyte rep)
	{
		return add_object(type_tag, class_tag, &rep[0], rep.size());
	}
private:
	class DER_Sequence
	{
	public:
		/*
		* Return the type and class taggings
		*/
		ASN1_Tag tag_of() const
		{
			return ASN1_Tag(type_tag | class_tag);
		}

		/*
		* Return the encoded ASN1_Tag.SEQUENCE/SET
		*/
		SafeVector!ubyte get_contents()
		{
			const ASN1_Tag real_class_tag = ASN1_Tag(class_tag | ASN1_Tag.CONSTRUCTED);
			
			if (type_tag == ASN1_Tag.SET)
			{
				std.algorithm.sort(set_contents.begin(), set_contents.end());
				for (size_t i = 0; i != set_contents.size(); ++i)
					contents += set_contents[i];
				set_contents.clear();
			}
			
			SafeVector!ubyte result;
			result += encode_tag(type_tag, real_class_tag);
			result += encode_length(contents.size());
			result += contents;
			contents.clear();
			
			return result;
		}

		/*
		* Add an encoded value to the ASN1_Tag.SEQUENCE/SET
		*/
		void add_bytes(in ubyte* data, size_t length)
		{
			if (type_tag == ASN1_Tag.SET)
				set_contents.push_back(SafeVector!ubyte(data, data + length));
			else
				contents += Pair(data, length);
		}

		/*
		* DER_Sequence Constructor
		*/
		this(ASN1_Tag t1, ASN1_Tag t2)
		{
			type_tag = t1;
			class_tag = t2;
		}

	private:
		ASN1_Tag type_tag, class_tag;
		SafeVector!ubyte contents;
		Vector!(  SafeVector!ubyte  ) set_contents;
	};

	SafeVector!ubyte contents;
	Vector!( DER_Sequence ) subsequences;
};

/*
* DER encode an ASN.1 type tag
*/
SafeVector!ubyte encode_tag(ASN1_Tag type_tag, ASN1_Tag class_tag)
{
	if ((class_tag | 0xE0) != 0xE0)
		throw new Encoding_Error("DER_Encoder: Invalid class tag " ~
		                         std.conv.to!string(class_tag));
	
	SafeVector!ubyte encoded_tag;
	if (type_tag <= 30)
		encoded_tag.push_back(cast(ubyte)(type_tag | class_tag));
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
SafeVector!ubyte encode_length(size_t length)
{
	SafeVector!ubyte encoded_length;
	if (length <= 127)
		encoded_length.push_back(cast(ubyte)(length));
	else
	{
		const size_t top_byte = significant_bytes(length);
		
		encoded_length.push_back(cast(ubyte)(0x80 | top_byte));
		
		for (size_t i = sizeof(length) - top_byte; i != sizeof(length); ++i)
			encoded_length.push_back(get_byte(i, length));
	}
	return encoded_length;
}