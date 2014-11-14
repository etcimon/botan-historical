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
import botan.utils.parsing;
import botan.utils.bit_ops;
import botan.utils.types;
import std.algorithm;

import botan.utils.types;

alias DER_Encoder = FreeListRef!BER_Decoder_Impl;


/**
* General DER Encoding Object
*/
class DER_Encoder_Impl
{
public:
	Vector!ubyte get_contents_unlocked()
	{ return unlock(get_contents()); }


	/*
	* Return the encoded m_contents
	*/
	Secure_Vector!ubyte get_contents()
	{
		if (m_subsequences.length != 0)
			throw new Invalid_State("DER_Encoder: Sequence hasn't been marked done");
		
		Secure_Vector!ubyte output;
		std.algorithm.swap(output, m_contents);
		return output;
	}
	
	/*
	* Start a new ASN.1 ASN1_Tag.SEQUENCE/SET/EXPLICIT
	*/
	DER_Encoder start_cons(ASN1_Tag m_type_tag,
	                       ASN1_Tag m_class_tag)
	{
		m_subsequences.push_back(DER_Sequence(m_type_tag, m_class_tag));
		return this;
	}
	
	/*
	* Finish the current ASN.1 ASN1_Tag.SEQUENCE/SET/EXPLICIT
	*/
	DER_Encoder end_cons()
	{
		if (m_subsequences.empty)
			throw new Invalid_State("end_cons: No such sequence");
		
		Secure_Vector!ubyte seq = m_subsequences[m_subsequences.length-1].get_contents();
		m_subsequences.pop_back();
		raw_bytes(seq);
		return this;
	}
	
	/*
	* Start a new ASN.1 EXPLICIT encoding
	*/
	DER_Encoder start_explicit(ushort type_no)
	{
		ASN1_Tag m_type_tag = cast(ASN1_Tag)(type_no);
		
		if (m_type_tag == ASN1_Tag.SET)
			throw new Internal_Error("DER_Encoder.start_explicit(SET); cannot perform");
		
		return start_cons(m_type_tag, ASN1_Tag.CONTEXT_SPECIFIC);
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
	DER_Encoder raw_bytes(in Secure_Vector!ubyte val)
	{
		return raw_bytes(&val[0], val.length);
	}
	
	DER_Encoder raw_bytes(in Vector!ubyte val)
	{
		return raw_bytes(&val[0], val.length);
	}
	
	/*
	* Write raw bytes into the stream
	*/
	DER_Encoder raw_bytes(in ubyte* bytes, size_t length)
	{
		if (m_subsequences.length)
			m_subsequences[m_subsequences.length-1].add_bytes(bytes, length);
		else
			m_contents ~= bytes[0 .. length];
		
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
	DER_Encoder encode(in Secure_Vector!ubyte bytes,
	                   ASN1_Tag real_type)
	{
		return encode(&bytes[0], bytes.length, real_type, real_type, ASN1_Tag.UNIVERSAL);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in Vector!ubyte bytes,
	                   ASN1_Tag real_type)
	{
		return encode(&bytes[0], bytes.length,
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
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		ubyte val = is_true ? 0xFF : 0x00;
		return add_object(m_type_tag, m_class_tag, &val, 1);
	}
	
	/*
	* DER encode a small INTEGER
	*/
	DER_Encoder encode(size_t n,
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(BigInt(n), m_type_tag, m_class_tag);
	}
	
	/*
	* DER encode an INTEGER
	*/
	DER_Encoder encode(in BigInt n,
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (n == 0)
			return add_object(m_type_tag, m_class_tag, 0);
		
		bool extra_zero = (n.bits() % 8 == 0);
		Secure_Vector!ubyte m_contents = Secure_Vector!ubyte(extra_zero + n.bytes());
		BigInt.encode(&m_contents[extra_zero], n);
		if (n < 0)
		{
			foreach (size_t i; 0 .. m_contents.length)
				m_contents[i] = ~m_contents[i];
			for (size_t i = m_contents.length; i > 0; --i)
				if (++m_contents[i-1])
					break;
		}
		
		return add_object(m_type_tag, m_class_tag, m_contents);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in Secure_Vector!ubyte bytes,
	                   ASN1_Tag real_type,
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(&bytes[0], bytes.length, real_type, m_type_tag, m_class_tag);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in Vector!ubyte bytes,
	                   ASN1_Tag real_type,
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		return encode(&bytes[0], bytes.length, real_type, m_type_tag, m_class_tag);
	}
	
	/*
	* DER encode an OCTET STRING or BIT STRING
	*/
	DER_Encoder encode(in ubyte* bytes, size_t length,
	                   ASN1_Tag real_type,
	                   ASN1_Tag m_type_tag, ASN1_Tag m_class_tag = ASN1_Tag.CONTEXT_SPECIFIC)
	{
		if (real_type != ASN1_Tag.OCTET_STRING && real_type != ASN1_Tag.BIT_STRING)
			throw new Invalid_Argument("DER_Encoder: Invalid tag for ubyte/bit string");
		
		if (real_type == ASN1_Tag.BIT_STRING)
		{
			Secure_Vector!ubyte encoded;
			encoded.push_back(0);
			encoded ~= bytes[0 .. length];
			return add_object(m_type_tag, m_class_tag, encoded);
		}
		else
			return add_object(m_type_tag, m_class_tag, bytes, length);
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
		foreach (const value; values[])
			encode(value);
		return this;
	}

	/*
	* Write the encoding of the ubyte(s)
	*/
	DER_Encoder add_object(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag, in string rep_str)
	{
		const ubyte* rep = cast(const ubyte*)(rep_str.data());
		const size_t rep_len = rep_str.length;
		return add_object(m_type_tag, m_class_tag, rep, rep_len);
	}

	/*
	* Write the encoding of the ubyte(s)
	*/
	DER_Encoder add_object(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag, in ubyte* rep, size_t length)
	{
		Secure_Vector!ubyte buffer;
		buffer ~= encode_tag(m_type_tag, m_class_tag);
		buffer ~= encode_length(length);
		buffer ~= rep[0 .. length];
		
		return raw_bytes(buffer);
	}

	/*
	* Write the encoding of the ubyte
	*/
	DER_Encoder add_object(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag, ubyte rep)
	{
		return add_object(m_type_tag, m_class_tag, &rep, 1);
	}


	DER_Encoder add_object(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag, in Vector!ubyte rep)
	{
		return add_object(m_type_tag, m_class_tag, &rep[0], rep.length);
	}

	DER_Encoder add_object(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag, in Secure_Vector!ubyte rep)
	{
		return add_object(m_type_tag, m_class_tag, &rep[0], rep.length);
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
			return ASN1_Tag(m_type_tag | m_class_tag);
		}

		/*
		* Return the encoded ASN1_Tag.SEQUENCE/SET
		*/
		Secure_Vector!ubyte get_contents()
		{
			const ASN1_Tag real_class_tag = ASN1_Tag(m_class_tag | ASN1_Tag.CONSTRUCTED);
			
			if (m_type_tag == ASN1_Tag.SET)
			{	// sort?
				auto set_contents = m_set_contents[];
				sort!("a < b", SwapStrategy.stable)(set_contents);
				foreach (Secure_Vector!ubyte data; set_contents)
					m_contents ~= data;
				m_set_contents.clear();
			}
			
			Secure_Vector!ubyte result;
			result ~= encode_tag(m_type_tag, real_class_tag);
			result ~= encode_length(m_contents.length);
			result ~= m_contents;
			m_contents.clear();
			
			return result;
		}

		/*
		* Add an encoded value to the ASN1_Tag.SEQUENCE/SET
		*/
		void add_bytes(in ubyte* data, size_t length)
		{
			if (m_type_tag == ASN1_Tag.SET)
				m_set_contents.push_back(Secure_Vector!ubyte(data, data + length));
			else
				m_contents ~= data[0 .. length];
		}

		/*
		* DER_Sequence Constructor
		*/
		this(ASN1_Tag t1, ASN1_Tag t2)
		{
			m_type_tag = t1;
			m_class_tag = t2;
		}

	private:

		ASN1_Tag m_type_tag;
		ASN1_Tag m_class_tag;
		Secure_Vector!ubyte m_contents;
		Vector!( Secure_Vector!ubyte ) m_set_contents;
	}

	Secure_Vector!ubyte m_contents;
	Vector!DER_Sequence m_subsequences;
}

/*
* DER encode an ASN.1 type tag
*/
Secure_Vector!ubyte encode_tag(ASN1_Tag m_type_tag, ASN1_Tag m_class_tag)
{
	if ((m_class_tag | 0xE0) != 0xE0)
		throw new Encoding_Error("DER_Encoder: Invalid class tag " ~
		                         to!string(m_class_tag));
	
	Secure_Vector!ubyte encoded_tag;
	if (m_type_tag <= 30)
		encoded_tag.push_back(cast(ubyte)(m_type_tag | m_class_tag));
	else
	{
		size_t blocks = high_bit(m_type_tag) + 6;
		blocks = (blocks - (blocks % 7)) / 7;
		
		encoded_tag.push_back(m_class_tag | 0x1F);
		foreach (size_t i; 0 .. (blocks - 1))
			encoded_tag.push_back(0x80 | ((m_type_tag >> 7*(blocks-i-1)) & 0x7F));
		encoded_tag.push_back(m_type_tag & 0x7F);
	}
	
	return encoded_tag;
}

/*
* DER encode an ASN.1 length field
*/
Secure_Vector!ubyte encode_length(size_t length)
{
	Secure_Vector!ubyte encoded_length;
	if (length <= 127)
		encoded_length.push_back(cast(ubyte)(length));
	else
	{
		const size_t top_byte = significant_bytes(length);
		
		encoded_length.push_back(cast(ubyte)(0x80 | top_byte));
		
		for (size_t i = (length).sizeof - top_byte; i != (length).sizeof; ++i)
			encoded_length.push_back(get_byte(i, length));
	}
	return encoded_length;
}