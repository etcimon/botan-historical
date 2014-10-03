/*
* DER Encoder
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.asn1_obj;
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