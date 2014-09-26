/*
* BER Decoder
* (C) 1999-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/asn1_oid.h>
#include <botan/data_src.h>
/**
* BER Decoding Object
*/
class BER_Decoder
{
	public:
		BER_Object get_next_object();

		Vector!( byte ) get_next_octet_string();

		void push_back(in BER_Object obj);

		bool more_items() const;
		BER_Decoder verify_end();
		BER_Decoder discard_remaining();

		BER_Decoder  start_cons(ASN1_Tag type_tag, ASN1_Tag class_tag = UNIVERSAL);
		BER_Decoder end_cons();

		BER_Decoder get_next(BER_Object& ber);

		BER_Decoder raw_bytes(SafeVector!byte v);
		BER_Decoder raw_bytes(Vector!( byte )& v);

		BER_Decoder decode_null();
		BER_Decoder decode(bool& v);
		BER_Decoder decode(size_t& v);
		BER_Decoder decode(class BigInt& v);
		BER_Decoder decode(Vector!( byte )& v, ASN1_Tag type_tag);
		BER_Decoder decode(SafeVector!byte v, ASN1_Tag type_tag);

		BER_Decoder decode(bool& v,
								  ASN1_Tag type_tag,
								  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		BER_Decoder decode(size_t& v,
								  ASN1_Tag type_tag,
								  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		BER_Decoder decode(class BigInt& v,
								  ASN1_Tag type_tag,
								  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		BER_Decoder decode(Vector!( byte )& v,
								  ASN1_Tag real_type,
								  ASN1_Tag type_tag,
								  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		BER_Decoder decode(SafeVector!byte v,
								  ASN1_Tag real_type,
								  ASN1_Tag type_tag,
								  ASN1_Tag class_tag = CONTEXT_SPECIFIC);

		BER_Decoder decode(class ASN1_Object& obj,
								  ASN1_Tag type_tag = NO_OBJECT,
								  ASN1_Tag class_tag = NO_OBJECT);

		BER_Decoder decode_octet_string_bigint(class BigInt& b);

		ulong decode_constrained_integer(ASN1_Tag type_tag,
													 ASN1_Tag class_tag,
													 size_t T_bytes);

		BER_Decoder decode_integer_type(T)(ref T output)
		{
			return decode_integer_type<T>(output, INTEGER, UNIVERSAL);
		}

		BER_Decoder decode_integer_type(T)(ref T output,
														ASN1_Tag type_tag,
														ASN1_Tag class_tag = CONTEXT_SPECIFIC)
		{
			output = decode_constrained_integer(type_tag, class_tag, sizeof(output));
			return this;
		}

		BER_Decoder decode_optional(T)(ref T output,
										  ASN1_Tag type_tag,
										  ASN1_Tag class_tag,
										  ref const T default_value = T());

		BER_Decoder decode_optional_implicit(T)(
				ref T output,
				ASN1_Tag type_tag,
				ASN1_Tag class_tag,
				ASN1_Tag real_type,
				ASN1_Tag real_class,
				ref const T default_value = T());

		BER_Decoder decode_list(T)(Vector!( T ) output,
									ASN1_Tag type_tag = SEQUENCE,
									ASN1_Tag class_tag = UNIVERSAL);

		BER_Decoder decode_and_check(T)(in T expected,
										in string error_msg)
		{
			T actual;
			decode(actual);

			if(actual != expected)
				throw new Decoding_Error(error_msg);

			return this;
		}

		/*
		* Decode an OPTIONAL string type
		*/
		BER_Decoder decode_optional_string(Alloc)(Vector!( byte, Alloc ) output,
														ASN1_Tag real_type,
														ushort type_no,
														ASN1_Tag class_tag = CONTEXT_SPECIFIC)
		{
			BER_Object obj = get_next_object();

			ASN1_Tag type_tag = cast(ASN1_Tag)(type_no);

			if(obj.type_tag == type_tag && obj.class_tag == class_tag)
			{
				if((class_tag & CONSTRUCTED) && (class_tag & CONTEXT_SPECIFIC))
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

		BER_Decoder operator=(in BER_Decoder);

		BER_Decoder(DataSource&);

		BER_Decoder(const byte[], size_t);

		BER_Decoder(in SafeVector!byte);

		BER_Decoder(in Vector!byte vec);

		BER_Decoder(in BER_Decoder);
		~BER_Decoder();
	private:
		BER_Decoder* parent;
		DataSource* source;
		BER_Object pushed;
		mutable bool owns;
};

/*
* Decode an OPTIONAL or DEFAULT element
*/
BER_Decoder BER_Decoder::decode_optional(T)(ref T output,
											ASN1_Tag type_tag,
											ASN1_Tag class_tag,
											ref const T default_value)
{
	BER_Object obj = get_next_object();

	if(obj.type_tag == type_tag && obj.class_tag == class_tag)
	{
		if((class_tag & CONSTRUCTED) && (class_tag & CONTEXT_SPECIFIC))
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
BER_Decoder BER_Decoder::decode_optional_implicit(T)(
	ref T output,
	ASN1_Tag type_tag,
	ASN1_Tag class_tag,
	ASN1_Tag real_type,
	ASN1_Tag real_class,
	const T& default_value)
{
	BER_Object obj = get_next_object();

	if(obj.type_tag == type_tag && obj.class_tag == class_tag)
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
BER_Decoder BER_Decoder::decode_list(T)(Vector!( T ) vec,
												  ASN1_Tag type_tag,
												  ASN1_Tag class_tag)
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