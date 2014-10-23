/*
* TLS Data Reader
* (C) 2010-2011,2014 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_reader;

import botan.utils.exceptn;
import botan.alloc.secmem;
import botan.utils.loadstor;
import string;
import botan.utils.types;
import std.exception;

/**
* Helper class for decoding TLS protocol messages
*/
struct TLS_Data_Reader
{
public:
	this(string type, in Vector!ubyte buf_input) 
	{
		m_typename = type;
		m_buf = buf_input; 
		m_offset = 0;
	}

	void assert_done() const
	{
		if (has_remaining())
			throw new decode_error("Extra bytes at end of message");
	}

	size_t remaining_bytes() const
	{
		return m_buf.length - m_offset;
	}

	bool has_remaining() const
	{
		return (remaining_bytes() > 0);
	}

	void discard_next(size_t bytes)
	{
		assert_at_least(bytes);
		m_offset += bytes;
	}

	ushort get_uint()
	{
		assert_at_least(4);
		ushort result = make_uint(m_buf[m_offset  ], m_buf[m_offset+1],
											 m_buf[m_offset+2], m_buf[m_offset+3]);
		m_offset += 4;
		return result;
	}

	ushort get_ushort()
	{
		assert_at_least(2);
		ushort result = make_ushort(m_buf[m_offset], m_buf[m_offset+1]);
		m_offset += 2;
		return result;
	}

	ubyte get_byte()
	{
		assert_at_least(1);
		ubyte result = m_buf[m_offset];
		m_offset += 1;
		return result;
	}

	
	Container get_elem(T, Container)(size_t num_elems)
	{
		assert_at_least(num_elems * (T).sizeof);

		Container result(num_elems);

		for (size_t i = 0; i != num_elems; ++i)
			result[i] = load_be!T(&m_buf[m_offset], i);

		m_offset += num_elems * (T).sizeof;

		return result;
	}

	Vector!T get_range(T)(size_t len_bytes,
							  size_t min_elems,
							  size_t max_elems)
	{
		const size_t num_elems =
			get_num_elems(len_bytes, (T).sizeof, min_elems, max_elems);

		return get_elem!(T, Vector!T)(num_elems);
	}

	Vector!T get_range_vector(T)(size_t len_bytes,
									  size_t min_elems,
									  size_t max_elems)
	{
		const size_t num_elems =
			get_num_elems(len_bytes, (T).sizeof, min_elems, max_elems);

		return get_elem!(T, Vector!T)(num_elems);
	}

	string get_string(size_t len_bytes,
								  size_t min_bytes,
								  size_t max_bytes)
	{
		Vector!ubyte v =
			get_range_vector!ubyte(len_bytes, min_bytes, max_bytes);

		return string(cast(char*)(&v[0]), v.length);
	}

	Vector!T get_fixed(T)(size_t size)
	{
		return get_elem!(T, Vector!T)(size);
	}

private:
	size_t get_length_field(size_t len_bytes)
	{
		assert_at_least(len_bytes);

		if (len_bytes == 1)
			return get_byte();
		else if (len_bytes == 2)
			return get_ushort();

		throw new decode_error("Bad length size");
	}

	size_t get_num_elems(size_t len_bytes,
							size_t T_size,
							size_t min_elems,
							size_t max_elems)
	{
		const size_t byte_length = get_length_field(len_bytes);

		if (byte_length % T_size != 0)
			throw new decode_error("Size isn't multiple of T");

		const size_t num_elems = byte_length / T_size;

		if (num_elems < min_elems || num_elems > max_elems)
			throw new decode_error("Length field outside parameters");

		return num_elems;
	}

	void assert_at_least(size_t n) const
	{
		if (m_buf.length - m_offset < n)
			throw new decode_error("Expected " ~ std.conv.to!string(n) +
									 " bytes remaining, only " ~
									 std.conv.to!string(m_buf.length-m_offset) +
									 " left");
	}

	Decoding_Error decode_error(in string why) const
	{
		return Decoding_Error("Invalid " ~ string(m_typename) ~ ": " ~ why);
	}

	string m_typename;
	const Vector!ubyte m_buf;
	size_t m_offset;
};

/**
* Helper function for encoding length-tagged vectors
*/
void append_tls_length_value(T, Alloc)(ref Vector!( ubyte, Alloc ) buf,
										  const T* vals,
										  size_t vals_size,
										  size_t tag_size)
{
	const size_t T_size = (T).sizeof;
	const size_t val_bytes = T_size * vals_size;

	if (tag_size != 1 && tag_size != 2)
		throw new Invalid_Argument("append_tls_length_value: invalid tag size");

	if ((tag_size == 1 && val_bytes > 255) ||
		(tag_size == 2 && val_bytes > 65535))
		throw new Invalid_Argument("append_tls_length_value: value too large");

	for (size_t i = 0; i != tag_size; ++i)
		buf.push_back(get_byte((val_bytes).sizeof-tag_size+i, val_bytes));

	for (size_t i = 0; i != vals_size; ++i)
		for (size_t j = 0; j != T_size; ++j)
			buf.push_back(get_byte(j, vals[i]));
}

void append_tls_length_value(T, Alloc, Alloc2)(ref Vector!( ubyte, Alloc ) buf,
												  const ref Vector!( T, Alloc2 ) vals,
												  size_t tag_size)
{
	append_tls_length_value(buf, &vals[0], vals.length, tag_size);
}

void append_tls_length_value(Alloc)(ref Vector!( ubyte, Alloc ) buf,
									  in string str,
									  size_t tag_size)
{
	append_tls_length_value(buf,
							cast(const ubyte*)(&str[0]),
							str.length,
							tag_size);
}
