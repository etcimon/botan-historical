/*
* Filter interface for Transformations
* (C) 2013,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.transform_filter;
import botan.internal.rounding;
namespace {

size_t choose_update_size(size_t update_granularity)
{
	const size_t target_size = 1024;

	if (update_granularity >= target_size)
		return update_granularity;

	return round_up(target_size, update_granularity);
}

}

Transformation_Filter::Transformation_Filter(Transformation* transform) :
	Buffered_Filter(choose_update_size(transform.update_granularity()),
						 transform.minimum_final_size()),
	m_nonce(transform.default_nonce_length() == 0),
	m_transform(transform),
	m_buffer(m_transform.update_granularity())
{
}

string Transformation_Filter::name() const
{
	return m_transform.name();
}

void Transformation_Filter::Nonce_State::update(in InitializationVector iv)
{
	m_nonce = unlock(iv.bits_of());
	m_fresh_nonce = true;
}

Vector!byte Transformation_Filter::Nonce_State::get()
{
	BOTAN_ASSERT(m_fresh_nonce, "The nonce is fresh for this message");

	if (!m_nonce.empty())
		m_fresh_nonce = false;
	return m_nonce;
}

void Transformation_Filter::set_iv(in InitializationVector iv)
{
	m_nonce.update(iv);
}

void Transformation_Filter::set_key(in SymmetricKey key)
{
	if (Keyed_Transform* keyed = cast(Keyed_Transform*)(m_transform.get()))
		keyed.set_key(key);
	else if (key.length() != 0)
		throw new Exception("Transformation " ~ name() ~ " does not accept keys");
}

Key_Length_Specification Transformation_Filter::key_spec() const
{
	if (Keyed_Transform* keyed = cast(Keyed_Transform*)(m_transform.get()))
		return keyed.key_spec();
	return Key_Length_Specification(0);
}

bool Transformation_Filter::valid_iv_length(size_t length) const
{
	return m_transform.valid_nonce_length(length);
}

void Transformation_Filter::write(in byte* input, size_t input_length)
{
	Buffered_Filter::write(input, input_length);
}

void Transformation_Filter::end_msg()
{
	Buffered_Filter::end_msg();
}

void Transformation_Filter::start_msg()
{
	send(m_transform.start_vec(m_nonce.get()));
}

void Transformation_Filter::buffered_block(in byte* input, size_t input_length)
{
	while(input_length)
	{
		const size_t take = std.algorithm.min(m_transform.update_granularity(), input_length);

		m_buffer.assign(input, input + take);
		m_transform.update(m_buffer);

		send(m_buffer);

		input += take;
		input_length -= take;
	}
}

void Transformation_Filter::buffered_final(in byte* input, size_t input_length)
{
	SafeVector!byte buf(input, input + input_length);
	m_transform.finish(buf);
	send(buf);
}

}
