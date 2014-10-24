/*
* Filter interface for Transformations
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.transform_filter;

import botan.algo_base.transform;
import botan.filters.key_filt;
import botan.filters.buf_filt;
import botan.filters.transform_filter;
import botan.utils.rounding;

/**
* Filter interface for Transformations
*/
class Transformation_Filter : Keyed_Filter, Buffered_Filter
{
public:
	this(Transformation transform)
	{
		super(choose_update_size(transform.update_granularity()),
		      transform.minimum_final_size());
		m_nonce = transform.default_nonce_length() == 0;
		m_transform = transform;
		m_buffer = m_transform.update_granularity();
	}

	final void set_iv(in InitializationVector iv)
	{
		m_nonce.update(iv);
	}

	final void set_key(in SymmetricKey key)
	{
		if (Keyed_Transform keyed = cast(Keyed_Transform)(*m_transform))
			keyed.set_key(key);
		else if (key.length() != 0)
			throw new Exception("Transformation " ~ name ~ " does not accept keys");
	}

	final Key_Length_Specification key_spec() const
	{
		if (Keyed_Transform keyed = cast(Keyed_Transform)(*m_transform))
			return keyed.key_spec();
		return Key_Length_Specification(0);
	}

	final bool valid_iv_length(size_t length) const
	{
		return m_transform.valid_nonce_length(length);
	}

	final @property string name() const
	{
		return m_transform.name;
	}

protected:
	final const Transformation get_transform() const { return *m_transform; }

	final Transformation get_transform() { return *m_transform; }

private:
	final void write(in ubyte* input, size_t input_length)
	{
		super.write(input, input_length);
	}	

	final void start_msg()
	{
		send(m_transform.start_vec(m_nonce));
	}

	final void end_msg()
	{
		super.end_msg();
	}

	final void buffered_block(in ubyte* input, size_t input_length)
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

	final void buffered_final(in ubyte* input, size_t input_length)
	{
		Secure_Vector!ubyte buf = Secure_Vector!ubyte(input, input + input_length);
		m_transform.finish(buf);
		send(buf);
	}

	final class Nonce_State
	{
	public:
		this(bool allow_null_nonce)
		{
			m_fresh_nonce = allow_null_nonce;
		}

		void update(in InitializationVector iv)
		{
			m_nonce = unlock(iv.bits_of());
			m_fresh_nonce = true;
		}

		Vector!ubyte get()
		{
			assert(m_fresh_nonce, "The nonce is fresh for this message");
			
			if (!m_nonce.empty)
				m_fresh_nonce = false;
			return m_nonce;
		}
	private:
		bool m_fresh_nonce;
		Vector!ubyte m_nonce;
	};

	Nonce_State m_nonce;
	Unique!Transformation m_transform;
	Secure_Vector!ubyte m_buffer;
};

private:

size_t choose_update_size(size_t update_granularity)
{
	const size_t target_size = 1024;
	
	if (update_granularity >= target_size)
		return update_granularity;
	
	return round_up(target_size, update_granularity);
}