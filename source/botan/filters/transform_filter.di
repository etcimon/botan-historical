/*
* Filter interface for Transformations
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.algo_base.transform;
import botan.key_filt;
import botan.buf_filt;
/**
* Filter interface for Transformations
*/
class Transformation_Filter : Keyed_Filter,
													 private Buffered_Filter
{
	public:
		Transformation_Filter(Transformation* t);

		override void set_iv(in InitializationVector iv);

		override void set_key(in SymmetricKey key);

		override Key_Length_Specification key_spec() const;

		override bool valid_iv_length(size_t length) const;

		override string name() const;

	package:
		const Transformation& get_transform() const { return *m_transform; }

		Transformation& get_transform() { return *m_transform; }

	private:
		override void write(in ubyte* input, size_t input_length);
		override void start_msg();
		override void end_msg();

		override void buffered_block(in ubyte* input, size_t input_length);
		override void buffered_final(in ubyte* input, size_t input_length);

		class Nonce_State
		{
			public:
				Nonce_State(bool allow_null_nonce) : m_fresh_nonce(allow_null_nonce) {}

				void update(in InitializationVector iv);
				Vector!ubyte get();
			private:
				bool m_fresh_nonce;
				Vector!ubyte m_nonce;
		};

		Nonce_State m_nonce;
		Unique!Transformation m_transform;
		SafeVector!ubyte m_buffer;
};