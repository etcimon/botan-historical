/*
* Filter interface for Transformations
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.transform;
import botan.key_filt;
import botan.buf_filt;
/**
* Filter interface for Transformations
*/
class Transformation_Filter : public Keyed_Filter,
													 private Buffered_Filter
{
	public:
		Transformation_Filter(Transformation* t);

		void set_iv(in InitializationVector iv) override;

		void set_key(in SymmetricKey key) override;

		Key_Length_Specification key_spec() const override;

		bool valid_iv_length(size_t length) const override;

		string name() const override;

	protected:
		const Transformation& get_transform() const { return *m_transform; }

		Transformation& get_transform() { return *m_transform; }

	private:
		void write(in byte* input, size_t input_length) override;
		void start_msg() override;
		void end_msg() override;

		void buffered_block(in byte* input, size_t input_length) override;
		void buffered_final(in byte* input, size_t input_length) override;

		class Nonce_State
		{
			public:
				Nonce_State(bool allow_null_nonce) : m_fresh_nonce(allow_null_nonce) {}

				void update(in InitializationVector iv);
				Vector!( byte ) get();
			private:
				bool m_fresh_nonce;
				Vector!( byte ) m_nonce;
		};

		Nonce_State m_nonce;
		Unique!Transformation m_transform;
		SafeVector!byte m_buffer;
};