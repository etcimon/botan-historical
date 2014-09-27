/*
* EAC1_1 objects
* (C) 2008 Falko Strenzke
*
* Distributed under the terms of the botan license.
*/

import botan.signed_obj;
import botan.ecdsa_sig;
/**
* TR03110 v1.1 EAC CV Certificate
*/
// CRTP is used enable the call sequence:
class EAC1_1_obj(Derived) : public EAC_Signed_Object!Derived
{
	public:
		/**
		* Return the signature as a concatenation of the encoded parts.
		* @result the concatenated signature
		*/
		Vector!( byte ) get_concat_sig() const
		{ return m_sig.get_concatenation(); }

		bool check_signature(class Public_Key& key) const
		{
			return EAC_Signed_Object::check_signature(key, m_sig.DER_encode());
		}

	protected:
		ECDSA_Signature m_sig;

		void init(DataSource& input)
		{
			try
			{
				Derived::decode_info(input, tbs_bits, m_sig);
			}
			catch(Decoding_Error)
			{
				throw new Decoding_Error(PEM_label_pref + " decoding failed");
			}
		}

		~this(){}
};