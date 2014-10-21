/*
* Filter interface for AEAD Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.aead_filt;

import botan.filters.transform_filter;
import botan.modes.aead.aead;
/**
* Filter interface for AEAD Modes
*/
class AEAD_Filter : Transformation_Filter
{
public:
	this(AEAD_Mode aead)
	{
		super(aead);
	}

	/**
	* Set associated data that is not included in the ciphertext but
	* that should be authenticated. Must be called after set_key
	* and before end_msg.
	*
	* @param ad the associated data
	* @param ad_len length of add in bytes
	*/
	void set_associated_data(in ubyte* ad, size_t ad_len)
	{
		(cast(AEAD_Mode)(get_transform())).set_associated_data(ad, ad_len);
	}
};