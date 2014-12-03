/*
* Filter interface for AEAD Modes
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.aead_filt;

import botan.constants;
static if (BOTAN_HAS_AEAD_FILTER):

import botan.filters.transform_filter;
import botan.modes.aead.aead;
/**
* Filter interface for AEAD Modes
*/
final class AEADFilter : Transformation_Filter
{
public:
    this(AEADMode aead)
    {
        super(aead);
    }

    /**
    * Set associated data that is not included in the ciphertext but
    * that should be authenticated. Must be called after setKey
    * and before endMsg.
    *
    * @param ad = the associated data
    * @param ad_len = length of add in bytes
    */
    void setAssociatedData(in ubyte* ad, size_t ad_len)
    {
        (cast(AEADMode)(get_transform())).setAssociatedData(ad, ad_len);
    }
}