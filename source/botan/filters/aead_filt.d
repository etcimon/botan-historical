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
final class AEADFilter : TransformationFilter, Filterable
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
    void setAssociatedData(const(ubyte)* ad, size_t ad_len)
    {
        (cast(AEADMode)(getTransform())).setAssociatedData(ad, ad_len);
    }

    // void setNext(Filter f, size_t n) { super.setNext(&f, 1); }

    override bool attachable() { return super.attachable(); }

    override @property string name() const { return super.name; }
    override void write(const(ubyte)* input, size_t len) { return super.write(input, len); }

    override void startMsg() { super.startMsg(); }
    override void endMsg() { super.endMsg(); }
    override void setNext(Filter* filters, size_t sz) { super.setNext(filters, sz); }

}