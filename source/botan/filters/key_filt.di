/*
* Keyed_Filter
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/filter.h>
#include <botan/sym_algo.h>
/**
* This class represents keyed filters, i.e. filters that have to be
* fed with a key in order to function.
*/
class Keyed_Filter : public Filter
{
	public:
		/**
		* Set the key of this filter
		* @param key the key to use
		*/
		abstract void set_key(const SymmetricKey& key) = 0;

		/**
		* Set the initialization vector of this filter. Note: you should
		* call set_iv() only after you have called set_key()
		* @param iv the initialization vector to use
		*/
		abstract void set_iv(const InitializationVector& iv);

		/**
		* Check whether a key length is valid for this filter
		* @param length the key length to be checked for validity
		* @return true if the key length is valid, false otherwise
		*/
		bool valid_keylength(size_t length) const
		{
			return key_spec().valid_keylength(length);
		}

		/**
		* @return object describing limits on key size
		*/
		abstract Key_Length_Specification key_spec() const = 0;

		/**
		* Check whether an IV length is valid for this filter
		* @param length the IV length to be checked for validity
		* @return true if the IV length is valid, false otherwise
		*/
		abstract bool valid_iv_length(size_t length) const
		{ return (length == 0); }
};