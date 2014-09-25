/*
* Symmetric Algorithm Base Class
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/key_spec.h>
#include <botan/exceptn.h>
#include <botan/symkey.h>
#include <botan/types.h>
/**
* This class represents a symmetric algorithm object.
*/
class SymmetricAlgorithm
{
	public:
		abstract ~SymmetricAlgorithm() {}

		abstract void clear() = 0;

		/**
		* @return object describing limits on key size
		*/
		abstract Key_Length_Specification key_spec() const = 0;

		/**
		* @return minimum allowed key length
		*/
		size_t maximum_keylength() const
		{
			return key_spec().maximum_keylength();
		}

		/**
		* @return maxmium allowed key length
		*/
		size_t minimum_keylength() const
		{
			return key_spec().minimum_keylength();
		}

		/**
		* Check whether a given key length is valid for this algorithm.
		* @param length the key length to be checked.
		* @return true if the key length is valid.
		*/
		bool valid_keylength(size_t length) const
		{
			return key_spec().valid_keylength(length);
		}

		/**
		* Set the symmetric key of this object.
		* @param key the SymmetricKey to be set.
		*/
		void set_key(const SymmetricKey& key)
		{
			set_key(key.begin(), key.length());
		}

		template<typename Alloc>
		void set_key(const std::vector<byte, Alloc>& key)
		{
			set_key(&key[0], key.size());
		}

		/**
		* Set the symmetric key of this object.
		* @param key the to be set as a byte array.
		* @param length in bytes of key param
		*/
		void set_key(in byte[] key)
		{
			if(!valid_keylength(length))
				throw Invalid_Key_Length(name(), length);
			key_schedule(key, length);
		}

		abstract string name() const = 0;

	private:
		/**
		* Run the key schedule
		* @param key the key
		* @param length of key
		*/
		abstract void key_schedule(in byte[] key) = 0;
};