/*
* Transformations of data
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/secmem.h>
#include <botan/key_spec.h>
#include <botan/exceptn.h>
#include <botan/symkey.h>
#include <string>
#include <vector>
/**
* Interface for general transformations on data
*/
class Transformation
{
	public:
		/**
		* Begin processing a message.
		* @param nonce the per message nonce
		*/
		template<typename Alloc>
		SafeVector!byte start_vec(in Vector!( byte, Alloc ) nonce)
		{
			return start(&nonce[0], nonce.size());
		}

		/**
		* Begin processing a message.
		* @param nonce the per message nonce
		* @param nonce_len length of nonce
		*/
		abstract SafeVector!byte start(in byte[] nonce, size_t nonce_len) = 0;

		/**
		* Process some data. Input must be in size update_granularity() byte blocks.
		* @param blocks in/out paramter which will possibly be resized
		* @param offset an offset into blocks to begin processing
		*/
		abstract void update(SafeVector!byte blocks, size_t offset = 0) = 0;

		/**
		* Complete processing of a message.
		*
		* @param final_block in/out parameter which must be at least
		*		  minimum_final_size() bytes, and will be set to any final output
		* @param offset an offset into final_block to begin processing
		*/
		abstract void finish(SafeVector!byte final_block, size_t offset = 0) = 0;

		/**
		* Returns the size of the output if this transform is used to process a
		* message with input_length bytes. Will throw new if unable to give a precise
		* answer.
		*/
		abstract size_t output_length(size_t input_length) const = 0;

		/**
		* @return size of required blocks to update
		*/
		abstract size_t update_granularity() const = 0;

		/**
		* @return required minimium size to finalize() - may be any
		*			length larger than this.
		*/
		abstract size_t minimum_final_size() const = 0;

		/**
		* Return the default size for a nonce
		*/
		abstract size_t default_nonce_length() const = 0;

		/**
		* Return true iff nonce_len is a valid length for the nonce
		*/
		abstract bool valid_nonce_length(size_t nonce_len) const = 0;

		/**
		* Return some short name describing the provider of this tranformation.
		* Useful in cases where multiple implementations are available (eg,
		* different implementations of AES). Default "core" is used for the
		* 'standard' implementation included in the library.
		*/
		abstract string provider() const { return "core"; }

		abstract string name() const = 0;

		abstract void clear() = 0;

		abstract ~Transformation() {}
};

class Keyed_Transform : public Transformation
{
	public:
		/**
		* @return object describing limits on key size
		*/
		abstract Key_Length_Specification key_spec() const = 0;

		/**
		* Check whether a given key length is valid for this algorithm.
		* @param length the key length to be checked.
		* @return true if the key length is valid.
		*/
		bool valid_keylength(size_t length) const
		{
			return key_spec().valid_keylength(length);
		}

		template<typename Alloc>
		void set_key(in Vector!( byte, Alloc ) key)
		{
			set_key(&key[0], key.size());
		}

		void set_key(in SymmetricKey key)
		{
			set_key(key.begin(), key.length());
		}

		/**
		* Set the symmetric key of this transform
		* @param key contains the key material
		* @param length in bytes of key param
		*/
		void set_key(in byte[] key)
		{
			if(!valid_keylength(length))
				throw new Invalid_Key_Length(name(), length);
			key_schedule(key, length);
		}

	private:
		abstract void key_schedule(in byte[] key) = 0;
};