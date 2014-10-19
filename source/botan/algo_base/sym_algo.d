module botan.algo_base.sym_algo;

import botan.key_spec;
import botan.utils.exceptn;
import botan.algo_base.symkey;
import botan.utils.types;

/**
* This class represents a symmetric algorithm object.
*/
class SymmetricAlgorithm
{
public:
	~this() {}
	
	abstract void clear();
	
	/**
		* @return object describing limits on key size
		*/
	abstract Key_Length_Specification key_spec() const;
	
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
	void set_key(in SymmetricKey key)
	{
		set_key(key.begin(), key.length());
	}
	
	void set_key(Alloc)(in Vector!( ubyte, Alloc ) key)
	{
		set_key(&key[0], key.length);
	}
	
	/**
		* Set the symmetric key of this object.
		* @param key the to be set as a ubyte array.
		* @param length in bytes of key param
		*/
	void set_key(in ubyte* key, size_t length)
	{
		if (!valid_keylength(length))
			throw new Invalid_Key_Length(name(), length);
		key_schedule(key, length);
	}
	
	abstract string name() const;
	
private:
	/**
		* Run the key schedule
		* @param key the key
		* @param length of key
		*/
	abstract void key_schedule(in ubyte* key, size_t length);
};

