module botan.algo_base.sym_algo;

import botan.utils.exceptn;
public import botan.algo_base.key_spec;
public import botan.algo_base.symkey;
public import botan.utils.types;

/**
* This class represents a symmetric algorithm object.
*/
interface SymmetricAlgorithm
{
public:
    abstract void clear();
    
    /**
        * @return object describing limits on key size
        */
    abstract KeyLengthSpecification keySpec() const;
    
    /**
    * @return minimum allowed key length
    */
    final size_t maximumKeylength() const
    {
        return keySpec().maximumKeylength();
    }
    
    /**
    * @return maxmium allowed key length
    */
    final size_t minimumKeylength() const
    {
        return keySpec().minimumKeylength();
    }
    
    /**
    * Check whether a given key length is valid for this algorithm.
    * @param length = the key length to be checked.
    * @return true if the key length is valid.
    */
    final bool validKeylength(size_t length) const
    {
        return keySpec().validKeylength(length);
    }
    
    /**
    * Set the symmetric key of this object.
    * @param key = the SymmetricKey to be set.
    */
    final void setKey(in SymmetricKey key)
    {
        setKey(key.ptr, key.length);
    }
    
    final void setKey(Alloc)(in Vector!( ubyte, Alloc ) key)
    {
        setKey(key.ptr, key.length);
    }
    
    /**
    * Set the symmetric key of this object.
    * @param key = the to be set as a ubyte array.
    * @param length = in bytes of key param
    */
    final void setKey(in ubyte* key, size_t length)
    {
        if (!validKeylength(length))
            throw new InvalidKeyLength(name, length);
        keySchedule(key, length);
    }

    abstract @property string name() const;
    
protected:
    /**
    * Run the key schedule
    * @param key = the key
    * @param length = of key
    */
    abstract void keySchedule(in ubyte* key, size_t length);
}

