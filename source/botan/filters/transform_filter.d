/*
* Filter interface for Transformations
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.transform_filter;

import botan.algo_base.transform;
import botan.filters.key_filt;
import botan.filters.buf_filt;
import botan.filters.transform_filter;
import botan.utils.rounding;

/**
* Filter interface for Transformations
*/
class TransformationFilter : KeyedFilter, BufferedFilter
{
public:
    this(Transformation transform)
    {
        super(chooseUpdateSize(transform.updateGranularity()),
              transform.minimumFinalSize());
        m_nonce = transform.defaultNonceLength() == 0;
        m_transform = transform;
        m_buffer = m_transform.updateGranularity();
    }

    final void setIv(in InitializationVector iv)
    {
        m_nonce.update(iv);
    }

    final void setKey(in SymmetricKey key)
    {
        if (KeyedTransform keyed = cast(KeyedTransform)(*m_transform))
            keyed.setKey(key);
        else if (key.length != 0)
            throw new Exception("Transformation " ~ name ~ " does not accept keys");
    }

    final KeyLengthSpecification keySpec() const
    {
        if (KeyedTransform keyed = cast(KeyedTransform)(*m_transform))
            return keyed.keySpec();
        return KeyLengthSpecification(0);
    }

    final bool validIvLength(size_t length) const
    {
        return m_transform.validNonceLength(length);
    }

    final @property string name() const
    {
        return m_transform.name;
    }

protected:
    final Transformation getTransform() const { return *m_transform; }

    final Transformation getTransform() { return *m_transform; }

private:
    final void write(in ubyte* input, size_t input_length)
    {
        super.write(input, input_length);
    }    

    final void startMsg()
    {
        send(m_transform.startVec(m_nonce));
    }

    final void endMsg()
    {
        super.endMsg();
    }

    final void bufferedBlock(in ubyte* input, size_t input_length)
    {
        while (input_length)
        {
            const size_t take = std.algorithm.min(m_transform.updateGranularity(), input_length);
            
            m_buffer.replace(input[0 .. input + take]);
            m_transform.update(m_buffer);
            
            send(m_buffer);
            
            input += take;
            input_length -= take;
        }
    }

    final void bufferedFinal(in ubyte* input, size_t input_length)
    {
        SecureVector!ubyte buf = SecureVector!ubyte(input, input + input_length);
        m_transform.finish(buf);
        send(buf);
    }

    final class NonceState
    {
    public:
        this(bool allow_null_nonce)
        {
            m_fresh_nonce = allow_null_nonce;
        }

        void update(in InitializationVector iv)
        {
            m_nonce = unlock(iv.bitsOf());
            m_fresh_nonce = true;
        }

        Vector!ubyte get()
        {
            assert(m_fresh_nonce, "The nonce is fresh for this message");
            
            if (!m_nonce.empty)
                m_fresh_nonce = false;
            return m_nonce;
        }
    private:
        bool m_fresh_nonce;
        Vector!ubyte m_nonce;
    }

    NonceState m_nonce;
    Unique!Transformation m_transform;
    SecureVector!ubyte m_buffer;
}

private:

size_t chooseUpdateSize(size_t update_granularity)
{
    const size_t target_size = 1024;
    
    if (update_granularity >= target_size)
        return update_granularity;
    
    return round_up(target_size, update_granularity);
}