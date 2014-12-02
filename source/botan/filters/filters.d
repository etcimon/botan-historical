/*
* Filters
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.filters.filters;

import botan.algo_factory.algo_factory;
import botan.filters.filter;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.hash.hash;
import botan.mac.mac;

public import botan.filters.pipe;
import botan.filters.basefilt;
import botan.filters.key_filt;
import botan.libstate.libstate;
import botan.algo_base.scan_name;

static if (BOTAN_HAS_CODEC_FILTERS) {
  import botan.filters.b64_filt;
  import botan.filters.hex_filt;
}

import std.algorithm;

/**
* Stream Cipher Filter
*/
final class StreamCipher_Filter : Keyed_Filter
{
public:

    @property string name() const { return m_cipher.name; }

    /**
    * Write input data
    * @param input = data
    * @param input_len = length of input in bytes
    */
    void write(in ubyte* input, size_t length)
    {
        while (length)
        {
            size_t copied = std.algorithm.min(length, m_buffer.length);
            m_cipher.cipher(input, m_buffer.ptr, copied);
            send(m_buffer, copied);
            input += copied;
            length -= copied;
        }
    }

    bool valid_iv_length(size_t iv_len) const
    { return m_cipher.valid_iv_length(iv_len); }

    /**
    * Set the initialization vector for this filter.
    * @param iv = the initialization vector to set
    */
    void set_iv(in InitializationVector iv)
    {
        m_cipher.set_iv(iv.ptr, iv.length);
    }


    /**
    * Set the key of this filter.
    * @param key = the key to set
    */
    void set_key(in SymmetricKey key) { m_cipher.set_key(key); }

    override Key_Length_Specification key_spec() const { return m_cipher.key_spec(); }

    /**
    * Construct a stream cipher filter.
    * @param cipher_obj = a cipher object to use
    */
    this(StreamCipher stream_cipher)
    {
        m_buffer = DEFAULT_BUFFERSIZE;
        m_cipher = stream_cipher;
    }


    /**
    * Construct a stream cipher filter.
    * @param cipher_obj = a cipher object to use
    * @param key = the key to use inside this filter
    */
    this(StreamCipher stream_cipher, in SymmetricKey key)
    {
        m_buffer = DEFAULT_BUFFERSIZE;
        m_cipher = stream_cipher;
        m_cipher.set_key(key);
    }

    /**
    * Construct a stream cipher filter.
    * @param cipher = the name of the desired cipher
    */
    this(in string sc_name)
        
    {
        m_buffer = DEFAULT_BUFFERSIZE;
        Algorithm_Factory af = global_state().algorithm_factory();
        m_cipher = af.make_stream_cipher(sc_name);
    }

    /**
    * Construct a stream cipher filter.
    * @param cipher = the name of the desired cipher
    * @param key = the key to use inside this filter
    */
    this(in string sc_name, in SymmetricKey key)
    {
        m_buffer = DEFAULT_BUFFERSIZE;
        Algorithm_Factory af = global_state().algorithm_factory();
        m_cipher = af.make_stream_cipher(sc_name);
        m_cipher.set_key(key);
    }

    ~this() { delete m_cipher; }
private:
    Secure_Vector!ubyte m_buffer;
    StreamCipher m_cipher;
}

/**
* Hash Filter.
*/
final class Hash_Filter : Filter
{
public:
    void write(in ubyte* input, size_t len) { m_hash.update(input, len); }

    /*
    * Complete a calculation by a Hash_Filter
    */
    void end_msg()
    {
        Secure_Vector!ubyte output = m_hash.finished();
        if (m_OUTPUT_LENGTH)
            send(output, std.algorithm.min(m_OUTPUT_LENGTH, output.length));
        else
            send(output);
    }

    @property string name() const { return m_hash.name; }

    /**
    * Construct a hash filter.
    * @param hash_fun = the hash function to use
    * @param len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the hashfunction
    * hash. Otherwise, specify a smaller value here so that the
    * output of the hash algorithm will be cut off.
    */
    this(HashFunction hash_fun, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        m_hash = hash_fun;
    }

    /**
    * Construct a hash filter.
    * @param request = the name of the hash algorithm to use
    * @param len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the hashfunction
    * hash. Otherwise, specify a smaller value here so that the
    * output of the hash algorithm will be cut off.
    */
    this(in string algo_spec, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        Algorithm_Factory af = global_state().algorithm_factory();
        m_hash = af.make_hash_function(algo_spec);
    }

    ~this() { delete m_hash; }
private:
    const size_t m_OUTPUT_LENGTH;
    HashFunction m_hash;
}

/**
* MessageAuthenticationCode Filter.
*/
final class MAC_Filter : Keyed_Filter
{
public:
    void write(in ubyte* input, size_t len) { m_mac.update(input, len); }

    /*
    * Complete a calculation by a MAC_Filter
    */
    void end_msg()
    {
        Secure_Vector!ubyte output = m_mac.finished();
        if (m_OUTPUT_LENGTH)
            send(output, std.algorithm.min(m_OUTPUT_LENGTH, output.length));
        else
            send(output);
    }

    @property string name() const { return m_mac.name; }

    /**
    * Set the key of this filter.
    * @param key = the key to set
    */
    void set_key(in SymmetricKey key) { m_mac.set_key(key); }

    override Key_Length_Specification key_spec() const { return m_mac.key_spec(); }

    /**
    * Construct a MAC filter. The MAC key will be left empty.
    * @param mac_obj = the MAC to use
    * @param out_len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(MessageAuthenticationCode mac_obj, size_t out_len = 0) 
    {
        m_OUTPUT_LENGTH = out_len;
        m_mac = mac_obj;
    }

    /**
    * Construct a MAC filter.
    * @param mac_obj = the MAC to use
    * @param key = the MAC key to use
    * @param out_len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(MessageAuthenticationCode mac_obj, in SymmetricKey key, size_t out_len = 0)
    {
        m_OUTPUT_LENGTH = out_len;
        m_mac = mac_obj;
        m_mac.set_key(key);
    }

    /**
    * Construct a MAC filter. The MAC key will be left empty.
    * @param mac = the name of the MAC to use
    * @param len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(in string mac_name, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        Algorithm_Factory af = global_state().algorithm_factory();
        m_mac = af.make_mac(mac_name);
    }

    /**
    * Construct a MAC filter.
    * @param mac = the name of the MAC to use
    * @param key = the MAC key to use
    * @param len = the output length of this filter. Leave the default
    * value 0 if you want to use the full output of the
    * MAC. Otherwise, specify a smaller value here so that the
    * output of the MAC will be cut off.
    */
    this(in string mac_name, in SymmetricKey key, size_t len = 0)
    {
        m_OUTPUT_LENGTH = len;
        Algorithm_Factory af = global_state().algorithm_factory();
        m_mac = af.make_mac(mac_name);
        m_mac.set_key(key);
    }

    ~this() { delete m_mac; }
private:
    const size_t m_OUTPUT_LENGTH;
    MessageAuthenticationCode m_mac;
}