/*
* ChaCha20
* (C) 2014 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.stream.chacha;

import botan.constants;
static if (BOTAN_HAS_CHACHA):

import botan.stream.stream_cipher;
import botan.utils.loadstor;
import botan.utils.rotate;
import botan.utils.xor_buf;
import botan.utils.types;

/**
* DJB's ChaCha (http://cr.yp.to/chacha.html)
*/
final class ChaCha : StreamCipher
{
public:
    /*
    * Combine cipher stream with message
    */
    void cipher(in ubyte* input, ubyte* output, size_t length)
    {
        while (length >= m_buffer.length - m_position)
        {
            xor_buf(output, input, &m_buffer[m_position], m_buffer.length - m_position);
            length -= (m_buffer.length - m_position);
            input += (m_buffer.length - m_position);
            output += (m_buffer.length - m_position);
            chacha(*cast(ubyte[64]*) m_buffer.ptr, *cast(ubyte[64]*) m_state.ptr);
            
            ++m_state[12];
            m_state[13] += (m_state[12] == 0);
            
            m_position = 0;
        }
        
        xor_buf(output, input, &m_buffer[m_position], length);
        
        m_position += length;
    }

    /*
    * Return the name of this type
    */
    void set_iv(in ubyte* iv, size_t length)
    {
        if (!valid_iv_length(length))
            throw new Invalid_IV_Length(name, length);
        
        m_state[12] = 0;
        m_state[13] = 0;
        
        m_state[14] = load_le!uint(iv, 0);
        m_state[15] = load_le!uint(iv, 1);
        
        chacha(*cast(ubyte[64]*) m_buffer.ptr, *cast(ubyte[64]*) m_state.ptr);
        ++m_state[12];
        m_state[13] += (m_state[12] == 0);
        
        m_position = 0;
    }

    bool valid_iv_length(size_t iv_len) const
    { return (iv_len == 8); }

    Key_Length_Specification key_spec() const
    {
        return Key_Length_Specification(16, 32, 16);
    }

    /*
    * Clear memory of sensitive data
    */
    void clear()
    {
        zap(m_state);
        zap(m_buffer);
        m_position = 0;
    }

    /*
    * Return the name of this type
    */
    @property string name() const
    {
        return "ChaCha";
    }

    StreamCipher clone() const { return new ChaCha; }
protected:

    void chacha(ref ubyte[64] output, in uint[16] input)
    {
        uint x00 = input[ 0], x01 = input[ 1], x02 = input[ 2], x03 = input[ 3],
            x04 = input[ 4], x05 = input[ 5], x06 = input[ 6], x07 = input[ 7],
            x08 = input[ 8], x09 = input[ 9], x10 = input[10], x11 = input[11],
            x12 = input[12], x13 = input[13], x14 = input[14], x15 = input[15];
        
        
        foreach (size_t i; 0 .. 10)
        {
            mixin(CHACHA_QUARTER_ROUND!(x00, x04, x08, x12)() ~
                  CHACHA_QUARTER_ROUND!(x01, x05, x09, x13)() ~
                  CHACHA_QUARTER_ROUND!(x02, x06, x10, x14)() ~
                  CHACHA_QUARTER_ROUND!(x03, x07, x11, x15)() ~
                  
                  CHACHA_QUARTER_ROUND!(x00, x05, x10, x15)() ~
                  CHACHA_QUARTER_ROUND!(x01, x06, x11, x12)() ~
                  CHACHA_QUARTER_ROUND!(x02, x07, x08, x13)() ~
                  CHACHA_QUARTER_ROUND!(x03, x04, x09, x14)()
                  );
        }
        
        store_le(x00 + input[ 0], output.ptr + 4 *  0);
        store_le(x01 + input[ 1], output.ptr + 4 *  1);
        store_le(x02 + input[ 2], output.ptr + 4 *  2);
        store_le(x03 + input[ 3], output.ptr + 4 *  3);
        store_le(x04 + input[ 4], output.ptr + 4 *  4);
        store_le(x05 + input[ 5], output.ptr + 4 *  5);
        store_le(x06 + input[ 6], output.ptr + 4 *  6);
        store_le(x07 + input[ 7], output.ptr + 4 *  7);
        store_le(x08 + input[ 8], output.ptr + 4 *  8);
        store_le(x09 + input[ 9], output.ptr + 4 *  9);
        store_le(x10 + input[10], output.ptr + 4 * 10);
        store_le(x11 + input[11], output.ptr + 4 * 11);
        store_le(x12 + input[12], output.ptr + 4 * 12);
        store_le(x13 + input[13], output.ptr + 4 * 13);
        store_le(x14 + input[14], output.ptr + 4 * 14);
        store_le(x15 + input[15], output.ptr + 4 * 15);
    }

private:
    /*
    * ChaCha Key Schedule
    */
    void key_schedule(in ubyte* key, size_t length)
    {
        __gshared immutable uint[] TAU =    [ 0x61707865, 0x3120646e, 0x79622d36, 0x6b206574 ];
        
        __gshared immutable uint[] SIGMA = [ 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 ];
        
        const uint[] CONSTANTS = (length == 16) ? TAU : SIGMA;
        
        m_state.resize(16);
        m_buffer.resize(64);
        
        m_state[0] = CONSTANTS[0];
        m_state[1] = CONSTANTS[1];
        m_state[2] = CONSTANTS[2];
        m_state[3] = CONSTANTS[3];
        
        m_state[4] = load_le!uint(key, 0);
        m_state[5] = load_le!uint(key, 1);
        m_state[6] = load_le!uint(key, 2);
        m_state[7] = load_le!uint(key, 3);
        
        if (length == 32)
            key += 16;
        
        m_state[8] = load_le!uint(key, 0);
        m_state[9] = load_le!uint(key, 1);
        m_state[10] = load_le!uint(key, 2);
        m_state[11] = load_le!uint(key, 3);
        
        m_position = 0;
        
        const ubyte[8] ZERO;
        set_iv(ZERO, ZERO.length);
    }


    Secure_Vector!uint m_state;
    Secure_Vector!ubyte m_buffer;
    size_t m_position = 0;
}

string CHACHA_QUARTER_ROUND(alias _a, alias _b, alias _c, alias _d)()
{
    alias a = __traits(identifier, _a).stringof;
    alias b = __traits(identifier, _b).stringof;
    alias c = __traits(identifier, _c).stringof;
    alias d = __traits(identifier, _d).stringof;

    return a ~ ` += ` ~ b ~ `; ` ~ d ~ ` ^= ` ~ a ~ `; ` ~ d ~ ` = rotate_left(` ~ d ~ `, 16);
                ` ~ c ~ ` += ` ~ d ~ `; ` ~ b ~ ` ^= ` ~ c ~ `; ` ~ b ~ ` = rotate_left(` ~ b ~ `, 12);
                ` ~ a ~ ` += ` ~ b ~ `; ` ~ d ~ ` ^= ` ~ a ~ `; ` ~ d ~ ` = rotate_left(` ~ d ~ `, 8);
                ` ~ c ~ ` += ` ~ d ~ `; ` ~ b ~ ` ^= ` ~ c ~ `; ` ~ b ~ ` = rotate_left(` ~ b ~ `, 7);`;
}
