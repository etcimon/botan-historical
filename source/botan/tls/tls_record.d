/*
* TLS Record Handling
* (C) 2004-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_record;

import botan.constants;
static if (BOTAN_HAS_TLS):
package:

import botan.libstate.libstate;
import botan.tls.tls_magic;
import botan.tls.tls_version;
import botan.tls.tls_seq_numbers;
import botan.tls.tls_session_key;
import botan.tls.tls_ciphersuite;
import botan.tls.tls_exceptn;
import botan.modes.aead.aead;
import botan.mac.mac;
import botan.algo_factory.algo_factory;
import botan.rng.rng;
import botan.block.block_cipher;
import botan.stream.stream_cipher;
import botan.utils.rounding;
import botan.utils.xor_buf;
import botan.utils.loadstor;
import botan.utils.types;
import std.algorithm;
import std.datetime;

alias Connection_Cipher_State = FreeListRef!Connection_Cipher_State_Impl;

/**
* TLS Cipher State
*/
final class Connection_Cipher_State_Impl
{
public:
    /**
    * Initialize a new cipher state
    */
    this(TLS_Protocol_Version _version, Connection_Side side, bool our_side, in TLS_Ciphersuite suite, in TLS_Session_Keys keys) 
    {
        m_start_time = Clock.currTime();
        m_is_ssl3 = _version == TLS_Protocol_Version.SSL_V3;
        SymmetricKey mac_key, cipher_key;
        InitializationVector iv;
        
        if (side == CLIENT)
        {
            cipher_key = keys.client_cipher_key();
            iv = keys.client_iv();
            mac_key = keys.client_mac_key();
        }
        else
        {
            cipher_key = keys.server_cipher_key();
            iv = keys.server_iv();
            mac_key = keys.server_mac_key();
        }
        
        const string cipher_algo = suite.cipher_algo();
        const string mac_algo = suite.mac_algo();
        
        if (AEAD_Mode aead = get_aead(cipher_algo, our_side ? ENCRYPTION : DECRYPTION))
        {
            m_aead = aead;
            m_aead.set_key(cipher_key + mac_key);
            
            assert(iv.length == 4, "Using 4/8 partial implicit nonce");
            m_nonce = iv.bits_of();
            m_nonce.resize(12);
            return;
        }
        
        Algorithm_Factory af = global_state().algorithm_factory();
        
        if (const BlockCipher bc = af.prototype_block_cipher(cipher_algo))
        {
            m_block_cipher = bc.clone();
            m_block_cipher.set_key(cipher_key);
            m_block_cipher_cbc_state = iv.bits_of();
            m_block_size = bc.block_size;
            
            if (_version.supports_explicit_cbc_ivs())
                m_iv_size = m_block_size;
        }
        else if (const StreamCipher sc = af.prototype_stream_cipher(cipher_algo))
        {
            m_stream_cipher = sc.clone();
            m_stream_cipher.set_key(cipher_key);
        }
        else
            throw new Invalid_Argument("Unknown TLS cipher " ~ cipher_algo);
        
        if (_version == TLS_Protocol_Version.SSL_V3)
            m_mac = af.make_mac("SSL3-MAC(" ~ mac_algo ~ ")");
        else
            m_mac = af.make_mac("HMAC(" ~ mac_algo ~ ")");
        
        m_mac.set_key(mac_key);
    }

    AEAD_Mode aead() { return *m_aead; }

    Secure_Vector!ubyte aead_nonce(ulong seq) const
    {
        assert(m_aead, "Using AEAD mode");
        assert(m_nonce.length == 12, "Expected nonce size");
        store_bigEndian(seq, &m_nonce[4]);
        return m_nonce;
    }

    Secure_Vector!ubyte aead_nonce(in ubyte* record, size_t record_len) const
    {
        assert(m_aead, "Using AEAD mode");
        assert(m_nonce.length == 12, "Expected nonce size");
        assert(record_len >= 8, "Record includes nonce");
        copy_mem(&m_nonce[4], record, 8);
        return m_nonce;
    }


    Secure_Vector!ubyte format_ad(ulong msg_sequence, ubyte msg_type, TLS_Protocol_Version _version, ushort msg_length) const
    {
        m_ad.clear();
        foreach (size_t i; 0 .. 8)
            m_ad.push_back(get_byte(i, msg_sequence));
        m_ad.push_back(msg_type);
        
        if (_version != TLS_Protocol_Version.SSL_V3)
        {
            m_ad.push_back(_version.major_version());
            m_ad.push_back(_version.minor_version());
        }
        
        m_ad.push_back(get_byte(0, msg_length));
        m_ad.push_back(get_byte(1, msg_length));
        
        return m_ad;
    }

    BlockCipher block_cipher() { return *m_block_cipher; }

    StreamCipher stream_cipher() { return *m_stream_cipher; }

    MessageAuthenticationCode mac() { return *m_mac; }

    Secure_Vector!ubyte cbc_state() { return m_block_cipher_cbc_state; }

    @property size_t block_size() const { return m_block_size; }

    size_t mac_size() const { return m_mac.output_length; }

    size_t iv_size() const { return m_iv_size; }

    bool mac_includes_record_version() const { return !m_is_ssl3; }

    bool cipher_padding_single_byte() const { return m_is_ssl3; }

    bool cbc_without_explicit_iv() const
    { return (m_block_size > 0) && (m_iv_size == 0); }

    Duration age() const
    {
        return Clock.currTime() - m_start_time;
    }

private:
    SysTime m_start_time;
    Unique!BlockCipher m_block_cipher;
    Secure_Vector!ubyte m_block_cipher_cbc_state;
    Unique!StreamCipher m_stream_cipher;
    Unique!MessageAuthenticationCode m_mac;

    Unique!AEAD_Mode m_aead;
    Secure_Vector!ubyte m_nonce, m_ad;

    size_t m_block_size;
    size_t m_iv_size;
    bool m_is_ssl3;
}

/**
* Create a TLS record
* @param output = the output record is placed here
* @param msg_type = is the type of the message (handshake, alert, ...)
* @param msg = is the plaintext message
* @param msg_length = is the length of msg
* @param _version = is the protocol version
* @param msg_sequence = is the sequence number
* @param cipherstate = is the writing cipher state
* @param rng = is a random number generator
* @return number of bytes written to write_buffer
*/
void write_record(ref Secure_Vector!ubyte output,
                  ubyte msg_type, in ubyte* msg, size_t msg_length,
                  TLS_Protocol_Version _version,
                  ulong msg_sequence,
                  Connection_Cipher_State cipherstate,
                  RandomNumberGenerator rng)
{
    output.clear();
    
    output.push_back(msg_type);
    output.push_back(_version.major_version());
    output.push_back(_version.minor_version());
    
    if (_version.is_datagram_protocol())
    {
        foreach (size_t i; 0 .. 8)
            output.push_back(get_byte(i, msg_sequence));
    }
    
    if (!cipherstate) // initial unencrypted handshake records
    {
        output.push_back(get_byte!ushort(0, msg_length));
        output.push_back(get_byte!ushort(1, msg_length));
        
        output.insert(output.end(), msg.ptr, &msg[msg_length]);
        
        return;
    }
    
    if (Unique!AEAD_Mode aead = cipherstate.aead())
    {
        const size_t ctext_size = aead.output_length(msg_length);
        
        auto nonce = cipherstate.aead_nonce(msg_sequence);
        const size_t implicit_nonce_bytes = 4; // FIXME, take from ciphersuite
        const size_t explicit_nonce_bytes = 8;
        
        assert(nonce.length == implicit_nonce_bytes + explicit_nonce_bytes, "Expected nonce size");
        
        // wrong if start_vec returns something
        const size_t rec_size = ctext_size + explicit_nonce_bytes;
        
        assert(rec_size <= 0xFFFF, "Ciphertext length fits in field");
        
        output.push_back(get_byte!ushort(0, rec_size));
        output.push_back(get_byte!ushort(1, rec_size));
        
        aead.set_associated_data_vec(cipherstate.format_ad(msg_sequence, msg_type, _version, msg_length));
        
        output ~= nonce.ptr[implicit_nonce_bytes .. implicit_nonce_bytes + explicit_nonce_bytes];
        output ~= aead.start_vec(nonce);
        
        const size_t offset = output.length;
        output ~= msg.ptr[0 .. msg_length];
        aead.finish(output, offset);
        
        assert(output.length == offset + ctext_size, "Expected size");
        
        assert(output.length < MAX_CIPHERTEXT_SIZE,
                     "Produced ciphertext larger than protocol allows");
        return;
    }
    
    cipherstate.mac().update(cipherstate.format_ad(msg_sequence, msg_type, _version, msg_length));
    
    cipherstate.mac().update(msg, msg_length);
    
    const size_t block_size = cipherstate.block_size;
    const size_t iv_size = cipherstate.iv_size();
    const size_t mac_size = cipherstate.mac_size();
    
    const size_t buf_size = round_up(iv_size + msg_length + mac_size + (block_size ? 1 : 0), block_size);
    
    if (buf_size > MAX_CIPHERTEXT_SIZE)
        throw new Internal_Error("Output record is larger than allowed by protocol");
    
    output.push_back(get_byte!ushort(0, buf_size));
    output.push_back(get_byte!ushort(1, buf_size));
    
    const size_t header_size = output.length;
    
    if (iv_size)
    {
        output.resize(output.length + iv_size);
        rng.randomize(&output[$- iv_size], iv_size);
    }
    
    output.insert(output.end(), msg.ptr, &msg[msg_length]);
    
    output.resize(output.length + mac_size);
    cipherstate.mac().flushInto(&output[output.length - mac_size]);
    
    if (block_size)
    {
        const size_t pad_val = buf_size - (iv_size + msg_length + mac_size + 1);
        
        foreach (size_t i; 0 .. (pad_val + 1))
            output.push_back(pad_val);
    }
    
    if (buf_size > MAX_CIPHERTEXT_SIZE)
        throw new Internal_Error("Produced ciphertext larger than protocol allows");
    
    assert(buf_size + header_size == output.length,
                 "Output buffer is sized properly");
    
    if (StreamCipher sc = cipherstate.stream_cipher())
    {
        sc.cipher1(&output[header_size], buf_size);
    }
    else if (BlockCipher bc = cipherstate.block_cipher())
    {
        Secure_Vector!ubyte cbc_state = cipherstate.cbc_state();
        
        assert(buf_size % block_size == 0,
                     "Buffer is an even multiple of block size");
        
        ubyte* buf = &output[header_size];
        
        const size_t blocks = buf_size / block_size;
        
        xor_buf(buf.ptr, cbc_state.ptr, block_size);
        bc.encrypt(buf.ptr);
        
        for (size_t i = 1; i < blocks; ++i)
        {
            xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
            bc.encrypt(&buf[block_size*i]);
        }
        
        cbc_state.replace(buf.ptr[block_size*(blocks-1) .. block_size*blocks]);
    }
    else
        throw new Internal_Error("NULL cipher not supported");
}

/**
* Decode a TLS record
* @return zero if full message, else number of bytes still needed
*/
size_t read_record(Secure_Vector!ubyte readbuf,
                   in ubyte* input, in size_t input_sz,
                   ref size_t consumed,
                   Secure_Vector!ubyte record,
                   ref ulong record_sequence,
                   TLS_Protocol_Version record_version,
                   Record_Type record_type,
                   Connection_Sequence_Numbers sequence_numbers,
                   Connection_Cipher_State delegate(ushort) get_cipherstate)
{
    consumed = 0;
    if (readbuf.length < TLS_HEADER_SIZE) // header incomplete?
    {
        if (size_t needed = fill_buffer_to(readbuf, input, input_sz, consumed, TLS_HEADER_SIZE))
            return needed;
            
            assert(readbuf.length == TLS_HEADER_SIZE,
                           "Have an entire header");
    }
    
    // Possible SSLv2 format client hello
    if (!sequence_numbers && (readbuf[0] & 0x80) && (readbuf[2] == 1))
    {
        if (readbuf[3] == 0 && readbuf[4] == 2)
            throw new TLS_Exception(TLS_Alert.PROTOCOL_VERSION, "TLS_Client claims to only support SSLv2, rejecting");
        
        if (readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
        {
            const size_t record_len = make_ushort(readbuf[0], readbuf[1]) & 0x7FFF;
            
            if (size_t needed = fill_buffer_to(readbuf,
                                               input, input_sz, consumed,
                                               record_len + 2))
                return needed;
            
            assert(readbuf.length == (record_len + 2), "Have the entire SSLv2 hello");
            
            // Fake v3-style handshake message wrapper
            record_version = TLS_Protocol_Version.TLS_V10;
            record_sequence = 0;
            record_type = HANDSHAKE;
            
            record.resize(4 + readbuf.length - 2);
            
            record[0] = CLIENT_HELLO_SSLV2;
            record[1] = 0;
            record[2] = readbuf[0] & 0x7F;
            record[3] = readbuf[1];
            copy_mem(&record[4], &readbuf[2], readbuf.length - 2);
            
            readbuf.clear();
            return 0;
        }
    }

    record_version = TLS_Protocol_Version(readbuf[1], readbuf[2]);
    
    const bool is_dtls = record_version.is_datagram_protocol();
    
    if (is_dtls && readbuf.length < DTLS_HEADER_SIZE)
    {
        if (size_t needed = fill_buffer_to(readbuf, input, input_sz, consumed, DTLS_HEADER_SIZE))
            return needed;
        
        assert(readbuf.length == DTLS_HEADER_SIZE,
                           "Have an entire header");
    }
    
    const size_t header_size = (is_dtls) ? DTLS_HEADER_SIZE : TLS_HEADER_SIZE;
    
    const size_t record_len = make_ushort(readbuf[header_size-2],
    readbuf[header_size-1]);
    
    if (record_len > MAX_CIPHERTEXT_SIZE)
        throw new TLS_Exception(TLS_Alert.RECORD_OVERFLOW, "Got message that exceeds maximum size");
    
    if (size_t needed = fill_buffer_to(readbuf, input, input_sz, consumed, header_size + record_len))
        return needed; // wrong for DTLS?
    
    assert(cast(size_t)(header_size) + record_len == readbuf.length, "Have the full record");
    
    record_type = cast(Record_Type)(readbuf[0]);
    
    ushort epoch = 0;
    
    if (is_dtls)
    {
        record_sequence = load_bigEndian!ulong(&readbuf[3], 0);
        epoch = (record_sequence >> 48);
    }
    else if (sequence_numbers)
    {
        record_sequence = sequence_numbers.next_read_sequence();
        epoch = sequence_numbers.current_read_epoch();
    }
    else
    {
        // server initial handshake case
        record_sequence = 0;
        epoch = 0;
    }

    if (sequence_numbers && sequence_numbers.already_seen(record_sequence))
        return 0;
    
    ubyte* record_contents = &readbuf[header_size];
    
    if (epoch == 0) // Unencrypted initial handshake
    {
        record.replace(readbuf.ptr[header_size .. header_size + record_len]);
        readbuf.clear();
        return 0; // got a full record
    }
    
    // Otherwise, decrypt, check MAC, return plaintext
    Connection_Cipher_State cipherstate = get_cipherstate(epoch);
    
    // FIXME: DTLS reordering might cause us not to have the cipher state
    
    assert(cipherstate, "Have cipherstate for this epoch");
    
    decrypt_record(record,
                   record_contents,
                   record_len,
                   record_sequence,
                   record_version,
                   record_type,
                   cipherstate);
    
    if (sequence_numbers)
        sequence_numbers.read_accept(record_sequence);
    
    readbuf.clear();
    return 0;
}


private:
                    
size_t fill_buffer_to(Secure_Vector!ubyte readbuf, in ubyte* input, 
                      ref size_t input_size, ref size_t input_consumed, 
                      size_t desired)
{
    if (readbuf.length >= desired)
        return 0; // already have it
    
    const size_t taken = std.algorithm.min(input_size, desired - readbuf.length);
    
    readbuf.insert(readbuf.end(), input.ptr, &input[taken]);
    input_consumed += taken;
    input_size -= taken;
    input += taken;
    
    return (desired - readbuf.length); // how many bytes do we still need?
}

/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one ubyte long), or the length
* of the padding otherwise. This is actually padding_length + 1
* because both the padding and padding_length fields are padding from
* our perspective.
*
* Returning 0 in the error case should ensure the MAC check will fail.
* This approach is suggested in section 6.2.3.2 of RFC 5246.
*
* Also returns 0 if block_size == 0, so can be safely called with a
* stream cipher in use.
*
* @fixme This should run in constant time
*/
size_t tls_padding_check(bool sslv3_padding, size_t block_size, in ubyte* record, in size_t record_len)
{
    const size_t padding_length = record[(record_len-1)];

    if (padding_length >= record_len)
        return 0;
    
    /*
    * SSL v3 requires that the padding be less than the block size
    * but not does specify the value of the padding bytes.
    */
    if (sslv3_padding)
    {
        if (padding_length > 0 && padding_length < block_size)
            return (padding_length + 1);
        else
            return 0;
    }
    
    /*
    * TLS v1.0 and up require all the padding bytes be the same value
    * and allows up to 255 bytes.
    */
    const size_t pad_start = record_len - padding_length - 1;
    
    size_t cmp = 0;
    
    foreach (size_t i; 0 .. padding_length)
        cmp += record[pad_start + i] ^ padding_length;
    
    return cmp ? 0 : padding_length + 1;
}

void cbc_decrypt_record(ubyte[] record_contents, Connection_Cipher_State cipherstate, in BlockCipher bc)
{
    size_t record_len = record_contents.length;
    const size_t block_size = cipherstate.block_size;
    
    assert(record_len % block_size == 0, "Buffer is an even multiple of block size");
    
    const size_t blocks = record_len / block_size;
    
    assert(blocks >= 1, "At least one ciphertext block");
    
    ubyte* buf = record_contents.ptr;
    
    Secure_Vector!ubyte last_ciphertext = Secure_Vector!ubyte(block_size);
    copy_mem(last_ciphertext.ptr, buf.ptr, block_size);
    
    bc.decrypt(buf.ptr);
    xor_buf(buf.ptr, &cipherstate.cbc_state()[0], block_size);
    
    Secure_Vector!ubyte last_ciphertext2;
    
    for (size_t i = 1; i < blocks; ++i)
    {
        last_ciphertext2.replace(buf.ptr[block_size*i .. block_size*(i+1)]);
        bc.decrypt(&buf[block_size*i]);
        xor_buf(&buf[block_size*i], last_ciphertext.ptr, block_size);
        std.algorithm.swap(last_ciphertext, last_ciphertext2);
    }
    
    cipherstate.cbc_state() = last_ciphertext;
}

void decrypt_record(Secure_Vector!ubyte output,
                    in ubyte* record_contents, in size_t record_len,
                    ulong record_sequence,
                    TLS_Protocol_Version record_version,
                    Record_Type record_type,
                    Connection_Cipher_State cipherstate)
{
    if (Unique!AEAD_Mode aead = cipherstate.aead())
    {
        auto nonce = cipherstate.aead_nonce(record_contents);
        __gshared immutable size_t nonce_length = 8; // fixme, take from ciphersuite
        
        assert(record_len > nonce_length, "Have data past the nonce");
        const ubyte* msg = &record_contents[nonce_length];
        const size_t msg_length = record_len - nonce_length;
        
        const size_t ptext_size = aead.output_length(msg_length);
        
        aead.set_associated_data_vec(cipherstate.format_ad(record_sequence, record_type, record_version, ptext_size));
        
        output ~= aead.start_vec(nonce);
        
        const size_t offset = output.length;
        output ~= msg[0 .. msg_length];
        aead.finish(output, offset);
        
        assert(output.length == ptext_size + offset, "Produced expected size");
    }
    else
    {
        // GenericBlockCipher / GenericStreamCipher case
        
        bool padding_bad = false;
        size_t pad_size = 0;
        
        if (Unique!StreamCipher sc = cipherstate.stream_cipher())
        {
            sc.cipher1(record_contents, record_len);
            // no padding to check or remove
        }
        else if (Unique!BlockCipher bc = cipherstate.block_cipher())
        {
            cbc_decrypt_record(record_contents, record_len, cipherstate, bc);
            
            pad_size = tls_padding_check(cipherstate.cipher_padding_single_byte(),
                                         cipherstate.block_size,
                                         record_contents, record_len);
            
            padding_bad = (pad_size == 0);
        }
        else
        {
            throw new Internal_Error("No cipher state set but needed to decrypt");
        }
        
        const size_t mac_size = cipherstate.mac_size();
        const size_t iv_size = cipherstate.iv_size();
        
        const size_t mac_pad_iv_size = mac_size + pad_size + iv_size;
        
        if (record_len < mac_pad_iv_size)
            throw new Decoding_Error("Record sent with invalid length");
        
        const ubyte* plaintext_block = &record_contents[iv_size];
        const ushort plaintext_length = record_len - mac_pad_iv_size;
        
        cipherstate.mac().update(cipherstate.format_ad(record_sequence, record_type, record_version, plaintext_length));
        
        cipherstate.mac().update(plaintext_block, plaintext_length);
        
        Vector!ubyte mac_buf = Vector!ubyte(mac_size);
        cipherstate.mac().flushInto(mac_buf.ptr);
        
        const size_t mac_offset = record_len - (mac_size + pad_size);
        
        const bool mac_bad = !same_mem(&record_contents[mac_offset], mac_buf.ptr, mac_size);
        
        if (mac_bad || padding_bad)
            throw new TLS_Exception(TLS_Alert.BAD_RECORD_MAC, "Message authentication failure");
        
        output.replace(plaintext_block[0 .. plaintext_block + plaintext_length]);
    }
}