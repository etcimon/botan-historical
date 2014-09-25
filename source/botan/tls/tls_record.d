/*
* TLS Record Handling
* (C) 2012,2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_record.h>
#include <botan/tls_ciphersuite.h>
#include <botan/tls_exceptn.h>
#include <botan/libstate.h>
#include <botan/loadstor.h>
#include <botan/internal/tls_seq_numbers.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/rounding.h>
#include <botan/internal/xor_buf.h>

namespace Botan {

namespace TLS {

Connection_Cipher_State::Connection_Cipher_State(Protocol_Version version,
                                                 Connection_Side side,
                                                 bool our_side,
                                                 const Ciphersuite& suite,
                                                 const Session_Keys& keys) :
   m_start_time(std::chrono::system_clock::now()),
   m_is_ssl3(version == Protocol_Version::SSL_V3)
   {
   SymmetricKey mac_key, cipher_key;
   InitializationVector iv;

   if(side == CLIENT)
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

   const std::string cipher_algo = suite.cipher_algo();
   const std::string mac_algo = suite.mac_algo();

   if(AEAD_Mode* aead = get_aead(cipher_algo, our_side ? ENCRYPTION : DECRYPTION))
      {
      m_aead.reset(aead);
      m_aead->set_key(cipher_key + mac_key);

      BOTAN_ASSERT(iv.length() == 4, "Using 4/8 partial implicit nonce");
      m_nonce = iv.bits_of();
      m_nonce.resize(12);
      return;
      }

   Algorithm_Factory& af = global_state().algorithm_factory();

   if(const BlockCipher* bc = af.prototype_block_cipher(cipher_algo))
      {
      m_block_cipher.reset(bc->clone());
      m_block_cipher->set_key(cipher_key);
      m_block_cipher_cbc_state = iv.bits_of();
      m_block_size = bc->block_size();

      if(version.supports_explicit_cbc_ivs())
         m_iv_size = m_block_size;
      }
   else if(const StreamCipher* sc = af.prototype_stream_cipher(cipher_algo))
      {
      m_stream_cipher.reset(sc->clone());
      m_stream_cipher->set_key(cipher_key);
      }
   else
      throw Invalid_Argument("Unknown TLS cipher " + cipher_algo);

   if(version == Protocol_Version::SSL_V3)
      m_mac.reset(af.make_mac("SSL3-MAC(" + mac_algo + ")"));
   else
      m_mac.reset(af.make_mac("HMAC(" + mac_algo + ")"));

   m_mac->set_key(mac_key);
   }

const secure_vector<byte>& Connection_Cipher_State::aead_nonce(u64bit seq)
   {
   BOTAN_ASSERT(m_aead, "Using AEAD mode");
   BOTAN_ASSERT(m_nonce.size() == 12, "Expected nonce size");
   store_be(seq, &m_nonce[4]);
   return m_nonce;
   }

const secure_vector<byte>&
Connection_Cipher_State::aead_nonce(const byte record[], size_t record_len)
   {
   BOTAN_ASSERT(m_aead, "Using AEAD mode");
   BOTAN_ASSERT(m_nonce.size() == 12, "Expected nonce size");
   BOTAN_ASSERT(record_len >= 8, "Record includes nonce");
   copy_mem(&m_nonce[4], record, 8);
   return m_nonce;
   }

const secure_vector<byte>&
Connection_Cipher_State::format_ad(u64bit msg_sequence,
                                   byte msg_type,
                                   Protocol_Version version,
                                   u16bit msg_length)
   {
   m_ad.clear();
   for(size_t i = 0; i != 8; ++i)
      m_ad.push_back(get_byte(i, msg_sequence));
   m_ad.push_back(msg_type);

   if(version != Protocol_Version::SSL_V3)
      {
      m_ad.push_back(version.major_version());
      m_ad.push_back(version.minor_version());
      }

   m_ad.push_back(get_byte(0, msg_length));
   m_ad.push_back(get_byte(1, msg_length));

   return m_ad;
   }

void write_record(secure_vector<byte>& output,
                  byte msg_type, const byte msg[], size_t msg_length,
                  Protocol_Version version,
                  u64bit msg_sequence,
                  Connection_Cipher_State* cipherstate,
                  RandomNumberGenerator& rng)
   {
   output.clear();

   output.push_back(msg_type);
   output.push_back(version.major_version());
   output.push_back(version.minor_version());

   if(version.is_datagram_protocol())
      {
      for(size_t i = 0; i != 8; ++i)
         output.push_back(get_byte(i, msg_sequence));
      }

   if(!cipherstate) // initial unencrypted handshake records
      {
      output.push_back(get_byte<u16bit>(0, msg_length));
      output.push_back(get_byte<u16bit>(1, msg_length));

      output.insert(output.end(), &msg[0], &msg[msg_length]);

      return;
      }

   if(AEAD_Mode* aead = cipherstate->aead())
      {
      const size_t ctext_size = aead->output_length(msg_length);

      auto nonce = cipherstate->aead_nonce(msg_sequence);
      const size_t implicit_nonce_bytes = 4; // FIXME, take from ciphersuite
      const size_t explicit_nonce_bytes = 8;

      BOTAN_ASSERT(nonce.size() == implicit_nonce_bytes + explicit_nonce_bytes,
                   "Expected nonce size");

      // wrong if start_vec returns something
      const size_t rec_size = ctext_size + explicit_nonce_bytes;

      BOTAN_ASSERT(rec_size <= 0xFFFF, "Ciphertext length fits in field");

      output.push_back(get_byte<u16bit>(0, rec_size));
      output.push_back(get_byte<u16bit>(1, rec_size));

      aead->set_associated_data_vec(
         cipherstate->format_ad(msg_sequence, msg_type, version, msg_length)
         );

      output += std::make_pair(&nonce[implicit_nonce_bytes], explicit_nonce_bytes);
      output += aead->start_vec(nonce);

      const size_t offset = output.size();
      output += std::make_pair(&msg[0], msg_length);
      aead->finish(output, offset);

      BOTAN_ASSERT(output.size() == offset + ctext_size, "Expected size");

      BOTAN_ASSERT(output.size() < MAX_CIPHERTEXT_SIZE,
                   "Produced ciphertext larger than protocol allows");
      return;
      }

   cipherstate->mac()->update(
      cipherstate->format_ad(msg_sequence, msg_type, version, msg_length)
      );

   cipherstate->mac()->update(msg, msg_length);

   const size_t block_size = cipherstate->block_size();
   const size_t iv_size = cipherstate->iv_size();
   const size_t mac_size = cipherstate->mac_size();

   const size_t buf_size = round_up(
      iv_size + msg_length + mac_size + (block_size ? 1 : 0),
      block_size);

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Output record is larger than allowed by protocol");

   output.push_back(get_byte<u16bit>(0, buf_size));
   output.push_back(get_byte<u16bit>(1, buf_size));

   const size_t header_size = output.size();

   if(iv_size)
      {
      output.resize(output.size() + iv_size);
      rng.randomize(&output[output.size() - iv_size], iv_size);
      }

   output.insert(output.end(), &msg[0], &msg[msg_length]);

   output.resize(output.size() + mac_size);
   cipherstate->mac()->final(&output[output.size() - mac_size]);

   if(block_size)
      {
      const size_t pad_val =
         buf_size - (iv_size + msg_length + mac_size + 1);

      for(size_t i = 0; i != pad_val + 1; ++i)
         output.push_back(pad_val);
      }

   if(buf_size > MAX_CIPHERTEXT_SIZE)
      throw Internal_Error("Produced ciphertext larger than protocol allows");

   BOTAN_ASSERT(buf_size + header_size == output.size(),
                "Output buffer is sized properly");

   if(StreamCipher* sc = cipherstate->stream_cipher())
      {
      sc->cipher1(&output[header_size], buf_size);
      }
   else if(BlockCipher* bc = cipherstate->block_cipher())
      {
      secure_vector<byte>& cbc_state = cipherstate->cbc_state();

      BOTAN_ASSERT(buf_size % block_size == 0,
                   "Buffer is an even multiple of block size");

      byte* buf = &output[header_size];

      const size_t blocks = buf_size / block_size;

      xor_buf(&buf[0], &cbc_state[0], block_size);
      bc->encrypt(&buf[0]);

      for(size_t i = 1; i < blocks; ++i)
         {
         xor_buf(&buf[block_size*i], &buf[block_size*(i-1)], block_size);
         bc->encrypt(&buf[block_size*i]);
         }

      cbc_state.assign(&buf[block_size*(blocks-1)],
                       &buf[block_size*blocks]);
      }
   else
      throw Internal_Error("NULL cipher not supported");
   }

namespace {

size_t fill_buffer_to(secure_vector<byte>& readbuf,
                      const byte*& input,
                      size_t& input_size,
                      size_t& input_consumed,
                      size_t desired)
   {
   if(readbuf.size() >= desired)
      return 0; // already have it

   const size_t taken = std::min(input_size, desired - readbuf.size());

   readbuf.insert(readbuf.end(), &input[0], &input[taken]);
   input_consumed += taken;
   input_size -= taken;
   input += taken;

   return (desired - readbuf.size()); // how many bytes do we still need?
   }

/*
* Checks the TLS padding. Returns 0 if the padding is invalid (we
* count the padding_length field as part of the padding size so a
* valid padding will always be at least one byte long), or the length
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
size_t tls_padding_check(bool sslv3_padding,
                         size_t block_size,
                         const byte record[],
                         size_t record_len)
   {
   const size_t padding_length = record[(record_len-1)];

   if(padding_length >= record_len)
      return 0;

   /*
   * SSL v3 requires that the padding be less than the block size
   * but not does specify the value of the padding bytes.
   */
   if(sslv3_padding)
      {
      if(padding_length > 0 && padding_length < block_size)
         return (padding_length + 1);
      else
         return 0;
      }

   /*
   * TLS v1.0 and up require all the padding bytes be the same value
   * and allows up to 255 bytes.
   */
   const size_t pad_start = record_len - padding_length - 1;

   volatile size_t cmp = 0;

   for(size_t i = 0; i != padding_length; ++i)
      cmp += record[pad_start + i] ^ padding_length;

   return cmp ? 0 : padding_length + 1;
   }

void cbc_decrypt_record(byte record_contents[], size_t record_len,
                        Connection_Cipher_State& cipherstate,
                        const BlockCipher& bc)
   {
   const size_t block_size = cipherstate.block_size();

   BOTAN_ASSERT(record_len % block_size == 0,
                "Buffer is an even multiple of block size");

   const size_t blocks = record_len / block_size;

   BOTAN_ASSERT(blocks >= 1, "At least one ciphertext block");

   byte* buf = record_contents;

   secure_vector<byte> last_ciphertext(block_size);
   copy_mem(&last_ciphertext[0], &buf[0], block_size);

   bc.decrypt(&buf[0]);
   xor_buf(&buf[0], &cipherstate.cbc_state()[0], block_size);

   secure_vector<byte> last_ciphertext2;

   for(size_t i = 1; i < blocks; ++i)
      {
      last_ciphertext2.assign(&buf[block_size*i], &buf[block_size*(i+1)]);
      bc.decrypt(&buf[block_size*i]);
      xor_buf(&buf[block_size*i], &last_ciphertext[0], block_size);
      std::swap(last_ciphertext, last_ciphertext2);
      }

   cipherstate.cbc_state() = last_ciphertext;
   }

void decrypt_record(secure_vector<byte>& output,
                    byte record_contents[], size_t record_len,
                    u64bit record_sequence,
                    Protocol_Version record_version,
                    Record_Type record_type,
                    Connection_Cipher_State& cipherstate)
   {
   if(AEAD_Mode* aead = cipherstate.aead())
      {
      auto nonce = cipherstate.aead_nonce(record_contents, record_len);
      const size_t nonce_length = 8; // fixme, take from ciphersuite

      BOTAN_ASSERT(record_len > nonce_length, "Have data past the nonce");
      const byte* msg = &record_contents[nonce_length];
      const size_t msg_length = record_len - nonce_length;

      const size_t ptext_size = aead->output_length(msg_length);

      aead->set_associated_data_vec(
         cipherstate.format_ad(record_sequence, record_type, record_version, ptext_size)
         );

      output += aead->start_vec(nonce);

      const size_t offset = output.size();
      output += std::make_pair(&msg[0], msg_length);
      aead->finish(output, offset);

      BOTAN_ASSERT(output.size() == ptext_size + offset, "Produced expected size");
      }
   else
      {
      // GenericBlockCipher / GenericStreamCipher case

      volatile bool padding_bad = false;
      size_t pad_size = 0;

      if(StreamCipher* sc = cipherstate.stream_cipher())
         {
         sc->cipher1(record_contents, record_len);
         // no padding to check or remove
         }
      else if(BlockCipher* bc = cipherstate.block_cipher())
         {
         cbc_decrypt_record(record_contents, record_len, cipherstate, *bc);

         pad_size = tls_padding_check(cipherstate.cipher_padding_single_byte(),
                                      cipherstate.block_size(),
                                      record_contents, record_len);

         padding_bad = (pad_size == 0);
         }
      else
         {
         throw Internal_Error("No cipher state set but needed to decrypt");
         }

      const size_t mac_size = cipherstate.mac_size();
      const size_t iv_size = cipherstate.iv_size();

      const size_t mac_pad_iv_size = mac_size + pad_size + iv_size;

      if(record_len < mac_pad_iv_size)
         throw Decoding_Error("Record sent with invalid length");

      const byte* plaintext_block = &record_contents[iv_size];
      const u16bit plaintext_length = record_len - mac_pad_iv_size;

      cipherstate.mac()->update(
         cipherstate.format_ad(record_sequence, record_type, record_version, plaintext_length)
         );

      cipherstate.mac()->update(plaintext_block, plaintext_length);

      std::vector<byte> mac_buf(mac_size);
      cipherstate.mac()->final(&mac_buf[0]);

      const size_t mac_offset = record_len - (mac_size + pad_size);

      const bool mac_bad = !same_mem(&record_contents[mac_offset], &mac_buf[0], mac_size);

      if(mac_bad || padding_bad)
         throw TLS_Exception(Alert::BAD_RECORD_MAC, "Message authentication failure");

      output.assign(plaintext_block, plaintext_block + plaintext_length);
      }
   }

}

size_t read_record(secure_vector<byte>& readbuf,
                   const byte input[],
                   size_t input_sz,
                   size_t& consumed,
                   secure_vector<byte>& record,
                   u64bit* record_sequence,
                   Protocol_Version* record_version,
                   Record_Type* record_type,
                   Connection_Sequence_Numbers* sequence_numbers,
                   std::function<Connection_Cipher_State* (u16bit)> get_cipherstate)
   {
   consumed = 0;

   if(readbuf.size() < TLS_HEADER_SIZE) // header incomplete?
      {
      if(size_t needed = fill_buffer_to(readbuf,
                                        input, input_sz, consumed,
                                        TLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(readbuf.size(), TLS_HEADER_SIZE,
                         "Have an entire header");
      }

   // Possible SSLv2 format client hello
   if(!sequence_numbers && (readbuf[0] & 0x80) && (readbuf[2] == 1))
      {
      if(readbuf[3] == 0 && readbuf[4] == 2)
         throw TLS_Exception(Alert::PROTOCOL_VERSION,
                             "Client claims to only support SSLv2, rejecting");

      if(readbuf[3] >= 3) // SSLv2 mapped TLS hello, then?
         {
         const size_t record_len = make_u16bit(readbuf[0], readbuf[1]) & 0x7FFF;

         if(size_t needed = fill_buffer_to(readbuf,
                                           input, input_sz, consumed,
                                           record_len + 2))
            return needed;

         BOTAN_ASSERT_EQUAL(readbuf.size(), (record_len + 2),
                            "Have the entire SSLv2 hello");

         // Fake v3-style handshake message wrapper
         *record_version = Protocol_Version::TLS_V10;
         *record_sequence = 0;
         *record_type = HANDSHAKE;

         record.resize(4 + readbuf.size() - 2);

         record[0] = CLIENT_HELLO_SSLV2;
         record[1] = 0;
         record[2] = readbuf[0] & 0x7F;
         record[3] = readbuf[1];
         copy_mem(&record[4], &readbuf[2], readbuf.size() - 2);

         readbuf.clear();
         return 0;
         }
      }

   *record_version = Protocol_Version(readbuf[1], readbuf[2]);

   const bool is_dtls = record_version->is_datagram_protocol();

   if(is_dtls && readbuf.size() < DTLS_HEADER_SIZE)
      {
      if(size_t needed = fill_buffer_to(readbuf,
                                        input, input_sz, consumed,
                                        DTLS_HEADER_SIZE))
         return needed;

      BOTAN_ASSERT_EQUAL(readbuf.size(), DTLS_HEADER_SIZE,
                         "Have an entire header");
      }

   const size_t header_size = (is_dtls) ? DTLS_HEADER_SIZE : TLS_HEADER_SIZE;

   const size_t record_len = make_u16bit(readbuf[header_size-2],
                                         readbuf[header_size-1]);

   if(record_len > MAX_CIPHERTEXT_SIZE)
      throw TLS_Exception(Alert::RECORD_OVERFLOW,
                          "Got message that exceeds maximum size");

   if(size_t needed = fill_buffer_to(readbuf,
                                     input, input_sz, consumed,
                                     header_size + record_len))
      return needed; // wrong for DTLS?

   BOTAN_ASSERT_EQUAL(static_cast<size_t>(header_size) + record_len,
                      readbuf.size(),
                      "Have the full record");

   *record_type = static_cast<Record_Type>(readbuf[0]);

   u16bit epoch = 0;

   if(is_dtls)
      {
      *record_sequence = load_be<u64bit>(&readbuf[3], 0);
      epoch = (*record_sequence >> 48);
      }
   else if(sequence_numbers)
      {
      *record_sequence = sequence_numbers->next_read_sequence();
      epoch = sequence_numbers->current_read_epoch();
      }
   else
      {
      // server initial handshake case
      *record_sequence = 0;
      epoch = 0;
      }

   if(sequence_numbers && sequence_numbers->already_seen(*record_sequence))
      return 0;

   byte* record_contents = &readbuf[header_size];

   if(epoch == 0) // Unencrypted initial handshake
      {
      record.assign(&readbuf[header_size], &readbuf[header_size + record_len]);
      readbuf.clear();
      return 0; // got a full record
      }

   // Otherwise, decrypt, check MAC, return plaintext
   Connection_Cipher_State* cipherstate = get_cipherstate(epoch);

   // FIXME: DTLS reordering might cause us not to have the cipher state

   BOTAN_ASSERT(cipherstate, "Have cipherstate for this epoch");

   decrypt_record(record,
                  record_contents,
                  record_len,
                  *record_sequence,
                  *record_version,
                  *record_type,
                  *cipherstate);

   if(sequence_numbers)
      sequence_numbers->read_accept(*record_sequence);

   readbuf.clear();
   return 0;
   }

}

}
