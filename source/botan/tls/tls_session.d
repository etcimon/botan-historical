/*
* TLS Session State
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_session.h>
#include <botan/der_enc.h>
#include <botan/ber_dec.h>
#include <botan/asn1_str.h>
#include <botan/pem.h>
#include <botan/cryptobox_psk.h>

namespace Botan {

namespace TLS {

Session::Session(const std::vector<byte>& session_identifier,
                 const secure_vector<byte>& master_secret,
                 Protocol_Version version,
                 u16bit ciphersuite,
                 byte compression_method,
                 Connection_Side side,
                 size_t fragment_size,
                 const std::vector<X509_Certificate>& certs,
                 const std::vector<byte>& ticket,
                 const Server_Information& server_info,
                 const std::string& srp_identifier) :
   m_start_time(std::chrono::system_clock::now()),
   m_identifier(session_identifier),
   m_session_ticket(ticket),
   m_master_secret(master_secret),
   m_version(version),
   m_ciphersuite(ciphersuite),
   m_compression_method(compression_method),
   m_connection_side(side),
   m_fragment_size(fragment_size),
   m_peer_certs(certs),
   m_server_info(server_info),
   m_srp_identifier(srp_identifier)
   {
   }

Session::Session(const std::string& pem)
   {
   secure_vector<byte> der = PEM_Code::decode_check_label(pem, "SSL SESSION");

   *this = Session(&der[0], der.size());
   }

Session::Session(const byte ber[], size_t ber_len)
   {
   byte side_code = 0;

   ASN1_String server_hostname;
   ASN1_String server_service;
   size_t server_port;

   ASN1_String srp_identifier_str;

   byte major_version = 0, minor_version = 0;

   std::vector<byte> peer_cert_bits;

   size_t start_time = 0;

   BER_Decoder(ber, ber_len)
      .start_cons(SEQUENCE)
        .decode_and_check(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION),
                          "Unknown version in session structure")
        .decode_integer_type(start_time)
        .decode_integer_type(major_version)
        .decode_integer_type(minor_version)
        .decode(m_identifier, OCTET_STRING)
        .decode(m_session_ticket, OCTET_STRING)
        .decode_integer_type(m_ciphersuite)
        .decode_integer_type(m_compression_method)
        .decode_integer_type(side_code)
        .decode_integer_type(m_fragment_size)
        .decode(m_master_secret, OCTET_STRING)
        .decode(peer_cert_bits, OCTET_STRING)
        .decode(server_hostname)
        .decode(server_service)
        .decode(server_port)
        .decode(srp_identifier_str)
      .end_cons()
      .verify_end();

   m_version = Protocol_Version(major_version, minor_version);
   m_start_time = std::chrono::system_clock::from_time_t(start_time);
   m_connection_side = static_cast<Connection_Side>(side_code);

   m_server_info = Server_Information(server_hostname.value(),
                                      server_service.value(),
                                      server_port);

   m_srp_identifier = srp_identifier_str.value();

   if(!peer_cert_bits.empty())
      {
      DataSource_Memory certs(&peer_cert_bits[0], peer_cert_bits.size());

      while(!certs.end_of_data())
         m_peer_certs.push_back(X509_Certificate(certs));
      }
   }

secure_vector<byte> Session::DER_encode() const
   {
   std::vector<byte> peer_cert_bits;
   for(size_t i = 0; i != m_peer_certs.size(); ++i)
      peer_cert_bits += m_peer_certs[i].BER_encode();

   return DER_Encoder()
      .start_cons(SEQUENCE)
         .encode(static_cast<size_t>(TLS_SESSION_PARAM_STRUCT_VERSION))
         .encode(static_cast<size_t>(std::chrono::system_clock::to_time_t(m_start_time)))
         .encode(static_cast<size_t>(m_version.major_version()))
         .encode(static_cast<size_t>(m_version.minor_version()))
         .encode(m_identifier, OCTET_STRING)
         .encode(m_session_ticket, OCTET_STRING)
         .encode(static_cast<size_t>(m_ciphersuite))
         .encode(static_cast<size_t>(m_compression_method))
         .encode(static_cast<size_t>(m_connection_side))
         .encode(static_cast<size_t>(m_fragment_size))
         .encode(m_master_secret, OCTET_STRING)
         .encode(peer_cert_bits, OCTET_STRING)
         .encode(ASN1_String(m_server_info.hostname(), UTF8_STRING))
         .encode(ASN1_String(m_server_info.service(), UTF8_STRING))
         .encode(static_cast<size_t>(m_server_info.port()))
         .encode(ASN1_String(m_srp_identifier, UTF8_STRING))
      .end_cons()
   .get_contents();
   }

std::string Session::PEM_encode() const
   {
   return PEM_Code::encode(this->DER_encode(), "SSL SESSION");
   }

std::chrono::seconds Session::session_age() const
   {
   return std::chrono::duration_cast<std::chrono::seconds>(
      std::chrono::system_clock::now() - m_start_time);
   }

std::vector<byte>
Session::encrypt(const SymmetricKey& master_key,
                 RandomNumberGenerator& rng) const
   {
   const auto der = this->DER_encode();

   return CryptoBox::encrypt(&der[0], der.size(), master_key, rng);
   }

Session Session::decrypt(const byte buf[], size_t buf_len,
                         const SymmetricKey& master_key)
   {
   try
      {
      const auto ber = CryptoBox::decrypt(buf, buf_len, master_key);

      return Session(&ber[0], ber.size());
      }
   catch(std::exception& e)
      {
      throw Decoding_Error("Failed to decrypt encrypted session -" +
                           std::string(e.what()));
      }
   }

}

}

