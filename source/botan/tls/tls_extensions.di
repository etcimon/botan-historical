/*
* TLS Extensions
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

import botan.alloc.secmem;
import botan.tls_magic;
import vector;
import string;
import map;
import set;
namespace TLS {

class TLS_Data_Reader;

enum Handshake_Extension_Type {
	TLSEXT_SERVER_NAME_INDICATION 	= 0,
	TLSEXT_MAX_FRAGMENT_LENGTH		= 1,
	TLSEXT_CLIENT_CERT_URL		 	= 2,
	TLSEXT_TRUSTED_CA_KEYS		 	= 3,
	TLSEXT_TRUNCATED_HMAC			= 4,

	TLSEXT_CERTIFICATE_TYPES		= 9,
	TLSEXT_USABLE_ELLIPTIC_CURVES	= 10,
	TLSEXT_EC_POINT_FORMATS			= 11,
	TLSEXT_SRP_IDENTIFIER			= 12,
	TLSEXT_SIGNATURE_ALGORITHMS		= 13,
	TLSEXT_HEARTBEAT_SUPPORT		= 15,

	TLSEXT_SESSION_TICKET			= 35,

	TLSEXT_NEXT_PROTOCOL			= 13172,

	TLSEXT_SAFE_RENEGOTIATION	  	= 65281,
}

/**
* Base class representing a TLS extension of some kind
*/
class Extension
{
	public:
		/**
		* @return code number of the extension
		*/
		abstract Handshake_Extension_Type type() const;

		/**
		* @return serialized binary for the extension
		*/
		abstract Vector!ubyte serialize() const;

		/**
		* @return if we should encode this extension or not
		*/
		abstract bool empty() const;

		~this() {}
}

/**
* Server Name Indicator extension (RFC 3546)
*/
class Server_Name_Indicator : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_SERVER_NAME_INDICATION; }

		Handshake_Extension_Type type() const { return static_type(); }

		Server_Name_Indicator(in string host_name) :
			sni_host_name(host_name) {}

		Server_Name_Indicator(TLS_Data_Reader& reader,
									 ushort extension_size);

		string host_name() const { return sni_host_name; }

		Vector!ubyte serialize() const;

		bool empty() const { return sni_host_name == ""; }
	private:
		string sni_host_name;
}

/**
* SRP identifier extension (RFC 5054)
*/
class SRP_Identifier : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_SRP_IDENTIFIER; }

		Handshake_Extension_Type type() const { return static_type(); }

		SRP_Identifier(in string identifier) :
			srp_identifier(identifier) {}

		SRP_Identifier(TLS_Data_Reader& reader,
							ushort extension_size);

		string identifier() const { return srp_identifier; }

		Vector!ubyte serialize() const;

		bool empty() const { return srp_identifier == ""; }
	private:
		string srp_identifier;
}

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class Renegotiation_Extension : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_SAFE_RENEGOTIATION; }

		Handshake_Extension_Type type() const { return static_type(); }

		Renegotiation_Extension() {}

		Renegotiation_Extension(in Vector!ubyte bits) :
			reneg_data(bits) {}

		Renegotiation_Extension(TLS_Data_Reader& reader,
									  ushort extension_size);

		in Vector!ubyte renegotiation_info() const
		{ return reneg_data; }

		Vector!ubyte serialize() const;

		bool empty() const { return false; } // always send this
	private:
		Vector!ubyte reneg_data;
}

/**
* Maximum Fragment Length Negotiation Extension (RFC 4366 sec 3.2)
*/
class Maximum_Fragment_Length : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_MAX_FRAGMENT_LENGTH; }

		Handshake_Extension_Type type() const { return static_type(); }

		bool empty() const { return false; }

		size_t fragment_size() const { return m_max_fragment; }

		Vector!ubyte serialize() const;

		/**
		* @param max_fragment specifies what maximum fragment size to
		*		  advertise. Currently must be one of 512, 1024, 2048, or
		*		  4096.
		*/
		Maximum_Fragment_Length(size_t max_fragment) :
			m_max_fragment(max_fragment) {}

		Maximum_Fragment_Length(TLS_Data_Reader& reader,
										ushort extension_size);

	private:
		size_t m_max_fragment;
}

/**
* Next Protocol Negotiation
* http://technotes.googlecode.com/git/nextprotoneg.html
*
* This implementation requires the semantics defined in the Google
* spec (implemented in Chromium); the internet draft leaves the format
* unspecified.
*/
class Next_Protocol_Notification : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_NEXT_PROTOCOL; }

		Handshake_Extension_Type type() const { return static_type(); }

		const Vector!string& protocols() const
		{ return m_protocols; }

		/**
		* Empty extension, used by client
		*/
		Next_Protocol_Notification() {}

		/**
		* List of protocols, used by server
		*/
		Next_Protocol_Notification(in Vector!string protocols) :
			m_protocols(protocols) {}

		Next_Protocol_Notification(TLS_Data_Reader& reader,
											ushort extension_size);

		Vector!ubyte serialize() const;

		bool empty() const { return false; }
	private:
		Vector!string m_protocols;
}

/**
* Session Ticket Extension (RFC 5077)
*/
class Session_Ticket : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_SESSION_TICKET; }

		Handshake_Extension_Type type() const { return static_type(); }

		/**
		* @return contents of the session ticket
		*/
		in Vector!ubyte contents() const { return m_ticket; }

		/**
		* Create empty extension, used by both client and server
		*/
		Session_Ticket() {}

		/**
		* Extension with ticket, used by client
		*/
		Session_Ticket(in Vector!ubyte session_ticket) :
			m_ticket(session_ticket) {}

		/**
		* Deserialize a session ticket
		*/
		Session_Ticket(TLS_Data_Reader& reader, ushort extension_size);

		Vector!ubyte serialize() const { return m_ticket; }

		bool empty() const { return false; }
	private:
		Vector!ubyte m_ticket;
}

/**
* Supported Elliptic Curves Extension (RFC 4492)
*/
class Supported_Elliptic_Curves : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_USABLE_ELLIPTIC_CURVES; }

		Handshake_Extension_Type type() const { return static_type(); }

		static string curve_id_to_name(ushort id);
		static ushort name_to_curve_id(in string name);

		const Vector!string& curves() const { return m_curves; }

		Vector!ubyte serialize() const;

		Supported_Elliptic_Curves(in Vector!string curves) :
			m_curves(curves) {}

		Supported_Elliptic_Curves(TLS_Data_Reader& reader,
										  ushort extension_size);

		bool empty() const { return m_curves.empty(); }
	private:
		Vector!string m_curves;
}

/**
* Signature Algorithms Extension for TLS 1.2 (RFC 5246)
*/
class Signature_Algorithms : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_SIGNATURE_ALGORITHMS; }

		Handshake_Extension_Type type() const { return static_type(); }

		static string hash_algo_name(ubyte code);
		static ubyte hash_algo_code(in string name);

		static string sig_algo_name(ubyte code);
		static ubyte sig_algo_code(in string name);

		Vector!( Pair!(string, string)  )
			supported_signature_algorthms() const
		{
			return m_supported_algos;
		}

		Vector!ubyte serialize() const;

		bool empty() const { return false; }

		Signature_Algorithms(in Vector!string hashes,
									const Vector!string& sig_algos);

		Signature_Algorithms(in Vector!( Pair!(string, string)  ) algos) :
			m_supported_algos(algos) {}

		Signature_Algorithms(TLS_Data_Reader& reader,
									ushort extension_size);
	private:
		Vector!( Pair!(string, string)  ) m_supported_algos;
}

/**
* Heartbeat Extension (RFC 6520)
*/
class Heartbeat_Support_Indicator : public Extension
{
	public:
		static Handshake_Extension_Type static_type()
		{ return TLSEXT_HEARTBEAT_SUPPORT; }

		Handshake_Extension_Type type() const { return static_type(); }

		bool peer_allowed_to_send() const { return m_peer_allowed_to_send; }

		Vector!ubyte serialize() const;

		bool empty() const { return false; }

		Heartbeat_Support_Indicator(bool peer_allowed_to_send) :
			m_peer_allowed_to_send(peer_allowed_to_send) {}

		Heartbeat_Support_Indicator(TLS_Data_Reader& reader, ushort extension_size);

	private:
		bool m_peer_allowed_to_send;
}

/**
* Represents a block of extensions in a hello message
*/
class Extensions
{
	public:
		std::set<Handshake_Extension_Type> extension_types() const;

		T* get(T)() const
		{
			Handshake_Extension_Type type = T::static_type();

			auto i = extensions.find(type);

			if (i != extensions.end())
				return cast(T*)(i.second.get());
			return null;
		}

		void add(Extension* extn)
		{
			extensions[extn.type()].reset(extn);
		}

		Vector!ubyte serialize() const;

		void deserialize(TLS_Data_Reader& reader);

		Extensions() {}

		Extensions(TLS_Data_Reader& reader) { deserialize(reader); }

	private:
		Extensions(in Extensions) {}
		Extensions& operator=(in Extensions) { return (*this); }

		HashMap<Handshake_Extension_Type, Unique!Extension> extensions;
}

}