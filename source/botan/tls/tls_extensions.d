/*
* TLS Extensions
* (C) 2011-2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_extensions;

import botan.alloc.zeroize;
import botan.tls.tls_magic;
import botan.utils.types;
// import string;
import botan.utils.hashmap;
import set;

import botan.tls.tls_reader;
import botan.tls.tls_exceptn;
import botan.utils.types : Unique;

typedef ushort Handshake_Extension_Type;
enum : Handshake_Extension_Type {
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
	abstract @property bool empty() const;

	~this() {}
}

/**
* Server Name Indicator extension (RFC 3546)
*/
class Server_Name_Indicator : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_SERVER_NAME_INDICATION; }

	Handshake_Extension_Type type() const { return static_type(); }

	this(in string host_name) 
	{
		m_sni_host_name = host_name;
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		/*
		* This is used by the server to confirm that it knew the name
		*/
		if (extension_size == 0)
			return;
		
		ushort name_bytes = reader.get_ushort();
		
		if (name_bytes + 2 != extension_size)
			throw new Decoding_Error("Bad encoding of SNI extension");
		
		while(name_bytes)
		{
			ubyte name_type = reader.get_byte();
			name_bytes--;
			
			if (name_type == 0) // DNS
			{
				m_sni_host_name = reader.get_string(2, 1, 65535);
				name_bytes -= (2 + m_sni_host_name.length);
			}
			else // some other unknown name type
			{
				reader.discard_next(name_bytes);
				name_bytes = 0;
			}
		}
	}

	string host_name() const { return m_sni_host_name; }

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		size_t name_len = m_sni_host_name.length;
		
		buf.push_back(get_byte!ushort(0, name_len+3));
		buf.push_back(get_byte!ushort(1, name_len+3));
		buf.push_back(0); // DNS
		
		buf.push_back(get_byte!ushort(0, name_len));
		buf.push_back(get_byte!ushort(1, name_len));
		
		buf += Pair(
			cast(const ubyte*)(m_sni_host_name.ptr),
			m_sni_host_name.length);
		
		return buf;
	}

	@property bool empty() const { return m_sni_host_name == ""; }
private:
	string m_sni_host_name;
}

/**
* SRP identifier extension (RFC 5054)
*/
class SRP_Identifier : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_SRP_IDENTIFIER; }

	Handshake_Extension_Type type() const { return static_type(); }

	this(in string identifier) 
	{
		m_srp_identifier = identifier;
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		m_srp_identifier = reader.get_string(1, 1, 255);
		
		if (m_srp_identifier.length + 1 != extension_size)
			throw new Decoding_Error("Bad encoding for SRP identifier extension");
	}

	this(ref TLS_Data_Reader reader,
						ushort extension_size);

	string identifier() const { return m_srp_identifier; }


	Vector!ubyte serialize() const
	{
		Vector!ubyte buf;

		const ubyte* srp_bytes = cast(const ubyte*)(m_srp_identifier.ptr);
		
		append_tls_length_value(buf, srp_bytes, m_srp_identifier.length, 1);
		
		return buf;
	}

	@property bool empty() const { return m_srp_identifier == ""; }
private:
	string m_srp_identifier;
}

/**
* Renegotiation Indication Extension (RFC 5746)
*/
class Renegotiation_Extension : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_SAFE_RENEGOTIATION; }

	Handshake_Extension_Type type() const { return static_type(); }

	this() {}

	this(in Vector!ubyte bits)
	{
		m_reneg_data = bits;
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		m_reneg_data = reader.get_range!ubyte(1, 0, 255);
		
		if (m_reneg_data.length + 1 != extension_size)
			throw new Decoding_Error("Bad encoding for secure renegotiation extn");
	}

	const Vector!ubyte renegotiation_info() const
	{ return m_reneg_data; }

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		append_tls_length_value(buf, m_reneg_data, 1);
		return buf;
	}

	@property bool empty() const { return false; } // always send this

private:
	Vector!ubyte m_reneg_data;
}

/**
* Maximum Fragment Length Negotiation Extension (RFC 4366 sec 3.2)
*/
class Maximum_Fragment_Length : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_MAX_FRAGMENT_LENGTH; }

	Handshake_Extension_Type type() const { return static_type(); }

	@property bool empty() const { return false; }

	size_t fragment_size() const { return m_max_fragment; }

	Vector!ubyte serialize() const
	{
		__gshared immutable ubyte[size_t] fragment_to_code = [ 512: 1, 1024: 2, 2048: 3, 4096: 4 ];
		
		auto i = fragment_to_code.get(m_max_fragment, 0);
		
		if (i == 0)
			throw new Invalid_Argument("Bad setting " ~
			                           std.conv.to!string(m_max_fragment) +
			                           " for maximum fragment size");
		
		return Vector!ubyte(1, i);
	}

	/**
	* @param max_fragment specifies what maximum fragment size to
	*		  advertise. Currently must be one of 512, 1024, 2048, or
	*		  4096.
	*/
	this(size_t max_fragment) 
	{
		m_max_fragment = max_fragment;
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		__gshared immutable size_t[] code_to_fragment = [ 0, 512, 1024, 2048, 4096 ];
		if (extension_size != 1)
			throw new Decoding_Error("Bad size for maximum fragment extension");
		ubyte val = reader.get_byte();

		
		auto i = code_to_fragment.get(cast(size_t) val, 0);

		if (i == 0)
			throw new TLS_Exception(Alert.ILLEGAL_PARAMETER,
			                        "Bad value in maximum fragment extension");
		
		m_max_fragment = i;
	}

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
class Next_Protocol_Notification : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_NEXT_PROTOCOL; }

	Handshake_Extension_Type type() const { return static_type(); }

	ref const Vector!string protocols() const
	{ return m_protocols; }

	/**
	* Empty extension, used by client
	*/
	this() {}

	/**
	* List of protocols, used by server
	*/
	this(in Vector!string protocols) 
	{
		m_protocols = protocols; 
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		if (extension_size == 0)
			return; // empty extension
		
		size_t bytes_remaining = extension_size;
		
		while(bytes_remaining)
		{
			const string p = reader.get_string(1, 0, 255);
			
			if (bytes_remaining < p.length + 1)
				throw new Decoding_Error("Bad encoding for next protocol extension");
			
			bytes_remaining -= (p.length + 1);
			
			m_protocols.push_back(p);
		}
	}

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf;
		
		for (size_t i = 0; i != m_protocols.length; ++i)
		{
			const string p = m_protocols[i];
			
			if (p != "")
				append_tls_length_value(buf,
				                        cast(const ubyte*)(p.ptr),
				                        p.length,
				                        1);
		}
		
		return buf;
	}

	@property bool empty() const { return false; }
private:
	Vector!string m_protocols;
}

/**
* Session Ticket Extension (RFC 5077)
*/
class Session_Ticket : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_SESSION_TICKET; }

	Handshake_Extension_Type type() const { return static_type(); }

	/**
	* @return contents of the session ticket
	*/
	const Vector!ubyte contents() const { return m_ticket; }

	/**
	* Create empty extension, used by both client and server
	*/
	this() {}

	/**
	* Extension with ticket, used by client
	*/
	this(in Vector!ubyte session_ticket)
	{
		m_ticket = session_ticket;
	}

	/**
	* Deserialize a session ticket
	*/
	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		m_ticket = reader.get_elem!(ubyte, Vector!ubyte)(extension_size);
	}

	Vector!ubyte serialize() const { return m_ticket; }

	@property bool empty() const { return false; }
private:
	Vector!ubyte m_ticket;
}

/**
* Supported Elliptic Curves Extension (RFC 4492)
*/
class Supported_Elliptic_Curves : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_USABLE_ELLIPTIC_CURVES; }

	Handshake_Extension_Type type() const { return static_type(); }

	static string curve_id_to_name(ushort id)
	{
		switch(id)
		{
			case 15:
				return "secp160k1";
			case 16:
				return "secp160r1";
			case 17:
				return "secp160r2";
			case 18:
				return "secp192k1";
			case 19:
				return "secp192r1";
			case 20:
				return "secp224k1";
			case 21:
				return "secp224r1";
			case 22:
				return "secp256k1";
			case 23:
				return "secp256r1";
			case 24:
				return "secp384r1";
			case 25:
				return "secp521r1";
			case 26:
				return "brainpool256r1";
			case 27:
				return "brainpool384r1";
			case 28:
				return "brainpool512r1";
			default:
				return ""; // something we don't know or support
		}
	}

	static ushort name_to_curve_id(in string name)
	{
		if (name == "secp160k1")
			return 15;
		if (name == "secp160r1")
			return 16;
		if (name == "secp160r2")
			return 17;
		if (name == "secp192k1")
			return 18;
		if (name == "secp192r1")
			return 19;
		if (name == "secp224k1")
			return 20;
		if (name == "secp224r1")
			return 21;
		if (name == "secp256k1")
			return 22;
		if (name == "secp256r1")
			return 23;
		if (name == "secp384r1")
			return 24;
		if (name == "secp521r1")
			return 25;
		if (name == "brainpool256r1")
			return 26;
		if (name == "brainpool384r1")
			return 27;
		if (name == "brainpool512r1")
			return 28;
		
		throw new Invalid_Argument("name_to_curve_id unknown name " ~ name);
	}

	const ref Vector!string curves() const { return m_curves; }

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf = Vector!ubyte(2);
		
		for (size_t i = 0; i != m_curves.length; ++i)
		{
			const ushort id = name_to_curve_id(m_curves[i]);
			buf.push_back(get_byte(0, id));
			buf.push_back(get_byte(1, id));
		}
		
		buf[0] = get_byte!ushort(0, buf.length-2);
		buf[1] = get_byte!ushort(1, buf.length-2);
		
		return buf;
	}

	this(in Vector!string curves) 
	{
		m_curves = curves;
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		ushort len = reader.get_ushort();
		
		if (len + 2 != extension_size)
			throw new Decoding_Error("Inconsistent length field in elliptic curve list");
		
		if (len % 2 == 1)
			throw new Decoding_Error("Elliptic curve list of strange size");
		
		len /= 2;
		
		foreach (size_t i; 0 .. len)
		{
			const ushort id = reader.get_ushort();
			const string name = curve_id_to_name(id);
			
			if (name != "")
				m_curves.push_back(name);
		}
	}

	@property bool empty() const { return m_curves.empty; }
private:
	Vector!string m_curves;
}

/**
* Signature Algorithms Extension for TLS 1.2 (RFC 5246)
*/
class Signature_Algorithms : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_SIGNATURE_ALGORITHMS; }

	Handshake_Extension_Type type() const { return static_type(); }

		static string hash_algo_name(ubyte code)
	{
		switch(code)
		{
			case 1:
				return "MD5";
				// code 1 is MD5 - ignore it
				
			case 2:
				return "SHA-1";
			case 3:
				return "SHA-224";
			case 4:
				return "SHA-256";
			case 5:
				return "SHA-384";
			case 6:
				return "SHA-512";
			default:
				return "";
		}
	}

	static ubyte hash_algo_code(in string name)
	{
		if (name == "MD5")
			return 1;
		
		if (name == "SHA-1")
			return 2;
		
		if (name == "SHA-224")
			return 3;
		
		if (name == "SHA-256")
			return 4;
		
		if (name == "SHA-384")
			return 5;
		
		if (name == "SHA-512")
			return 6;
		
		throw new Internal_Error("Unknown hash ID " ~ name ~ " for signature_algorithms");
	}

	static string sig_algo_name(ubyte code)
	{
		switch(code)
		{
			case 1:
				return "RSA";
			case 2:
				return "DSA";
			case 3:
				return "ECDSA";
			default:
				return "";
		}
	}

	static ubyte sig_algo_code(in string name)
	{
		if (name == "RSA")
			return 1;
		
		if (name == "DSA")
			return 2;
		
		if (name == "ECDSA")
			return 3;
		
		throw new Internal_Error("Unknown sig ID " ~ name ~ " for signature_algorithms");
	}

	Vector!( Pair!(string, string)  )
		supported_signature_algorthms() const
	{
		return m_supported_algos;
	}

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf = Vector!ubyte(2);
		
		for (size_t i = 0; i != m_supported_algos.length; ++i)
		{
			try
			{
				const ubyte hash_code = hash_algo_code(m_supported_algos[i].first);
				const ubyte sig_code = sig_algo_code(m_supported_algos[i].second);
				
				buf.push_back(hash_code);
				buf.push_back(sig_code);
			}
			catch
			{}
		}
		
		buf[0] = get_byte!ushort(0, buf.length-2);
		buf[1] = get_byte!ushort(1, buf.length-2);
		
		return buf;
	}

	@property bool empty() const { return false; }

	this(in Vector!string hashes,
	     const ref Vector!string sigs)
	{
		for (size_t i = 0; i != hashes.length; ++i)
			for (size_t j = 0; j != sigs.length; ++j)
				m_supported_algos.push_back(Pair(hashes[i], sigs[j]));
	}
	
	this(TLS_Data_Reader reader,
	     ushort extension_size)
	{
		ushort len = reader.get_ushort();
		
		if (len + 2 != extension_size)
			throw new Decoding_Error("Bad encoding on signature algorithms extension");
		
		while(len)
		{
			const string hash_code = hash_algo_name(reader.get_byte());
			const string sig_code = sig_algo_name(reader.get_byte());
			
			len -= 2;
			
			// If not something we know, ignore it completely
			if (hash_code == "" || sig_code == "")
				continue;
			
			m_supported_algos.push_back(Pair(hash_code, sig_code));
		}
	}

	this(in Vector!( Pair!(string, string)  ) algos) 
	{
		m_supported_algos = algos;
	}

private:
	Vector!( Pair!(string, string) ) m_supported_algos;
}

/**
* Heartbeat Extension (RFC 6520)
*/
class Heartbeat_Support_Indicator : Extension
{
public:
	static Handshake_Extension_Type static_type()
	{ return TLSEXT_HEARTBEAT_SUPPORT; }

	Handshake_Extension_Type type() const { return static_type(); }

	bool peer_allowed_to_send() const { return m_peer_allowed_to_send; }

	Vector!ubyte serialize() const
	{
		Vector!ubyte heartbeat = Vector!ubyte(1);
		heartbeat[0] = (m_peer_allowed_to_send ? 1 : 2);
		return heartbeat;
	}



	@property bool empty() const { return false; }

	this(bool peer_allowed_to_send) 
	{
		m_peer_allowed_to_send = peer_allowed_to_send; 
	}

	this(ref TLS_Data_Reader reader,
	     ushort extension_size)
	{
		if (extension_size != 1)
			throw new Decoding_Error("Strange size for heartbeat extension");
		
		const ubyte code = reader.get_byte();
		
		if (code != 1 && code != 2)
			throw new TLS_Exception(Alert.ILLEGAL_PARAMETER,
			                        "Unknown heartbeat code " ~ std.conv.to!string(code));
		
		m_peer_allowed_to_send = (code == 1);
	}

private:
	bool m_peer_allowed_to_send;
}

/**
* Represents a block of extensions in a hello message
*/
class Extensions
{
public:
	Handshake_Extension_Type[] extension_types() const
	{
		Appender!Handshake_Extension_Type offers;
		foreach (t, ext; extensions)
			offers ~= t;
		return offers.data;
	}


	T get(T)() const
	{
		Handshake_Extension_Type type = T.static_type();

		return extensions.get(type, null);
	}

	void add(Extension extn)
	{
		auto val = extensions.get(extn.type(), null);
		if (val)
			delete val;
		extensions[extn.type()] = extn;
	}

	Vector!ubyte serialize() const
	{
		Vector!ubyte buf = Vector!ubyte(2); // 2 bytes for length field
		
		foreach (ref extn; extensions)
		{
			if (extn.second.empty)
				continue;
			
			const ushort extn_code = extn.second.type();
			
			Vector!ubyte extn_val = extn.second.serialize();
			
			buf.push_back(get_byte(0, extn_code));
			buf.push_back(get_byte(1, extn_code));
			
			buf.push_back(get_byte!ushort(0, extn_val.length));
			buf.push_back(get_byte!ushort(1, extn_val.length));
			
			buf += extn_val;
		}
		
		const ushort extn_size = buf.length - 2;
		
		buf[0] = get_byte(0, extn_size);
		buf[1] = get_byte(1, extn_size);
		
		// avoid sending a completely empty extensions block
		if (buf.length == 2)
			return Vector!ubyte();
		
		return buf;
	}

	void deserialize(ref TLS_Data_Reader reader)
	{
		if (reader.has_remaining())
		{
			const ushort all_extn_size = reader.get_ushort();
			
			if (reader.remaining_bytes() != all_extn_size)
				throw new Decoding_Error("Bad extension size");
			
			while(reader.has_remaining())
			{
				const ushort extension_code = reader.get_ushort();
				const ushort extension_size = reader.get_ushort();
				
				Extension extn = make_extension(reader,
				                                extension_code,
				                                extension_size);
				
				if (extn)
					this.add(extn);
				else // unknown/unhandled extension
					reader.discard_next(extension_size);
			}
		}
	}

	this() {}

	this(ref TLS_Data_Reader reader) { deserialize(reader); }

private:
	this(in Extensions) {}
	Extensions opAssign(in Extensions) { return this; }

	HashMap!(Handshake_Extension_Type, Extension) extensions;
}


private:

Extension make_extension(ref TLS_Data_Reader reader,
                         ushort code,
                         ushort size)
{
	switch(code)
	{
		case TLSEXT_SERVER_NAME_INDICATION:
			return new Server_Name_Indicator(reader, size);
			
		case TLSEXT_MAX_FRAGMENT_LENGTH:
			return new Maximum_Fragment_Length(reader, size);
			
		case TLSEXT_SRP_IDENTIFIER:
			return new SRP_Identifier(reader, size);
			
		case TLSEXT_USABLE_ELLIPTIC_CURVES:
			return new Supported_Elliptic_Curves(reader, size);
			
		case TLSEXT_SAFE_RENEGOTIATION:
			return new Renegotiation_Extension(reader, size);
			
		case TLSEXT_SIGNATURE_ALGORITHMS:
			return new Signature_Algorithms(reader, size);
			
		case TLSEXT_NEXT_PROTOCOL:
			return new Next_Protocol_Notification(reader, size);
			
		case TLSEXT_HEARTBEAT_SUPPORT:
			return new Heartbeat_Support_Indicator(reader, size);
			
		case TLSEXT_SESSION_TICKET:
			return new Session_Ticket(reader, size);
			
		default:
			return null; // not known
	}
}
