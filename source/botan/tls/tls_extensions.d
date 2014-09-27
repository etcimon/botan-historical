/*
* TLS Extensions
* (C) 2011,2012 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_extensions.h>
#include <botan/internal/tls_reader.h>
#include <botan/tls_exceptn.h>
namespace TLS {

namespace {

Extension* make_extension(TLS_Data_Reader& reader,
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

}

void Extensions::deserialize(TLS_Data_Reader& reader)
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

			Extension* extn = make_extension(reader,
														extension_code,
														extension_size);

			if (extn)
				this->add(extn);
			else // unknown/unhandled extension
				reader.discard_next(extension_size);
		}
	}
}

Vector!( byte ) Extensions::serialize() const
{
	Vector!( byte ) buf(2); // 2 bytes for length field

	foreach (ref extn; extensions)
	{
		if (extn.second->empty())
			continue;

		const ushort extn_code = extn.second->type();

		Vector!( byte ) extn_val = extn.second->serialize();

		buf.push_back(get_byte(0, extn_code));
		buf.push_back(get_byte(1, extn_code));

		buf.push_back(get_byte<ushort>(0, extn_val.size()));
		buf.push_back(get_byte<ushort>(1, extn_val.size()));

		buf += extn_val;
	}

	const ushort extn_size = buf.size() - 2;

	buf[0] = get_byte(0, extn_size);
	buf[1] = get_byte(1, extn_size);

	// avoid sending a completely empty extensions block
	if (buf.size() == 2)
		return Vector!( byte )();

	return buf;
}

std::set<Handshake_Extension_Type> Extensions::extension_types() const
{
	std::set<Handshake_Extension_Type> offers;
	for (auto i = extensions.begin(); i != extensions.end(); ++i)
		offers.insert(i->first);
	return offers;
}

Server_Name_Indicator::Server_Name_Indicator(TLS_Data_Reader& reader,
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
		byte name_type = reader.get_byte();
		name_bytes--;

		if (name_type == 0) // DNS
		{
			sni_host_name = reader.get_string(2, 1, 65535);
			name_bytes -= (2 + sni_host_name.size());
		}
		else // some other unknown name type
		{
			reader.discard_next(name_bytes);
			name_bytes = 0;
		}
	}
}

Vector!( byte ) Server_Name_Indicator::serialize() const
{
	Vector!( byte ) buf;

	size_t name_len = sni_host_name.size();

	buf.push_back(get_byte<ushort>(0, name_len+3));
	buf.push_back(get_byte<ushort>(1, name_len+3));
	buf.push_back(0); // DNS

	buf.push_back(get_byte<ushort>(0, name_len));
	buf.push_back(get_byte<ushort>(1, name_len));

	buf += Pair(
		cast(const byte*)(sni_host_name.data()),
		sni_host_name.size());

	return buf;
}

SRP_Identifier::SRP_Identifier(TLS_Data_Reader& reader,
										 ushort extension_size)
{
	srp_identifier = reader.get_string(1, 1, 255);

	if (srp_identifier.size() + 1 != extension_size)
		throw new Decoding_Error("Bad encoding for SRP identifier extension");
}

Vector!( byte ) SRP_Identifier::serialize() const
{
	Vector!( byte ) buf;

	const byte* srp_bytes =
		cast(const byte*)(srp_identifier.data());

	append_tls_length_value(buf, srp_bytes, srp_identifier.size(), 1);

	return buf;
}

Renegotiation_Extension::Renegotiation_Extension(TLS_Data_Reader& reader,
																 ushort extension_size)
{
	reneg_data = reader.get_range<byte>(1, 0, 255);

	if (reneg_data.size() + 1 != extension_size)
		throw new Decoding_Error("Bad encoding for secure renegotiation extn");
}

Vector!( byte ) Renegotiation_Extension::serialize() const
{
	Vector!( byte ) buf;
	append_tls_length_value(buf, reneg_data, 1);
	return buf;
}

Vector!( byte ) Maximum_Fragment_Length::serialize() const
{
	const std::map<size_t, byte> fragment_to_code = { {  512, 1 },
																	  { 1024, 2 },
																	  { 2048, 3 },
																	  { 4096, 4 } };

	auto i = fragment_to_code.find(m_max_fragment);

	if (i == fragment_to_code.end())
		throw new std::invalid_argument("Bad setting " +
											 std::to_string(m_max_fragment) +
											 " for maximum fragment size");

	return Vector!( byte )(1, i->second);
}

Maximum_Fragment_Length::Maximum_Fragment_Length(TLS_Data_Reader& reader,
																 ushort extension_size)
{
	if (extension_size != 1)
		throw new Decoding_Error("Bad size for maximum fragment extension");
	byte val = reader.get_byte();

	const std::map<byte, size_t> code_to_fragment = { { 1,  512 },
																	  { 2, 1024 },
																	  { 3, 2048 },
																	  { 4, 4096 } };

	auto i = code_to_fragment.find(val);

	if (i == code_to_fragment.end())
		throw new TLS_Exception(Alert::ILLEGAL_PARAMETER,
								  "Bad value in maximum fragment extension");

	m_max_fragment = i->second;
}

Next_Protocol_Notification::Next_Protocol_Notification(TLS_Data_Reader& reader,
																		 ushort extension_size)
{
	if (extension_size == 0)
		return; // empty extension

	size_t bytes_remaining = extension_size;

	while(bytes_remaining)
	{
		const string p = reader.get_string(1, 0, 255);

		if (bytes_remaining < p.size() + 1)
			throw new Decoding_Error("Bad encoding for next protocol extension");

		bytes_remaining -= (p.size() + 1);

		m_protocols.push_back(p);
	}
}

Vector!( byte ) Next_Protocol_Notification::serialize() const
{
	Vector!( byte ) buf;

	for (size_t i = 0; i != m_protocols.size(); ++i)
	{
		const string p = m_protocols[i];

		if (p != "")
			append_tls_length_value(buf,
											cast(const byte*)(p.data()),
											p.size(),
											1);
	}

	return buf;
}

string Supported_Elliptic_Curves::curve_id_to_name(ushort id)
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

ushort Supported_Elliptic_Curves::name_to_curve_id(in string name)
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

	throw new Invalid_Argument("name_to_curve_id unknown name " + name);
}

Vector!( byte ) Supported_Elliptic_Curves::serialize() const
{
	Vector!( byte ) buf(2);

	for (size_t i = 0; i != m_curves.size(); ++i)
	{
		const ushort id = name_to_curve_id(m_curves[i]);
		buf.push_back(get_byte(0, id));
		buf.push_back(get_byte(1, id));
	}

	buf[0] = get_byte<ushort>(0, buf.size()-2);
	buf[1] = get_byte<ushort>(1, buf.size()-2);

	return buf;
}

Supported_Elliptic_Curves::Supported_Elliptic_Curves(TLS_Data_Reader& reader,
																	  ushort extension_size)
{
	ushort len = reader.get_ushort();

	if (len + 2 != extension_size)
		throw new Decoding_Error("Inconsistent length field in elliptic curve list");

	if (len % 2 == 1)
		throw new Decoding_Error("Elliptic curve list of strange size");

	len /= 2;

	for (size_t i = 0; i != len; ++i)
	{
		const ushort id = reader.get_ushort();
		const string name = curve_id_to_name(id);

		if (name != "")
			m_curves.push_back(name);
	}
}

string Signature_Algorithms::hash_algo_name(byte code)
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

byte Signature_Algorithms::hash_algo_code(in string name)
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

	throw new Internal_Error("Unknown hash ID " + name + " for signature_algorithms");
}

string Signature_Algorithms::sig_algo_name(byte code)
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

byte Signature_Algorithms::sig_algo_code(in string name)
{
	if (name == "RSA")
		return 1;

	if (name == "DSA")
		return 2;

	if (name == "ECDSA")
		return 3;

	throw new Internal_Error("Unknown sig ID " + name + " for signature_algorithms");
}

Vector!( byte ) Signature_Algorithms::serialize() const
{
	Vector!( byte ) buf(2);

	for (size_t i = 0; i != m_supported_algos.size(); ++i)
	{
		try
		{
			const byte hash_code = hash_algo_code(m_supported_algos[i].first);
			const byte sig_code = sig_algo_code(m_supported_algos[i].second);

			buf.push_back(hash_code);
			buf.push_back(sig_code);
		}
		catch(...)
		{}
	}

	buf[0] = get_byte<ushort>(0, buf.size()-2);
	buf[1] = get_byte<ushort>(1, buf.size()-2);

	return buf;
}

Signature_Algorithms::Signature_Algorithms(in Vector!( string ) hashes,
														 const Vector!( string )& sigs)
{
	for (size_t i = 0; i != hashes.size(); ++i)
		for (size_t j = 0; j != sigs.size(); ++j)
			m_supported_algos.push_back(Pair(hashes[i], sigs[j]));
}

Signature_Algorithms::Signature_Algorithms(TLS_Data_Reader& reader,
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

Session_Ticket::Session_Ticket(TLS_Data_Reader& reader,
										 ushort extension_size)
{
	m_ticket = reader.get_elem<byte, Vector!( byte ) >(extension_size);
}

}

}
