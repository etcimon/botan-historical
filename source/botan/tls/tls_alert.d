/*
* Alert Message
* (C) 2004-2006,2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

import botan.tls_alert;
import botan.utils.exceptn;


Alert.Alert(in SafeVector!ubyte buf)
{
	if (buf.length != 2)
		throw new Decoding_Error("Alert: Bad size " ~ std.conv.to!string(buf.length) +
									" for alert message");

	if (buf[0] == 1)		m_fatal = false;
	else if (buf[0] == 2) m_fatal = true;
	else
		throw new Decoding_Error("Alert: Bad code for alert level");

	const ubyte dc = buf[1];

	m_type_code = cast(Type)(dc);
}

Vector!ubyte Alert.serialize() const
{
	return Vector!ubyte({
		cast(ubyte)(is_fatal() ? 2 : 1),
		cast(ubyte)(type())
	});
}

string Alert.type_string() const
{
	switch(type())
	{
		case CLOSE_NOTIFY:
			return "close_notify";
		case UNEXPECTED_MESSAGE:
			return "unexpected_message";
		case BAD_RECORD_MAC:
			return "bad_record_mac";
		case DECRYPTION_FAILED:
			return "decryption_failed";
		case RECORD_OVERFLOW:
			return "record_overflow";
		case DECOMPRESSION_FAILURE:
			return "decompression_failure";
		case HANDSHAKE_FAILURE:
			return "handshake_failure";
		case NO_CERTIFICATE:
			return "no_certificate";
		case BAD_CERTIFICATE:
			return "bad_certificate";
		case UNSUPPORTED_CERTIFICATE:
			return "unsupported_certificate";
		case CERTIFICATE_REVOKED:
			return "certificate_revoked";
		case CERTIFICATE_EXPIRED:
			return "certificate_expired";
		case CERTIFICATE_UNKNOWN:
			return "certificate_unknown";
		case ILLEGAL_PARAMETER:
			return "illegal_parameter";
		case UNKNOWN_CA:
			return "unknown_ca";
		case ACCESS_DENIED:
			return "access_denied";
		case DECODE_ERROR:
			return "decode_error";
		case DECRYPT_ERROR:
			return "decrypt_error";
		case EXPORT_RESTRICTION:
			return "export_restriction";
		case PROTOCOL_VERSION:
			return "protocol_version";
		case INSUFFICIENT_SECURITY:
			return "insufficient_security";
		case INTERNAL_ERROR:
			return "internal_error";
		case USER_CANCELED:
			return "user_canceled";
		case NO_RENEGOTIATION:
			return "no_renegotiation";

		case UNSUPPORTED_EXTENSION:
			return "unsupported_extension";
		case CERTIFICATE_UNOBTAINABLE:
			return "certificate_unobtainable";
		case UNRECOGNIZED_NAME:
			return "unrecognized_name";
		case BAD_CERTIFICATE_STATUS_RESPONSE:
			return "bad_certificate_status_response";
		case BAD_CERTIFICATE_HASH_VALUE:
			return "bad_certificate_hash_value";
		case UNKNOWN_PSK_IDENTITY:
			return "unknown_psk_identity";

		case NULL_ALERT:
			return "none";

		case HEARTBEAT_PAYLOAD:
			return "heartbeat_payload";
	}

	/*
	* This is effectively the default case for the switch above, but we
	* leave it out so that when an alert type is added to the enum the
	* compiler can warn us that it is not included in the switch
	* statement.
	*/
	return "unrecognized_alert_" ~ std.conv.to!string(type());
}

}

}