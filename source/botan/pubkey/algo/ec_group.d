/*
* ECC Domain Parameters
*
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*	  2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.ec_group;

import botan.math.ec_gfp.curve_gfp;
import botan.math.ec_gfp.point_gfp;
import botan.math.bigint.bigint;
import botan.asn1.asn1_oid;
import botan.asn1.ber_dec;
import botan.asn1.der_enc;
import botan.libstate.libstate;
import botan.asn1.oid_lookup.oids;
import botan.codec.pem;

typedef ubyte EC_Group_Encoding;
/**
* This class represents elliptic curce domain parameters
*/
enum : EC_Group_Encoding {
	EC_DOMPAR_ENC_EXPLICIT = 0,
	EC_DOMPAR_ENC_IMPLICITCA = 1,
	EC_DOMPAR_ENC_OID = 2
}

/**
* Class representing an elliptic curve
*/
struct EC_Group
{
public:

	/**
	* Construct Domain paramers from specified parameters
	* @param curve elliptic curve
	* @param base_point a base point
	* @param order the order of the base point
	* @param cofactor the cofactor
	*/
	this(in CurveGFp _curve,
				const ref PointGFp _base_point,
				const ref BigInt _order,
				const ref BigInt _cofactor) 
	{
		curve = _curve;
		base_point = _base_point;
		order = _order;
		cofactor = _cofactor;
		oid = "";
	}

	/**
	* Decode a BER encoded ECC domain parameter set
	* @param ber_data the bytes of the BER encoding
	*/
	this(in Vector!ubyte ber_data)
	{
		BER_Decoder ber(ber_data);
		BER_Object obj = ber.get_next_object();
		
		if (obj.type_tag == ASN1_Tag.NULL_TAG)
			throw new Decoding_Error("Cannot handle ImplicitCA ECDSA parameters");
		else if (obj.type_tag == ASN1_Tag.OBJECT_ID)
		{
			OID dom_par_oid;
			BER_Decoder(ber_data).decode(dom_par_oid);
			this(dom_par_oid);
		}
		else if (obj.type_tag == ASN1_Tag.SEQUENCE)
		{
			BigInt p, a, b;
			Vector!ubyte sv_base_point;
			
			BER_Decoder(ber_data)
				.start_cons(ASN1_Tag.SEQUENCE)
					.decode_and_check!size_t(1, "Unknown ECC param version code")
					.start_cons(ASN1_Tag.SEQUENCE)
					.decode_and_check(OID("1.2.840.10045.1.1"),
					                  "Only prime ECC fields supported")
					.decode(p)
					.end_cons()
					.start_cons(ASN1_Tag.SEQUENCE)
					.decode_octet_string_bigint(a)
					.decode_octet_string_bigint(b)
					.end_cons()
					.decode(sv_base_point, ASN1_Tag.OCTET_STRING)
					.decode(order)
					.decode(cofactor)
					.end_cons()
					.verify_end();
			
			curve = CurveGFp(p, a, b);
			base_point = OS2ECP(sv_base_point, curve);
		}
		else
			throw new Decoding_Error("Unexpected tag while decoding ECC domain params");
	}

	/**
	* Create an EC domain by OID (or throw new if unknown)
	* @param oid the OID of the EC domain to create
	*/
	this(in OID domain_oid)
	{
		string pem = PEM_for_named_group(oids.lookup(domain_oid));
		
		if (!pem)
			throw new Lookup_Error("No ECC domain data for " ~ domain_oid.toString());
		
		this(pem);
		oid = domain_oid.toString();
	}

	/**
	* Create an EC domain from PEM encoding (as from PEM_encode), or
	* from an OID name (eg "secp256r1", or "1.2.840.10045.3.1.7")
	* @param pem_or_oid PEM-encoded data, or an OID
	*/
	this(in string pem_or_oid = "")
	{
		if (pem_or_oid == "")
			return; // no initialization / uninitialized
		
		try
		{
			Vector!ubyte ber =
				unlock(pem.decode_check_label(pem_or_oid, "EC PARAMETERS"));
			
			this(ber);
		}
		catch(Decoding_Error) // hmm, not PEM?
		{
			this(oids.lookup(pem_or_oid));
		}
	}

	/**
	* Create the DER encoding of this domain
	* @param form of encoding to use
	* @returns bytes encododed as DER
	*/
	Vector!ubyte DER_encode(EC_Group_Encoding form) const
	{
		if (form == EC_DOMPAR_ENC_EXPLICIT)
		{
			const size_t ecpVers1 = 1;
			OID curve_type("1.2.840.10045.1.1");
			
			const size_t p_bytes = curve.get_p().bytes();
			
			return DER_Encoder()
				.start_cons(ASN1_Tag.SEQUENCE)
					.encode(ecpVers1)
					.start_cons(ASN1_Tag.SEQUENCE)
					.encode(curve_type)
					.encode(curve.get_p())
					.end_cons()
					.start_cons(ASN1_Tag.SEQUENCE)
					.encode(BigInt.encode_1363(curve.get_a(), p_bytes),
					        ASN1_Tag.OCTET_STRING)
					.encode(BigInt.encode_1363(curve.get_b(), p_bytes),
					        ASN1_Tag.OCTET_STRING)
					.end_cons()
					.encode(EC2OSP(base_point, PointGFp.UNCOMPRESSED), ASN1_Tag.OCTET_STRING)
					.encode(order)
					.encode(cofactor)
					.end_cons()
					.get_contents_unlocked();
		}
		else if (form == EC_DOMPAR_ENC_OID)
			return DER_Encoder().encode(OID(get_oid())).get_contents_unlocked();
		else if (form == EC_DOMPAR_ENC_IMPLICITCA)
			return DER_Encoder().encode_null().get_contents_unlocked();
		else
			throw new Internal_Error("EC_Group::DER_encode: Unknown encoding");
	}

	/**
	* Return the PEM encoding (always in explicit form)
	* @return string containing PEM data
	*/
	string PEM_encode() const
	{
		const Vector!ubyte der = DER_encode(EC_DOMPAR_ENC_EXPLICIT);
		return pem.encode(der, "EC PARAMETERS");
	}

	/**
	* Return domain parameter curve
	* @result domain parameter curve
	*/
	const ref CurveGFp get_curve() const { return curve; }

	/**
	* Return domain parameter curve
	* @result domain parameter curve
	*/
	const ref PointGFp get_base_point() const { return base_point; }

	/**
	* Return the order of the base point
	* @result order of the base point
	*/
	const ref BigInt get_order() const { return order; }

	/**
	* Return the cofactor
	* @result the cofactor
	*/
	const ref BigInt get_cofactor() const { return cofactor; }

	bool initialized() const { return !base_point.is_zero(); }

	/**
	* Return the OID of these domain parameters
	* @result the OID
	*/
	string get_oid() const { return oid; }
	bool opCmp(string op)(const ref EC_Group rhs)
		if (op == "!=")
	{
		return !(lhs == rhs);
	}

	bool opEquals(in EC_Group other) const
	{
		return ((get_curve() == other.get_curve()) &&
				  (get_base_point() == other.get_base_point()) &&
				  (get_order() == other.get_order()) &&
				  (get_cofactor() == other.get_cofactor()));
	}

	/**
	* Return PEM representation of named EC group
	*/
	static string PEM_for_named_group(in string name)
	{
		if (name == "secp112r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MHQCAQEwGgYHKoZIzj0BAQIPANt8Kr9i415mgHa+rSCLMCAEDtt8Kr9i415mgHa+"
				"rSCIBA5lnvi6BDkW7t6JEXArIgQdBAlIcjmZWl7na1X5wvCYqJzlr4ckwKI+Dg/3"
				"dQACDwDbfCq/YuNedijfrGVhxQIBAQ=="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp112r2")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MHMCAQEwGgYHKoZIzj0BAQIPANt8Kr9i415mgHa+rSCLMCAEDmEnwkwF84oKqvZc"
				"DvAsBA5R3vGBXbXtdPzDTIXXCQQdBEujCrXokrThZJ3QkoZDrc1G9YguN0fe826V"
				"bpcCDjbfCq/YuNdZfKEFINBLAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "secp128r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGAAgEBMBwGByqGSM49AQECEQD////9////////////////MCQEEP////3/////"
				"//////////wEEOh1ecEQefQ92CSZPCzuXtMEIQQWH/dSi4mbLQwoYHylLFuGz1rI"
				"OVuv6xPALaKS3e16gwIRAP////4AAAAAdaMNG5A4oRUCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp128r2")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MH8CAQEwHAYHKoZIzj0BAQIRAP////3///////////////8wJAQQ1gMZmNGzu/6/"
				"Wcybv/mu4QQQXu78o4DQKRncLGVYu22KXQQhBHtqpdheVymD5vsyp83rwUAntpFq"
				"iU067nEG/oBfw0tEAhA/////f////74AJHIGE7WjAgEE"
				"-----END EC PARAMETERS-----";
		
		if (name == "secp160k1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBQAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAQUAAAAAAAAAAAAAAAAAAAAAAAAAAcEKQQ7TDgs43qh"
				"kqQBnnYwNvT13U1+u5OM+TUxj9zta8KChlMXM8PwPE/uAhUBAAAAAAAAAAAAAbj6"
				"Ft+rmsoWtrMCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp160r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGYAgEBMCAGByqGSM49AQECFQD/////////////////////f////zAsBBT/////"
				"////////////////f////AQUHJe+/FS9eotlrPifgdTUrcVl+kUEKQRKlrVojvVz"
				"KEZkaYlow4u5E8v8giOmKFUxaJR9WdzJEgQjUTd6xfsyAhUBAAAAAAAAAAAAAfTI"
				"+Seu08p1IlcCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp160r2")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGYAgEBMCAGByqGSM49AQECFQD////////////////////+//+sczAsBBT/////"
				"///////////////+//+scAQUtOE00/tZ64urVydJBGZNWvUDiLoEKQRS3LA0KToR"
				"fh9P8Rsw9xmdMUTObf6v/vLjMfKW4HH6DfmYLP6n1D8uAhUBAAAAAAAAAAAAADUe"
				"54aoGPOhoWsCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp192k1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGwAgEBMCQGByqGSM49AQECGQD//////////////////////////v//7jcwNAQY"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBgAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAMEMQTbT/EOwFfpriawfQKAt/Q0HaXRsergbH2bLy9tnFYop4RBY9AVvoY0QIKq"
				"iNleL50CGQD///////////////4m8vwXD2lGanTe/Y0CAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp192r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
				"/////////////////////v/////////8BBhkIQUZ5ZyA5w+n6atyJDBJ/rje7MFG"
				"ubEEMQQYjagOsDCQ9ny/IOtDoYgA9P8K/YL/EBIHGSuV/8jaeGMQEe1rJM3Vc/l3"
				"oR55SBECGQD///////////////+Z3vg2FGvJsbTSKDECAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp224k1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHIAgEBMCgGByqGSM49AQECHQD///////////////////////////////7//+Vt"
				"MDwEHAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEHAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAUEOQShRVszTfCZ3zD8KKFppGfp5HB1qQ9+ZQ62t6Rcfgif"
				"7X+6NEKCyvvW9+MZ98CwvVniykvbVW1hpQIdAQAAAAAAAAAAAAAAAAAB3OjS7GGE"
				"yvCpcXafsfcCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp224r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHIAgEBMCgGByqGSM49AQECHQD/////////////////////AAAAAAAAAAAAAAAB"
				"MDwEHP////////////////////7///////////////4EHLQFCoUMBLOr9UEyVlBE"
				"sLfXv9i6Jws5QyNV/7QEOQS3Dgy9a7S/fzITkLlKA8HTVsIRIjQygNYRXB0hvTdj"
				"iLX3I/tMIt/mzUN1oFoHR2RE1YGZhQB+NAIdAP//////////////////FqLguPA+"
				"E90pRVxcKj0CAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp256k1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHgAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+"
				"///8LzBEBCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQgAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAcEQQR5vmZ++dy7rFWgYpXOhwsHApv8"
				"2y3OKNlZ8oFbFvgXmEg62ncmo8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA"
				"/////////////////////rqu3OavSKA7v9JejNA2QUECAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp256r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHgAgEBMCwGByqGSM49AQECIQD/////AAAAAQAAAAAAAAAAAAAAAP//////////"
				"/////zBEBCD/////AAAAAQAAAAAAAAAAAAAAAP///////////////AQgWsY12Ko6"
				"k+ez671VdpiGvGUdBrDMU7D2O848PifSYEsEQQRrF9Hy4SxCR/i85uVjpEDydwN9"
				"gS3rM6D0oTlF2JjClk/jQuL+Gn+bjufrSnwPnhYrzjNXazFezsu2QGg3v1H1AiEA"
				"/////wAAAAD//////////7zm+q2nF56E87nKwvxjJVECAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "secp384r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBQAIBATA8BgcqhkjOPQEBAjEA////////////////////////////////////"
				"//////7/////AAAAAAAAAAD/////MGQEMP//////////////////////////////"
				"///////////+/////wAAAAAAAAAA/////AQwszEvp+I+5+SYjgVr4/gtGRgdnG7+"
				"gUESAxQIj1ATh1rGVjmNii7RnSqFyO3T7CrvBGEEqofKIr6LBTeOscce8yCtdG4d"
				"O2KLp5uYWfdB4IJUKjhVAvJdv1UpbDpUXjhydgq3NhfeSpYmLG9dnpi/kpLcKfj0"
				"Hb0omhR86doxE7XwuMAKYLHOHX6BnXpDHXyQ6g5fAjEA////////////////////"
				"////////////x2NNgfQ3Ld9YGg2ySLCneuzsGWrMxSlzAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "secp521r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBrAIBATBNBgcqhkjOPQEBAkIB////////////////////////////////////"
				"//////////////////////////////////////////////////8wgYgEQgH/////"
				"////////////////////////////////////////////////////////////////"
				"/////////////////ARCAFGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ"
				"4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8ABIGFBADGhY4GtwQE6c2e"
				"PstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5"
				"fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQm"
				"QMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////"
				"////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "1.3.6.1.4.1.8301.3.1.2.9.0.38")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBrAIBATBNBgcqhkjOPQEBAkIB////////////////////////////////////"
				"//////////////////////////////////////////////////8wgYgEQgH/////"
				"////////////////////////////////////////////////////////////////"
				"/////////////////ARCAFGVPrlhjhyaH5KaIaC2hUDuotpyW5mzFfO4tImRjvEJ"
				"4VYZOVHsfpN7FlLAvTuxvwc1c9+IPSw08e9FH9RrUD8ABIGFBADGhY4GtwQE6c2e"
				"PstmI5W0QpxkgTkFP7Uh+CivYGtNPbqhS1537+dZKP4dwSei/6jeM0izwYVqQpv5"
				"fn4xwuW9ZgEYOSlqeJo7wARcil+0LH0b2Zj1RElXm0RoF6+9Fyc+ZiyX7nKZXvQm"
				"QMVQuQE/rQdhNTxwhqJywkCIvpR2n9FmUAJCAf//////////////////////////"
				"////////////////+lGGh4O/L5Zrf8wBSPcJpdA7tcm4iZxHrrtvtx6ROGQJAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool160r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGYAgEBMCAGByqGSM49AQECFQDpXkpfc3BZ3GDfx62Vs9gTlRViDzAsBBQ0Dnvi"
				"ooDrdOK+YbradF2X6PfDAAQUHliahZVCNBITT6otveyVyNhnXlgEKQS+1a8W6j9q"
				"T2KTjEYx61r3vbzbwxZny0d6Go7DOPlHQWacl2MW2mMhAhUA6V5KX3NwWdxg31mR"
				"1FApQJ5g/AkCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool192r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGwAgEBMCQGByqGSM49AQECGQDDAvQdkyo2zaejRjCT0Y23j85HbeGoYpcwNAQY"
				"apEXQHax4OGcOcAx/oaFwcrgQOXGmijvBBhGmijvfCjMo9xyHQRPRJa8yn70FG+/"
				"JckEMQTAoGR+qrakh1OwM8VssPCQCi9cSFM3X9YUtpCGar1buItfSCjBSQAC5nc/"
				"ovopm48CGQDDAvQdkyo2zaejRi+enpFrW+jxAprErMECAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool224r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHIAgEBMCgGByqGSM49AQECHQDXwTSqJkNmhioYMCV10deHsJ8HV5faifV+yMD/"
				"MDwEHGil5iypzmwcKZgDpsFTC1FOGCrYsAQqWcrSn0MEHCWA9jzP5EE4hwcTsakj"
				"aeM+ITXSZtuzcjhsQAsEOQQNkCmtLH5c9DQII7KofcaMnkzjF0webv3uEsB9WKpW"
				"93LAcm8kxrieTs2sJDVLnpnKo/bTdhQCzQIdANfBNKomQ2aGKhgwJXXQ+5jRFrxL"
				"bd68o6Wnk58CAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool256r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHgAgEBMCwGByqGSM49AQECIQCp+1fboe6pvD5mCpCdg41ybjv2I9UmICggE0gd"
				"H25TdzBEBCB9Wgl1/CwwV+72dTBBev/n+4BVwSbcXGzpSktE8zC12QQgJtxcbOlK"
				"S0TzMLXZu9d8v5WEFilc9+HOa8zcGP+MB7YEQQSL0q65y35XyyxLSC/8gbevud4n"
				"4eO9I8I6RFO9ms4yYlR++DXD2sT9l/hGGhRhHcnCd0UTLe2OVFwdVMcvBGmXAiEA"
				"qftX26Huqbw+ZgqQnYONcYw5eqO1Yab3kB4OgpdIVqcCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool320r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBEAIBATA0BgcqhkjOPQEBAikA015HIDa8T7fhPHhe0gHgZfmPz6b29A3vT5K5"
				"7HiT7Cj81BKx8bMuJzBUBCg+4wtWj7qw+IPM69RtPzu4oqc1E/XredpmGQ6whf+p"
				"9JLzdal9hg60BChSCIOUnf28QtOtGYZAaIpv4T9BNJVUtJrMMdzNiEU5gW9etKyP"
				"sfGmBFEEQ71+mvtT2LhSibzEjuW/5vIBN9EKCH6254ceKhClmccQr40NOeIGERT9"
				"0FVF7BzIq0CTJH93J14HQ//tEXGC6qnHeHeqrGrH01JF0WkujuECKQDTXkcgNrxP"
				"t+E8eF7SAeBl+Y/PpbaPEqMtSC7H7oZY6YaRVVtExZMRAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool384r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBQAIBATA8BgcqhkjOPQEBAjEAjLkegqM4bSgPXW9+UOZB3xUvcQntVFa0ErHa"
				"GX+3ESOs06cpkB0acYdHABMxB+xTMGQEMHvDgsY9jBUMPHIICs4Fr6DCvqKOT7In"
				"hxORZe+6kfkPiqWBSlA61OsEqMfdIs4oJgQwBKjH3SLOKCaLObVUFvBEfC+3feEH"
				"3NKmLogOpT7rYtV8tDkCldvJlDq3hpb6UEwRBGEEHRxk8GjPRf+ipjqBt8E/a4hH"
				"o+d+8U/j23/K/gy9EOjoJuA0NtZGqu+HsuJH1K8eir4ddSD5wqRcseuOlc/VUmK3"
				"Cyn+7Fhk4ZwFT/mRKSgORkYhd5GBEUKCA0EmPFMVAjEAjLkegqM4bSgPXW9+UOZB"
				"3xUvcQntVFazHxZubKwEJafPOrava3/DEDuIMgLpBGVlAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "brainpool512r1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIIBogIBATBMBgcqhkjOPQEBAkEAqt2duNvpxIs/1OauM8n8B8swjbOzydIO1mOc"
				"ynAzCHF9TZsAm8ZoQq7NoSrmo4DmKIH/Ly2CxoUoqmBWWDpI8zCBhARAeDCjMYtg"
				"O4niMnFFrCNMxZTL3Y09+RYQqDRByuqYY7wt7V1aqCU6oQou8cmLmsi1fxEXpyvy"
				"x7nnwaxNd/yUygRAPfkWEKg0QcrqmGO8Le1dWqglOqEKLvHJi5rItX8RF6cr8se5"
				"58GsTXf8lMrcCD5nmEBQt1665d0oCb1jgBb3IwSBgQSBruS92C7ZZFohMi6cTGqT"
				"he2fcLXZFsG0O2Lu9NAJjv87H3ji0NSNUNFoe5O5fV98bVBHQGpeaIs1Igm8ufgi"
				"fd44XVZjMuzA6r+pz3gi/fIJ9wAkpXsaoADFW4gfgRGy3N5JSl9IXlvKS9iKJ2Ou"
				"0corL6jwVAZ4zR4POtgIkgJBAKrdnbjb6cSLP9TmrjPJ/AfLMI2zs8nSDtZjnMpw"
				"MwhwVT5cQUypJhlBhmEZf6wQRx2x04EIXdrdtYeWgpypAGkCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "x962_p192v2")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
				"/////////////////////v/////////8BBjMItbfuVxrJeScDWNkpOWYDDk6ohZo"
				"2VMEMQTuorrn4Ul4QvLed2nP6cmJwHKtaW9IA0pldNEdabbsemcruCoIPfLysIR9"
				"6XCy3hUCGQD///////////////5fsack3IBBhkjY3TECAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "x962_p192v3")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIGwAgEBMCQGByqGSM49AQECGQD////////////////////+//////////8wNAQY"
				"/////////////////////v/////////8BBgiEj3COVoFyqdCPa7MyUdgp9RiJWvV"
				"aRYEMQR9KXeBAMZaHaF4NxZYjc4ri0rujiKPGJY4qQ8iY3M3M0tJ3LZqbcj5l4rK"
				"dkipQ7ACGQD///////////////96YtAxyD9ClPZA7BMCAQE="
				"-----END EC PARAMETERS-----";
		
		if (name == "x962_p239v1")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
				"/zBABB5///////////////9///////+AAAAAAAB///////wEHmsBbDvc8YlB0NZU"
				"khR1ynGp2y+yfR03eWGFwpQsCgQ9BA/6ljzcqIFszDO4ZCvt+QXD01hXPT8n+707"
				"PLmqr33r6OTpCl2ubkBUylMLoEZUs2gYziJrOfzLewLxrgIef///////////////"
				"f///nl6an12QcfvRUiaIkJ0LAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "x962_p239v2")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
				"/zBABB5///////////////9///////+AAAAAAAB///////wEHmF/q2gyV2y7/tUN"
				"mfAknD/uWLlLoAOMeuhMjIMvLAQ9BDivCdmHJ3BRIMkhu16eJilqPNzy81dXoOr9"
				"h7gw51sBJeTb6g7HIG2g/AHZsIEyn7VV3m70YCN9/4vkugIef///////////////"
				"gAAAz6foWUN31BTAOCG8WCBjAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "x962_p239v3")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHSAgEBMCkGByqGSM49AQECHn///////////////3///////4AAAAAAAH//////"
				"/zBABB5///////////////9///////+AAAAAAAB///////wEHiVXBfoqMGZUsfTL"
				"A9anUKMMJQEC1JiHF9m6FattPgQ9BGdoro4Yu5LPzwBclJqixtlIU9DmYLv4VLHJ"
				"UF/pWhYH5omPOQwGvB1VK60ibztvz+SLboGEma8Y4+1s8wIef///////////////"
				"f///l13rQbOmBXw8QyFGUmVRAgEB"
				"-----END EC PARAMETERS-----";
		
		if (name == "gost_256A")
			return
				"-----BEGIN EC PARAMETERS-----"
				"MIHgAgEBMCwGByqGSM49AQECIQD/////////////////////////////////////"
				"///9lzBEBCD////////////////////////////////////////9lAQgAAAAAAAA"
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKYEQQQAAAAAAAAAAAAAAAAAAAAAAAAA"
				"AAAAAAAAAAAAAAAAAY2R5HHgmJzaJ99QWkU/K3Y1KU8t3yPjsSKsyZyenx4UAiEA"
				"/////////////////////2xhEHCZWtEARYQbCbdhuJMCAQE="
				"-----END EC PARAMETERS-----";
		
		return null;
	}

private:
	CurveGFp curve;
	PointGFp base_point;
	BigInt order, cofactor;
	string oid;
}