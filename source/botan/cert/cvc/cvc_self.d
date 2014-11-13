/*
* CVC Self-Signed Certificate
* (C) 2007 FlexSecure GmbH
*	  2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.cvc.cvc_self;

import botan.pubkey.pkcs8;
import botan.asn1.oid_lookup.oids;
import botan.pubkey.algo.ecdsa;
import botan.asn1.asn1_obj;
import botan.cert.cvc.cvc_cert;
import botan.cert.cvc.cvc_req;
import botan.cert.cvc.cvc_ado;
import botan.pubkey.pubkey;
import botan.pubkey.algo.ecc_key;
import botan.math.ec_gfp.curve_gfp;
import botan.cert.cvc.eac_asn_obj;
import botan.rng.rng;
import botan.utils.types;
import std.array : Appender;


/**
* This class represents a set of options used for the creation of CVC certificates
*/
struct EAC1_1_CVC_Options
{
public:

	ASN1_Car car;
	ASN1_Chr chr;
	ubyte holder_auth_templ;
	ASN1_Ced ced;
	ASN1_Cex cex;
	string hash_alg;
}

/**
* Create a selfsigned CVCA
* @param rng the rng to use
* @param key the ECDSA private key to be used to sign the certificate
* @param opts used to set several parameters. Necessary are:
* car, holder_auth_templ, hash_alg, ced, cex and hash_alg
* @result the self signed certificate
*/
EAC1_1_CVC create_self_signed_cert(const ref Private_Key key,
                                   const ref EAC1_1_CVC_Options opt,
                                   RandomNumberGenerator rng)
{
	// NOTE: we ignore the value of opt.chr
	
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(key);
	
	if (priv_key == 0)
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	
	ASN1_Chr chr(opt.car.value());
	
	Algorithm_Identifier sig_algo;
	string padding_and_hash = "EMSA1_BSI(" ~ opt.hash_alg ~ ")";
	sig_algo.oid = oids.lookup(priv_key.algo_name ~ "/" ~ padding_and_hash);
	sig_algo = Algorithm_Identifier(sig_algo.oid, Algorithm_Identifier.USE_NULL_PARAM);
	
	PK_Signer signer = PK_Signer(*priv_key, padding_and_hash);
	
	Vector!ubyte enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);
	
	return make_cvc_cert(signer,
	                     enc_public_key,
	                     opt.car, chr,
	                     opt.holder_auth_templ,
	                     opt.ced, opt.cex, rng);
}


/**
* Create a CVC request. The key encoding will be according to the provided private key.
* @param priv_key the private key associated with the requesting entity
* @param chr the chr to appear in the certificate (to be provided without
* sequence number)
* @param hash_alg the string defining the hash algorithm to be used for the creation
* of the signature
* @param rng the rng to use
* @result the new request
*/
EAC1_1_Req create_cvc_req(const ref Private_Key key,
                          const ref ASN1_Chr chr,
                          const ref string hash_alg,
                          RandomNumberGenerator rng)
{
	
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(&key);
	if (priv_key == 0)
	{
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	}
	Algorithm_Identifier sig_algo;
	string padding_and_hash = "EMSA1_BSI(" ~ hash_alg ~ ")";
	sig_algo.oid = oids.lookup(priv_key.algo_name ~ "/" ~ padding_and_hash);
	sig_algo = Algorithm_Identifier(sig_algo.oid, Algorithm_Identifier.USE_NULL_PARAM);
	
	PK_Signer signer = PK_Signer(*priv_key, padding_and_hash);
	
	Vector!ubyte enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);
	
	Vector!ubyte enc_cpi;
	enc_cpi.push_back(0x00);
	Vector!ubyte tbs = DER_Encoder()
		.encode(enc_cpi, ASN1_Tag.OCTET_STRING, ASN1_Tag(41), ASN1_Tag.APPLICATION)
			.raw_bytes(enc_public_key)
			.encode(chr)
			.get_contents_unlocked();
	
	Vector!ubyte signed_cert = EAC1_1_gen_CVC!EAC1_1_Req.make_signed(signer,
								                                     EAC1_1_gen_CVC!EAC1_1_Req.build_cert_body(tbs),
	                                                                 rng);
	
	auto source = scoped!DataSource_Memory(signed_cert);
	return EAC1_1_Req(source);
}

/**
* Create an ADO from a request object.
* @param priv_key the private key used to sign the ADO
* @param req the request forming the body of the ADO
* @param car the CAR forming the body of the ADO, i.e. the
* CHR of the entity associated with the provided private key
* @param rng the rng to use
*/
EAC1_1_ADO create_ado_req(const ref Private_Key key,
                          in EAC1_1_Req req,
                          const ref ASN1_Car car,
                          RandomNumberGenerator rng)
{
	
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(&key);
	if (priv_key == 0)
	{
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	}
	
	string padding_and_hash = padding_and_hash_from_oid(req.signature_algorithm().oid);
	PK_Signer signer = PK_Signer(*priv_key, padding_and_hash);
	Vector!ubyte tbs_bits = req.BER_encode();
	tbs_bits += DER_Encoder().encode(car).get_contents();
	
	Vector!ubyte signed_cert = EAC1_1_ADO.make_signed(signer, tbs_bits, rng);
	
	auto source = scoped!DataSource_Memory(signed_cert);
	return EAC1_1_ADO(source);
}


/**
* Create a CVCA certificate.
* @param priv_key the private key associated with the CVCA certificate
* to be created
* @param hash the string identifying the hash algorithm to be used
* for signing the certificate to be created
* @param car the CAR of the certificate to be created
* @param iris indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical iris image
* @param fingerpr indicates whether the entity associated with the certificate
* shall be entitled to read the biometrical fingerprint image
* @param cvca_validity_months length of time in months this will be valid
* @param rng a random number generator
* @result the CVCA certificate created
*/
EAC1_1_CVC create_cvca(const ref Private_Key key,
                       const ref string hash,
                       const ref ASN1_Car car, bool iris, bool fingerpr,
                       uint cvca_validity_months,
                       RandomNumberGenerator rng)
{
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(&key);
	if (priv_key == 0)
	{
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	}
	EAC1_1_CVC_Options opts;
	opts.car = car;
	
	opts.ced = ASN1_Ced(Clock.currTime());
	opts.cex = ASN1_Cex(opts.ced);
	opts.cex.add_months(cvca_validity_months);
	opts.holder_auth_templ = (CVCA | (iris * IRIS) | (fingerpr * FINGERPRINT));
	opts.hash_alg = hash;
	return create_self_signed_cert(*priv_key, opts, rng);
}


/**
* Create a link certificate between two CVCA certificates. The key
* encoding will be implicitCA.
* @param signer the cvca certificate associated with the signing
* entity
* @param priv_key the private key associated with the signer
* @param to_be_signed the certificate which whose CAR/CHR will be
* the holder of the link certificate
* @param rng a random number generator
*/
EAC1_1_CVC link_cvca(const ref EAC1_1_CVC signer,
                     const ref Private_Key key,
                     const ref EAC1_1_CVC signee,
                     RandomNumberGenerator rng)
{
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(&key);
	
	if (priv_key == 0)
		throw new Invalid_Argument("link_cvca(): unsupported key type");
	
	ASN1_Ced ced = ASN1_Ced(Clock.currTime());
	ASN1_Cex cex = ASN1_Cex(signee.get_cex());
	if (*cast(EAC_Time*)(&ced) > *cast(EAC_Time*)(&cex))
	{
		Appender!string detail = "link_cvca(): validity periods of provided certificates don't overlap: currend time = ced = ";
		detail ~= ced.toString();
		detail ~= ", signee.cex = ";
		detail ~= cex.toString();
		throw new Invalid_Argument(detail.data);
	}
	if (signer.signature_algorithm() != signee.signature_algorithm())
	{
		throw new Invalid_Argument("link_cvca(): signature algorithms of signer and signee don't match");
	}
	Algorithm_Identifier sig_algo = signer.signature_algorithm();
	string padding_and_hash = padding_and_hash_from_oid(sig_algo.oid);
	PK_Signer pk_signer = PK_Signer(*priv_key, padding_and_hash);
	Unique!Public_Key pk = signee.subject_public_key();
	ECDSA_PublicKey subj_pk = cast(ECDSA_PublicKey)(*pk);
	subj_pk.set_parameter_encoding(EC_DOMPAR_ENC_EXPLICIT);
	
	Vector!ubyte enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);
	
	return make_cvc_cert(pk_signer, enc_public_key,
	                     signer.get_car(),
	                     signee.get_chr(),
	                     signer.get_chat_value(),
	                     ced, cex,
	                     rng);
}

/**
* Create a CVC request. The key encoding will be implicitCA.
* @param priv_key the private key associated with the requesting entity
* @param chr the chr to appear in the certificate (to be provided without
* sequence number)
* @param hash_alg the string defining the hash algorithm to be used for the creation
* of the signature
* @param rng a random number generator
* @result the new request
*/
EAC1_1_Req create_cvc_req_implicitca(const ref Private_Key prkey,
                          const ref ASN1_Chr chr,
                          const ref string hash_alg,
                          RandomNumberGenerator rng)
{
	const ECDSA_PrivateKey priv_key = cast(const ECDSA_PrivateKey)(&prkey);
	if (priv_key == 0)
	{
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	}
	ECDSA_PrivateKey key = *priv_key;
	key.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
	return create_cvc_req(key, chr, hash_alg, rng);
}

/**
* Sign a CVC request.
* @param signer_cert the certificate of the signing entity
* @param priv_key the private key of the signing entity
* @param req the request to be signed
* @param seqnr the sequence number of the certificate to be created
* @param seqnr_len the number of digits the sequence number will be
* encoded in
* @param domestic indicates whether to sign a domestic or a foreign
* certificate: set to true for domestic
* @param dvca_validity_months validity period in months
* @param ca_is_validity_months validity period in months
* @param rng a random number generator
* @result the new certificate
*
**/

EAC1_1_CVC sign_request(const ref EAC1_1_CVC signer_cert,
                        const ref Private_Key key,
                        in EAC1_1_Req signee,
                        uint seqnr,
                        uint seqnr_len,
                        bool domestic,
                        uint dvca_validity_months,
                        uint ca_is_validity_months,
                        RandomNumberGenerator rng)
{
	const ECDSA_PrivateKey  priv_key = cast(const ECDSA_PrivateKey)(&key);
	if (priv_key == 0)
	{
		throw new Invalid_Argument("CVC_EAC::create_self_signed_cert(): unsupported key type");
	}
	string chr_str = signee.get_chr().value();
	
	string seqnr_string = std.conv.to!string(seqnr);
	
	while(seqnr_string.length < seqnr_len)
		seqnr_string = '0' + seqnr_string;
	
	chr_str += seqnr_string;
	ASN1_Chr chr = ASN1_Chr(chr_str);
	string padding_and_hash = padding_and_hash_from_oid(signee.signature_algorithm().oid);
	PK_Signer pk_signer = PK_Signer(*priv_key, padding_and_hash);
	Unique!Public_Key pk = signee.subject_public_key();
	ECDSA_PublicKey  subj_pk = cast(ECDSA_PublicKey)(*pk);
	// Unique!Public_Key signer_pk = signer_cert.subject_public_key();
	
	// for the case that the domain parameters are not set...
	// (we use those from the signer because they must fit)
	//subj_pk.set_domain_parameters(priv_key.domain_parameters());
	
	subj_pk.set_parameter_encoding(EC_DOMPAR_ENC_IMPLICITCA);
	
	Algorithm_Identifier sig_algo = Algorithm_Identifier(signer_cert.signature_algorithm());
	
	ASN1_Ced ced = ASN1_Ced(Clock.currTime());
	
	uint chat_val;
	uint chat_low = signer_cert.get_chat_value() & 0x3; // take the chat rights from signer
	ASN1_Cex cex(ced);
	if ((signer_cert.get_chat_value() & CVCA) == CVCA)
	{
		// we sign a dvca
		cex.add_months(dvca_validity_months);
		if (domestic)
			chat_val = DVCA_domestic | chat_low;
		else
			chat_val = DVCA_foreign | chat_low;
	}
	else if ((signer_cert.get_chat_value() & DVCA_domestic) == DVCA_domestic ||
	         (signer_cert.get_chat_value() & DVCA_foreign) == DVCA_foreign)
	{
		cex.add_months(ca_is_validity_months);
		chat_val = IS | chat_low;
	}
	else
	{
		throw new Invalid_Argument("sign_request(): encountered illegal value for CHAT");
		// (IS cannot sign certificates)
	}
	
	Vector!ubyte enc_public_key = eac_1_1_encoding(priv_key, sig_algo.oid);
	
	return make_cvc_cert(pk_signer, enc_public_key,
	                     ASN1_Car(signer_cert.get_chr().iso_8859()),
	                     chr,
	                     chat_val,
	                     ced,
	                     cex,
	                     rng);
}

/*
* cvc CHAT values
*/
typedef ubyte CHAT_values;
enum : CHAT_values {
	CVCA = 0xC0,
	DVCA_domestic = 0x80,
	DVCA_foreign =  0x40,
	IS	= 0x00,
	
	IRIS = 0x02,
	FINGERPRINT = 0x01
}

void encode_eac_bigint(ref DER_Encoder der, const ref BigInt x, ASN1_Tag tag)
{
	der.encode(BigInt.encode_1363(x, x.bytes()), ASN1_Tag.OCTET_STRING, tag);
}

Vector!ubyte eac_1_1_encoding(const EC_PublicKey* key,
                              const ref OID sig_algo)
{
	if (key.domain_format() == EC_DOMPAR_ENC_OID)
		throw new Encoding_Error("CVC encoder: cannot encode parameters by OID");
	
	const EC_Group domain = key.domain();
	
	// This is why we can't have nice things
	
	DER_Encoder enc;
	enc.start_cons(ASN1_Tag(73), ASN1_Tag.APPLICATION)
		.encode(sig_algo);
	
	if (key.domain_format() == EC_DOMPAR_ENC_EXPLICIT)
	{
		encode_eac_bigint(enc, domain.get_curve().get_p(), ASN1_Tag(1));
		encode_eac_bigint(enc, domain.get_curve().get_a(), ASN1_Tag(2));
		encode_eac_bigint(enc, domain.get_curve().get_b(), ASN1_Tag(3));
		
		enc.encode(EC2OSP(domain.get_base_point(), PointGFp.UNCOMPRESSED),
		           ASN1_Tag.OCTET_STRING, ASN1_Tag(4));
		
		encode_eac_bigint(enc, domain.get_order(), ASN1_Tag(4));
	}
	
	enc.encode(EC2OSP(key.public_point(), PointGFp.UNCOMPRESSED),
	           ASN1_Tag.OCTET_STRING, ASN1_Tag(6));
	
	if (key.domain_format() == EC_DOMPAR_ENC_EXPLICIT)
		encode_eac_bigint(enc, domain.get_cofactor(), ASN1_Tag(7));
	
	enc.end_cons();
	
	return enc.get_contents_unlocked();
}

string padding_and_hash_from_oid(const ref OID oid)
{
	string padding_and_hash = oids.lookup(oid); // use the hash
	
	if (padding_and_hash.substr(0,6) != "ECDSA/")
		throw new Invalid_State("CVC: Can only use ECDSA, not " ~ padding_and_hash);
	
	padding_and_hash.erase(0, padding_and_hash.find("/") + 1);
	return padding_and_hash;
}