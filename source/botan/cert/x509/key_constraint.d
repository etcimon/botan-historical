/*
* Enumerations
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.cert.x509.key_constraint;

import botan.constants;
static if (BOTAN_HAS_X509_CERTIFICATES):

import botan.asn1.ber_dec;
import botan.pubkey.x509_key;
import botan.asn1.ber_dec;

/**
* X.509v3 Key Constraints.
*/
enum KeyConstraints {
    NO_CONSTRAINTS      = 0,
    DIGITAL_SIGNATURE  = 32768,
    NON_REPUDIATION     = 16384,
    KEY_ENCIPHERMENT    = 8192,
    DATA_ENCIPHERMENT  = 4096,
    KEY_AGREEMENT        = 2048,
    KEY_CERT_SIGN        = 1024,
    CRL_SIGN              = 512,
    ENCIPHER_ONLY        = 256,
    DECIPHER_ONLY        = 128
}

/**
* Create the key constraints for a specific public key.
* @param pub_key = the public key from which the basic set of
* constraints to be placed in the return value is derived
* @param limits = additional limits that will be incorporated into the
* return value
* @return combination of key type specific constraints and
* additional limits
*/
KeyConstraints findConstraints(in PublicKey pub_key,
                                 KeyConstraints limits)
{
    const string name = pub_key.algo_name;
    
    size_t constraints = 0;
    
    if (name == "DH" || name == "ECDH")
        constraints |= KEY_AGREEMENT;
    
    if (name == "RSA" || name == "ElGamal")
        constraints |= KEY_ENCIPHERMENT | DATA_ENCIPHERMENT;
    
    if (name == "RSA" || name == "RW" || name == "NR" ||
        name == "DSA" || name == "ECDSA")
        constraints |= DIGITAL_SIGNATURE | NON_REPUDIATION;
    
    if (limits)
        constraints &= limits;
    
    return KeyConstraints(constraints);
}

/*
* Decode a BER encoded KeyUsage
*/
void decode(BERDecoder source, ref KeyConstraints key_usage)
{
    BER_Object obj = source.getNextObject();

    if (obj.type_tag != ASN1Tag.BIT_STRING || obj.class_tag != ASN1Tag.UNIVERSAL)
        throw new BERBadTag("Bad tag for usage constraint",
                              obj.type_tag, obj.class_tag);
    if (obj.value.length != 2 && obj.value.length != 3)
        throw new BERDecodingError("Bad size for BITSTRING in usage constraint");
    if (obj.value[0] >= 8)
        throw new BERDecodingError("Invalid unused bits in usage constraint");
    
    const ubyte mask = (0xFF << obj.value[0]);
    obj.value[obj.value.length-1] &= mask;
    
    ushort usage = 0;
    for (size_t j = 1; j != obj.value.length; ++j)
        usage = (obj.value[j] << 8) | usage;
    
    key_usage = KeyConstraints(usage);
}