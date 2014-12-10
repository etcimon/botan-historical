/*
* GOST 34.10-2001
* (C) 2007 Falko Strenzke, FlexSecure GmbH
*             Manuel Hartl, FlexSecure GmbH
* (C) 2008-2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.pubkey.algo.gost_3410;

import botan.constants;
static if (BOTAN_HAS_GOST_34_10_2001):

import botan.pubkey.algo.ecc_key;
import botan.pubkey.pk_ops;
import botan.pubkey.algo.gost_3410;
import botan.asn1.der_enc;
import botan.asn1.ber_dec;
import botan.math.ec_gfp.point_gfp;
import botan.rng.rng;

/**
* GOST-34.10 Public Key
*/
class GOST3410PublicKey
{
public:
    __gshared immutable string algoName = "GOST-34.10";
    /**
    * Construct a public key from a given public point.
    * @param dom_par = the domain parameters associated with this key
    * @param public_point = the public point defining this key
    */
    this(in ECGroup dom_par, in PointGFp public_point) 
    {
        m_pub = new ECPublicKey(dom_par, public_point, algoName, true, 2, null, &algorithmIdentifier, &x509SubjectPublicKey); 
    }

    /**
    * Construct from X.509 algorithm id and subject public key bits
    */
    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        OID ecc_param_id;
        
        // Also includes hash and cipher OIDs... brilliant design guys
        BERDecoder(alg_id.parameters).startCons(ASN1Tag.SEQUENCE).decode(ecc_param_id);
        
        ECGroup domain_params = ECGroup(ecc_param_id);
        
        SecureVector!ubyte bits;
        BERDecoder(key_bits).decode(bits, ASN1Tag.OCTET_STRING);
        
        const size_t part_size = bits.length / 2;
        
        // Keys are stored in little endian format (WTF)
        foreach (size_t i; 0 .. (part_size / 2))
        {
            std.algorithm.swap(bits[i], bits[part_size-1-i]);
            std.algorithm.swap(bits[part_size+i], bits[2*part_size-1-i]);
        }
        
        BigInt x = BigInt(bits.ptr, part_size);
        BigInt y = BigInt(&bits[part_size], part_size);
        
        PointFGp public_point = PointGFp(domain().getCurve(), x, y);
        m_pub = new ECPublicKey(domain_params, public_point, algoName, true, 2, null, &algorithmIdentifier, &x509SubjectPublicKey);
        assert(m_public_key.onTheCurve(), "Loaded GOST 34.10 public key is on the curve");
    }

    AlgorithmIdentifier algorithmIdentifier() const
    {
        Vector!ubyte params = DEREncoder().startCons(ASN1Tag.SEQUENCE)
                                            .encode(OID(domain().getOid()))
                                            .endCons()
                                            .getContentsUnlocked();
        
        return AlgorithmIdentifier(getOid(), params);
    }

    Vector!ubyte x509SubjectPublicKey() const
    {
        // Trust CryptoPro to come up with something obnoxious
        const BigInt x = publicPoint().getAffineX();
        const BigInt y = publicPoint().getAffineY();
        
        size_t part_size = std.algorithm.max(x.bytes(), y.bytes());
        
        Vector!ubyte bits = Vector!ubyte(2*part_size);
        
        x.binaryEncode(&bits[part_size - x.bytes()]);
        y.binaryEncode(&bits[2*part_size - y.bytes()]);
        
        // Keys are stored in little endian format (WTF)
        foreach (size_t i; 0 .. (part_size / 2))
        {
            std.algorithm.swap(bits[i], bits[part_size-1-i]);
            std.algorithm.swap(bits[part_size+i], bits[2*part_size-1-i]);
        }
        
        return DEREncoder().encode(bits, ASN1Tag.OCTET_STRING).getContentsUnlocked();
    }

    this(PublicKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    this(PrivateKey pkey) { m_pub = cast(ECPublicKey) pkey; }

    alias m_pub this;
private:
    ECPublicKey m_pub;
}

/**
* GOST-34.10 Private Key
*/
final class GOST3410PrivateKey : GOST3410PublicKey
{
public:

    this(in AlgorithmIdentifier alg_id, in SecureVector!ubyte key_bits)
    {
        m_priv = new ECPrivateKey(alg_id, key_bits, algoName, true, 2, null, &algorithmIdentifier, &x509SubjectPublicKey);
    }

    /**
    * Generate a new private key
    * @param rng = a random number generator
    * @param domain = parameters to used for this key
    * @param x = the private key; if zero, a new random key is generated
    */
    this(RandomNumberGenerator rng, in ECGroup domain, in BigInt x = 0)
    {
        m_priv = new ECPrivateKey(rng, domain, x, algoName, true, 2, null, &algorithmIdentifier, &x509SubjectPublicKey);
    }

    this(PrivateKey pkey) { m_priv = cast(ECPrivateKey) pkey; }

    alias m_priv this;
private:
    ECPrivateKey m_priv;
}

/**
* GOST-34.10 signature operation
*/
final class GOST3410SignatureOperation : Signature
{
public:    
    this(in PrivateKey pkey) {
        this(cast(ECPrivateKey) pkey);
    }

    this(in GOST3410PrivateKey pkey) {
        this(pkey.m_priv);
    }

    this(in ECPrivateKey gost_3410)
    {
        assert(gost_3410.algoName == GOST3410PublicKey.algoName);
        m_base_point = gost_3410.domain().getBasePoint();
        m_order = gost_3410.domain().getOrder();
        m_x = gost_3410.privateValue();
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

    override SecureVector!ubyte sign(in ubyte* msg, size_t msg_len,
                          RandomNumberGenerator rng)
    {
        BigInt k;
        do
            k.randomize(rng, m_order.bits()-1);
        while (k >= m_order);
        
        BigInt e = decode_littleEndian(msg, msg_len);
        
        e %= m_order;
        if (e == 0)
            e = 1;
        
        PointGFp k_times_P = m_base_point * k;
        
        assert(k_times_P.onTheCurve(),
                     "GOST 34.10 k*g is on the curve");
        
        BigInt r = k_times_P.getAffineX() % m_order;
        
        BigInt s = (r*m_x + k*e) % m_order;
        
        if (r == 0 || s == 0)
            throw new InvalidState("GOST 34.10: r == 0 || s == 0");
        
        SecureVector!ubyte output = SecureVector!ubyte(2*m_order.bytes());
        s.binaryEncode(&output[output.length / 2 - s.bytes()]);
        r.binaryEncode(&output[output.length - r.bytes()]);
        return output;
    }

private:
    const PointGFp m_base_point;
    const BigInt m_order;
    const BigInt m_x;
}

/**
* GOST-34.10 verification operation
*/
final class GOST3410VerificationOperation : Verification
{
public:
    this(in PublicKey pkey) {
        this(cast(ECPublicKey) pkey);
    }

    this(in GOST3410PublicKey pkey) {
        this(pkey.m_pub);
    }

    this(in ECPublicKey gost) 
    {
        assert(gost.algoName == GOST3410PublicKey.algoName);
        m_base_point = gost.domain().getBasePoint();
        m_public_point = gost.publicPoint();
        m_order = gost.domain().getOrder();
    }

    override size_t messageParts() const { return 2; }
    override size_t messagePartSize() const { return m_order.bytes(); }
    override size_t maxInputBits() const { return m_order.bits(); }

    override bool withRecovery() const { return false; }

    override bool verify(in ubyte* msg, size_t msg_len,
                in ubyte* sig, size_t sig_len)
    {
        if (sig_len != m_order.bytes()*2)
            return false;
        
        BigInt e = decode_littleEndian(msg, msg_len);
        
        BigInt s = BigInt(sig, sig_len / 2);
        BigInt r = BigInt(sig + sig_len / 2, sig_len / 2);
        
        if (r <= 0 || r >= m_order || s <= 0 || s >= m_order)
            return false;
        
        e %= m_order;
        if (e == 0)
            e = 1;
        
        BigInt v = inverseMod(e, m_order);
        
        BigInt z1 = (s*v) % m_order;
        BigInt z2 = (-r*v) % m_order;
        
        PointGFp R = multiExponentiate(m_base_point, z1,
                                        m_public_point, z2);
        
        if (R.isZero())
            return false;
        
        return (R.getAffineX() == r);
    }
private:
    const PointGFp m_base_point;
    const PointGFp m_public_point;
    const BigInt m_order;
}


private:

BigInt decodeLittleEndian(in ubyte* msg, size_t msg_len)
{
    SecureVector!ubyte msg_le = SecureVector!ubyte(msg, msg + msg_len);
    
    for (size_t i = 0; i != msg_le.length / 2; ++i)
        std.algorithm.swap(msg_le[i], msg_le[msg_le.length-1-i]);
    
    return BigInt(msg_le.ptr, msg_le.length);
}


static if (BOTAN_TEST):

import botan.test;
import botan.pubkey.test;
import botan.rng.auto_rng;
import botan.pubkey.pubkey;
import botan.asn1.oids;
import botan.codec.hex;
import core.atomic;

private __gshared size_t total_tests;

size_t testPkKeygen(RandomNumberGenerator rng)
{
    size_t fails;
    string[] gost_list = ["gost_256A", "secp112r1", "secp128r1", "secp160r1",
        "secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"];
    
    foreach (gost; gost_list) {
        atomicOp!"+="(total_tests, 1);
        auto key = scoped!GOST3410PrivateKey(rng, ECGroup(OIDS.lookup(gost)));
        key.checkKey(rng, true);
        fails += validateSaveAndLoad(&key, rng);
    }
    
    return fails;
}

size_t gostVerify(string group_id,
                   string x,
                   string hash,
                   string msg,
                   string signature)
{
    atomicOp!"+="(total_tests, 1);
    AutoSeededRNG rng;
    
    ECGroup group = ECGroup(OIDS.lookup(group_id));
    PointGFp public_point = OS2ECP(hexDecode(x), group.getCurve());
    
    auto gost = scoped!GOST3410PublicKey(group, public_point);
    
    const string padding = "EMSA1(" ~ hash ~ ")";
    
    PKVerifier v = PKVerifier(gost, padding);
    
    if (!v.verifyMessage(hexDecode(msg), hexDecode(signature)))
        return 1;
    
    return 0;
}

unittest
{
    size_t fails = 0;

    AutoSeededRNG rng;

    fails += testPkKeygen(rng);

    File ecdsa_sig = File("test_data/pubkey/gost_3410.vec", "r");
    
    fails += runTestsBb(ecdsa_sig, "GOST-34.10 Signature", "Signature", true,
                          (string[string] m) {
                                return gostVerify(m["Group"], m["Pubkey"], m["Hash"], m["Msg"], m["Signature"]);
                            });
    
    testReport("gost_3410", total_tests, fails);
}

