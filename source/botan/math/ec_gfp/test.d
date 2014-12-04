module botan.math.ec_gfp.test;

static if (BOTAN_TEST):

import botan.test;

import botan.codec.hex;
import botan.utils.memory.memory;
import botan.rng.auto_rng;
import botan.math.numbertheory.numthry;
import botan.math.ec_gfp.curve_gfp;
import botan.math.ec_gfp.point_gfp;
import botan.math.ec_gfp.ec_group;
import botan.math.numbertheory.reducer;
import botan.asn1.oids;
import botan.utils.types;

string toString(PointGFp point) {
    import std.array : Appender;
    Appender!string output;
    output ~= "(" ~ point.getAffineX() ~ " " ~ point.getAffineY() ~ " )";
    return output.data;
}

PointGFp createRandomPoint(RandomNumberGenerator rng, const CurveGFp curve)
{
    const BigInt p = curve.getP();
    
    ModularReducer mod_p = ModularReducer(p);
    
    while(true)
    {
        BigInt x = BigInt(rng, p.bits());
        
        BigInt x3 = mod_p.multiply(x, mod_p.square(x));
        
        BigInt ax = mod_p.multiply(curve.getA(), x);
        
        BigInt bx3 = mod_p.multiply(curve.getB(), x3);
        
        BigInt y = mod_p.reduce(ax + bx3);
        
        if (ressol(y, p) > 0)
            return PointGFp(curve, x, y);
    }
}

size_t testPointTurnOnSpRedMul()
{
    size_t fails = 0;
    
    // setting up expected values
    BigInt exp_Qx = BigInt("466448783855397898016055842232266600516272889280");
    BigInt exp_Qy = BigInt("1110706324081757720403272427311003102474457754220");
    BigInt exp_Qz = BigInt(1);
    
    // performing calculation to test
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode(p_secp);
    Vector!ubyte sv_a_secp = hexDecode(a_secp);
    Vector!ubyte sv_b_secp = hexDecode(b_secp);
    Vector!ubyte sv_G_secp_comp = hexDecode(G_secp_comp);
    BigInt bi_p_secp = BigInt.decode(&sv_p_secp[0], sv_p_secp.length);
    BigInt bi_a_secp = BigInt.decode(&sv_a_secp[0], sv_a_secp.length);
    BigInt bi_b_secp = BigInt.decode(&sv_b_secp[0], sv_b_secp.length);
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP(sv_G_secp_comp, secp160r1);
    
    BigInt d = BigInt("459183204582304");
    
    PointGFp r1 = d * p_G;
    mixin( CHECK(` r1.getAffineX() != 0 `) );
    
    PointGFp p_G2 = PointGFp(p_G);
    
    PointGFp r2 = d * p_G2;
    mixin( CHECK_MESSAGE( r1 == r2, "error with point mul after extra turn on sp red mul" ) );
    mixin( CHECK(` r1.getAffineX() != 0 `) );
    
    PointGFp p_r1 = r1;
    PointGFp p_r2 = r2;
    
    p_r1 *= 2;
    p_r2 *= 2;
    mixin( CHECK_MESSAGE( p_r1.getAffineX() == p_r2.getAffineX(), "error with mult2 after extra turn on sp red mul" ) );
    mixin( CHECK(` p_r1.getAffineX() != 0 `) );
    mixin( CHECK(` p_r2.getAffineX() != 0 `) );
    r1 *= 2;
    
    r2 *= 2;
    
    mixin( CHECK_MESSAGE( r1 == r2, "error with mult2 after extra turn on sp red mul" ) );
    mixin( CHECK_MESSAGE( r1.getAffineX() == r2.getAffineX(), "error with mult2 after extra turn on sp red mul" ) );
    mixin( CHECK(` r1.getAffineX() != 0 `) );
    r1 += p_G;
    r2 += p_G2;
    
    mixin( CHECK_MESSAGE( r1 == r2, "error with op+= after extra turn on sp red mul" ) );
    
    r1 += p_G;
    r2 += p_G2;
    
    mixin( CHECK_MESSAGE( r1 == r2, "error with op+= after extra turn on sp red mul for both operands" ) );
    r1 += p_G;
    r2 += p_G2;
    
    mixin( CHECK_MESSAGE( r1 == r2, "error with op+= after extra turn on sp red mul for both operands" ) );
    return fails;
}

size_t testCoordinates()
{
    size_t fails = 0;
    
    BigInt exp_affine_x = BigInt("16984103820118642236896513183038186009872590470");
    BigInt exp_affine_y = BigInt("1373093393927139016463695321221277758035357890939");
    
    // precalculation
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    PointGFp p0 = p_G;
    PointGFp p1 = p_G * 2;
    PointGFp point_exp = PointGFp(secp160r1, exp_affine_x, exp_affine_y);
    if (!point_exp.onTheCurve())
        throw new InternalError("Point not on the curve");
    
    mixin( CHECK_MESSAGE(  p1.getAffineX() == exp_affine_x, " p1_x = " ~ p1.getAffineX() ~ " \n" ~ "exp_x = " ~ exp_affine_x ~ " \n" ) );
    mixin( CHECK_MESSAGE(  p1.getAffineY() == exp_affine_y, " p1_y = " ~ p1.getAffineY() ~ " \n" ~ "exp_y = " ~ exp_affine_y ~ " \n" ) );
    return fails;
}


/**
Test point multiplication according to
--------
SEC 2: Test Vectors for SEC 1
Certicom Research
Working Draft
September, 1999
Version 0.3;
Section 2.1.2
--------
*/

size_t testPointTransformation ()
{
    size_t fails = 0;
    
    // get a vailid point
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    PointGFp p = dom_pars.getBasePoint();
    
    // get a copy
    PointGFp q = p;
    
    mixin( CHECK_MESSAGE(  p.getAffineX() == q.getAffineX(), "affine_x changed during copy" ) );
    mixin( CHECK_MESSAGE(  p.getAffineY() == q.getAffineY(), "affine_y changed during copy" ) );
    return fails;
}

size_t testPointMult ()
{
    size_t fails = 0;
    
    ECGroup secp160r1 = ECGroup(OIDS.lookup("secp160r1"));
    
    const CurveGFp curve = secp160r1.getCurve();
    
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_G_secp_comp = hexDecode(G_secp_comp);
    PointGFp p_G = OS2ECP(sv_G_secp_comp, curve);
    
    BigInt d_U = BigInt("0xaa374ffc3ce144e6b073307972cb6d57b2a4e982");
    PointGFp Q_U = d_U * p_G;
    
    mixin( CHECK(` Q_U.getAffineX() == BigInt("466448783855397898016055842232266600516272889280") `) );
    mixin( CHECK(` Q_U.getAffineY() == BigInt("1110706324081757720403272427311003102474457754220") `) );
    return fails;
}

size_t testPointNegative()
{
    size_t fails = 0;
    
    // performing calculation to test
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    
    PointGFp p1 = p_G *= 2;
    
    mixin( CHECK(` p1.getAffineX() == BigInt("16984103820118642236896513183038186009872590470") `) );
    mixin( CHECK(` p1.getAffineY() == BigInt("1373093393927139016463695321221277758035357890939") `) );
    
    PointGFp p1_neg = p1.negate();
    
    mixin( CHECK(` p1_neg.getAffineX() == BigInt("16984103820118642236896513183038186009872590470") `) );
    mixin( CHECK(` p1_neg.getAffineY() == BigInt("88408243403763901739989511495005261618427168388") `) );
    return fails;
}

size_t testZeropoint()
{
    size_t fails = 0;
    
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp = BigInt("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp = BigInt("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p1 = PointGFp(secp160r1,
                           BigInt("16984103820118642236896513183038186009872590470"),
                           BigInt("1373093393927139016463695321221277758035357890939"));
    
    if (!p1.onTheCurve())
        throw new InternalError("Point not on the curve");
    p1 -= p1;
    
    mixin( CHECK_MESSAGE( p1.isZero(), "p - q with q = p is not zero!" ) );
    return fails;
}

size_t testZeropointEncDec()
{
    size_t fails = 0;
    
    BigInt bi_p_secp = BigInt("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp = BigInt("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp = BigInt("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    CurveGFp curve = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p = PointGFp(curve);
    mixin( CHECK_MESSAGE( p.isZero(), "by constructor created zeropoint is no zeropoint!" ) );
    
    
    Vector!ubyte sv_p = unlock(EC2OSP(p, PointGFp.UNCOMPRESSED));
    PointGFp p_encdec = OS2ECP(sv_p, curve);
    mixin( CHECK_MESSAGE( p == p_encdec, "encoded-decoded (uncompressed) point is not equal the original!" ) );
    
    sv_p = unlock(EC2OSP(p, PointGFp.UNCOMPRESSED));
    p_encdec = OS2ECP(sv_p, curve);
    mixin( CHECK_MESSAGE( p == p_encdec, "encoded-decoded (compressed) point is not equal the original!" ) );
    
    sv_p = unlock(EC2OSP(p, PointGFp.HYBRID));
    p_encdec = OS2ECP(sv_p, curve);
    mixin( CHECK_MESSAGE( p == p_encdec, "encoded-decoded (hybrid) point is not equal the original!" ) );
    return fails;
}

size_t testCalcWithZeropoint()
{
    size_t fails = 0;
    
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a_secp = BigInt("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b_secp = BigInt("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    CurveGFp curve = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p = PointGFp(curve,
                          BigInt("16984103820118642236896513183038186009872590470"),
                          BigInt("1373093393927139016463695321221277758035357890939"));
    
    if (!p.onTheCurve())
        throw new InternalError("Point not on the curve");
    mixin( CHECK_MESSAGE( !p.isZero(), "created is zeropoint, shouldn't be!" ) );
    
    PointGFp zero = PointGFp(curve);
    mixin( CHECK_MESSAGE( zero.isZero(), "by constructor created zeropoint is no zeropoint!" ) );
    
    PointGFp res = p + zero;
    mixin( CHECK_MESSAGE( res == p, "point + zeropoint is not equal the point" ) );
    
    res = p - zero;
    mixin( CHECK_MESSAGE( res == p, "point - zeropoint is not equal the point" ) );
    
    res = zero * 32432243;
    mixin( CHECK_MESSAGE( res.isZero(), "zeropoint * skalar is not a zero-point!" ) );
    return fails;
}

size_t testAddPoint()
{
    size_t fails = 0;
    
    // precalculation
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    
    PointGFp p0 = p_G;
    PointGFp p1 = p_G *= 2;
    
    p1 += p0;
    
    PointGFp expected = PointGFp(secp160r1,
                                 BigInt("704859595002530890444080436569091156047721708633"),
                                 BigInt("1147993098458695153857594941635310323215433166682"));
    
    mixin( CHECK(` p1 == expected `) );
    return fails;
}

size_t testSubPoint()
{
    size_t fails = 0;
    
    //Setting up expected values
    BigInt exp_sub_x = BigInt("112913490230515010376958384252467223283065196552");
    BigInt exp_sub_y = BigInt("143464803917389475471159193867377888720776527730");
    BigInt exp_sub_z = BigInt("562006223742588575209908669014372619804457947208");
    
    // precalculation
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    
    PointGFp p0 = p_G;
    PointGFp p1 = p_G *= 2;
    
    p1 -= p0;
    
    PointGFp expected = PointGFp(secp160r1,
                                 BigInt("425826231723888350446541592701409065913635568770"),
                                 BigInt("203520114162904107873991457957346892027982641970"));
    
    mixin( CHECK(` p1 == expected `) );
    return fails;
}

size_t testMultPoint()
{
    size_t fails = 0;
    
    //Setting up expected values
    BigInt exp_mult_x = BigInt("967697346845926834906555988570157345422864716250");
    BigInt exp_mult_y = BigInt("512319768365374654866290830075237814703869061656");
    
    // precalculation
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    
    PointGFp p0 = p_G;
    PointGFp p1 = p_G *= 2;
    
    p1 *= p0.getAffineX();
    
    PointGFp expected = PointGFp(secp160r1, exp_mult_x, exp_mult_y);
    
    mixin( CHECK(` p1 == expected `) );
    return fails;
}

size_t testBasicOperations()
{
    size_t fails = 0;
    
    // precalculation
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffc";
    string b_secp = "1c97befc54bd7a8b65acf89f81d4d4adc565fa45";
    string G_secp_comp = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    
    PointGFp p0 = p_G;
    
    PointGFp expected = PointGFp(secp160r1,
                                 BigInt("425826231723888350446541592701409065913635568770"),
                                 BigInt("203520114162904107873991457957346892027982641970"));
    
    mixin( CHECK(` p0 == expected `) );
    
    PointGFp p1 = p_G *= 2;
    
    mixin( CHECK(` p1.getAffineX() == BigInt("16984103820118642236896513183038186009872590470") `) );
    mixin( CHECK(` p1.getAffineY() == BigInt("1373093393927139016463695321221277758035357890939") `) );
    
    PointGFp simplePlus = p1 + p0;
    PointGFp exp_simplePlus = PointGFp(secp160r1,
                                       BigInt("704859595002530890444080436569091156047721708633"),
                                       BigInt("1147993098458695153857594941635310323215433166682"));
    if (simplePlus != exp_simplePlus)
        writeln(simplePlus ~ " != " ~ exp_simplePlus);
    
    PointGFp simpleMinus= p1 - p0;
    PointGFp exp_simpleMinus = PointGFp(secp160r1,
                                        BigInt("425826231723888350446541592701409065913635568770"),
                                        BigInt("203520114162904107873991457957346892027982641970"));
    
    mixin( CHECK(` simpleMinus == exp_simpleMinus `) );
    
    PointGFp simpleMult= p1 * 123456789;
    
    mixin( CHECK(` simpleMult.getAffineX() == BigInt("43638877777452195295055270548491599621118743290") `) );
    mixin( CHECK(` simpleMult.getAffineY() == BigInt("56841378500012376527163928510402662349220202981") `) );
    
    // check that all initial points hasn't changed
    mixin( CHECK(` p1.getAffineX() == BigInt("16984103820118642236896513183038186009872590470") `) );
    mixin( CHECK(` p1.getAffineY() == BigInt("1373093393927139016463695321221277758035357890939") `) );
    
    mixin( CHECK(` p0.getAffineX() == BigInt("425826231723888350446541592701409065913635568770") `) );
    mixin( CHECK(` p0.getAffineY() == BigInt("203520114162904107873991457957346892027982641970") `) );
    return fails;
}

size_t testEncDecCompressed160()
{
    size_t fails = 0;
    
    // Test for compressed conversion (02/03) 160bit
    string p_secp = "ffffffffffffffffffffffffffffffff7fffffff";
    string a_secp = "ffffffffffffffffffffffffffffffff7ffffffC";
    string b_secp = "1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45";
    string G_secp_comp = "024A96B5688EF573284664698968C38BB913CBFC82";
    string G_order_secp_comp = "0100000000000000000001F4C8F927AED3CA752257";
    
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    Vector!ubyte sv_result = unlock(EC2OSP(p_G, PointGFp.COMPRESSED));
    
    mixin( CHECK(`  sv_result == sv_G_secp_comp `) );
    return fails;
}

size_t testEncDecCompressed256()
{
    size_t fails = 0;
    
    // Test for compressed conversion (02/03) 256bit
    string p_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
    string a_secp = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffFC";
    string b_secp = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B";
    string G_secp_comp = "036B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296";
    string G_order_secp_comp = "ffffffff00000000ffffffffffffffffBCE6FAADA7179E84F3B9CAC2FC632551";
    
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_comp = hexDecode( G_secp_comp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p_G = OS2ECP( sv_G_secp_comp, secp160r1 );
    Vector!ubyte sv_result = unlock(EC2OSP(p_G, PointGFp.COMPRESSED));
    
    mixin( CHECK(`  sv_result == sv_G_secp_comp `) );
    return fails;
}


size_t testEncDecUncompressed112()
{
    size_t fails = 0;
    
    // Test for uncompressed conversion (04) 112bit
    
    string p_secp = "db7c2abf62e35e668076bead208b";
    string a_secp = "6127C24C05F38A0AAAF65C0EF02C";
    string b_secp = "51DEF1815DB5ED74FCC34C85D709";
    string G_secp_uncomp = "044BA30AB5E892B4E1649DD0928643ADCD46F5882E3747DEF36E956E97";
    string G_order_secp_uncomp = "36DF0AAFD8B8D7597CA10520D04B";
    
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_uncomp = hexDecode( G_secp_uncomp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p_G = OS2ECP( sv_G_secp_uncomp, secp160r1 );
    Vector!ubyte sv_result = unlock(EC2OSP(p_G, PointGFp.UNCOMPRESSED));
    
    mixin( CHECK(` sv_result == sv_G_secp_uncomp `) );
    return fails;
}

size_t testEncDecUncompressed521()
{
    size_t fails = 0;
    
    // Test for uncompressed conversion(04) with big values(521 bit)
    string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
    string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
    string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
    string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
    
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_uncomp = hexDecode( G_secp_uncomp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    
    CurveGFp secp160r1 = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    
    PointGFp p_G = OS2ECP( sv_G_secp_uncomp, secp160r1 );
    
    Vector!ubyte sv_result = unlock(EC2OSP(p_G, PointGFp.UNCOMPRESSED));
    string result = hexEncode(&sv_result[0], sv_result.length);
    string exp_result = hexEncode(&sv_G_secp_uncomp[0], sv_G_secp_uncomp.length);
    
    mixin( CHECK_MESSAGE(  sv_result == sv_G_secp_uncomp, "\ncalc. result = " ~ result ~ "\nexp. result = " ~ exp_result ~ " \n" ) );
    return fails;
}

size_t testEncDecUncompressed521PrimeTooLarge()
{
    size_t fails = 0;
    
    // Test for uncompressed conversion(04) with big values(521 bit)
    string p_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"; // length increased by "ff"
    string a_secp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFC";
    string b_secp = "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00";
    string G_secp_uncomp = "0400C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2ffA8DE3348B3C1856A429BF97E7E31C2E5BD66011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650";
    string G_order_secp_uncomp = "01ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409";
    
    Vector!ubyte sv_p_secp = hexDecode( p_secp );
    Vector!ubyte sv_a_secp = hexDecode( a_secp );
    Vector!ubyte sv_b_secp = hexDecode( b_secp );
    Vector!ubyte sv_G_secp_uncomp = hexDecode( G_secp_uncomp );
    
    BigInt bi_p_secp = BigInt.decode( &sv_p_secp[0], sv_p_secp.length );
    BigInt bi_a_secp = BigInt.decode( &sv_a_secp[0], sv_a_secp.length );
    BigInt bi_b_secp = BigInt.decode( &sv_b_secp[0], sv_b_secp.length );
    
    CurveGFp secp521r1 (bi_p_secp, bi_a_secp, bi_b_secp);
    Unique!PointGFp p_G;
    bool exc = false;
    try
    {
        p_G = Unique!PointGFp(new PointGFp(OS2ECP(sv_G_secp_uncomp, secp521r1)));
        if (!p_G.onTheCurve())
            throw new InternalError("Point not on the curve");
    }
    catch (Exception e)
    {
        exc = true;
    }
    
    mixin( CHECK_MESSAGE( exc, "attempt of creation of point on curve with too high prime did not throw an exception" ) );
    return fails;
}

size_t testGfpStoreRestore()
{
    size_t fails = 0;
    
    // generate point
    //ECGroup dom_pars = global_config().get_ec_dompar("1.3.132.0.8");
    //ECGroup dom_pars = ECGroup("1.3.132.0.8");
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    PointGFp p = dom_pars.getBasePoint();
    
    //store point (to string)
    Vector!ubyte sv_mes = unlock(EC2OSP(p, PointGFp.COMPRESSED));
    PointGFp new_p = OS2ECP(sv_mes, dom_pars.getCurve());
    
    mixin( CHECK_MESSAGE(  p == new_p, "original and restored point are different!" ) );
    return fails;
}


// maybe move this test
size_t testCdcCurve33()
{
    size_t fails = 0;
    
    string G_secp_uncomp = "04081523d03d4f12cd02879dea4bf6a4f3a7df26ed888f10c5b2235a1274c386a2f218300dee6ed217841164533bcdc903f07a096f9fbf4ee95bac098a111f296f5830fe5c35b3e344d5df3a2256985f64fbe6d0edcc4c61d18bef681dd399df3d0194c5a4315e012e0245ecea56365baa9e8be1f7";
    
    Vector!ubyte sv_G_uncomp = hexDecode( G_secp_uncomp );
    
    BigInt bi_p_secp = BigInt("2117607112719756483104013348936480976596328609518055062007450442679169492999007105354629105748524349829824407773719892437896937279095106809");
    BigInt bi_a_secp = BigInt("0xa377dede6b523333d36c78e9b0eaa3bf48ce93041f6d4fc34014d08f6833807498deedd4290101c5866e8dfb589485d13357b9e78c2d7fbe9fe");
    BigInt bi_b_secp = BigInt("0xa9acf8c8ba617777e248509bcb4717d4db346202bf9e352cd5633731dd92a51b72a4dc3b3d17c823fcc8fbda4da08f25dea89046087342595a7");
    
    CurveGFp curve = CurveGFp(bi_p_secp, bi_a_secp, bi_b_secp);
    PointGFp p_G = OS2ECP( sv_G_uncomp, curve);
    bool exc = false;
    try
    {
        if (!p_G.onTheCurve())
            throw new InternalError("Point not on the curve");
    }
    catch (Exception)
    {
        exc = true;
    }
    mixin( CHECK(` !exc `) );
    return fails;
}

size_t testMoreZeropoint()
{
    size_t fails = 0;
    
    // by Falko
    
    string G = "024a96b5688ef573284664698968c38bb913cbfc82";
    Vector!ubyte sv_G_secp_comp = hexDecode( G );
    BigInt bi_p = BigInt("0xffffffffffffffffffffffffffffffff7fffffff");
    BigInt bi_a = BigInt("0xffffffffffffffffffffffffffffffff7ffffffc");
    BigInt bi_b = BigInt("0x1c97befc54bd7a8b65acf89f81d4d4adc565fa45");
    CurveGFp curve = CurveGFp(bi_p, bi_a, bi_b);
    
    PointGFp p1 = PointGFp(curve,
                           BigInt("16984103820118642236896513183038186009872590470"),
                           BigInt("1373093393927139016463695321221277758035357890939"));
    
    if (!p1.onTheCurve())
        throw new InternalError("Point not on the curve");
    PointGFp minus_p1 = -p1;
    if (!minus_p1.onTheCurve())
        throw new InternalError("Point not on the curve");
    PointGFp shouldBeZero = p1 + minus_p1;
    if (!shouldBeZero.onTheCurve())
        throw new InternalError("Point not on the curve");
    
    BigInt y1 = p1.getAffineY();
    y1 = curve.getP() - y1;
    
    CHECK_MESSAGE(p1.getAffineX() == minus_p1.getAffineX(),
                  "problem with minus_p1 : x");
    CHECK_MESSAGE(minus_p1.getAffineY() == y1,
                  "problem with minus_p1 : y");
    
    PointGFp zero = PointGFp(curve);
    if (!zero.onTheCurve())
        throw new InternalError("Point not on the curve");
    mixin( CHECK_MESSAGE( p1 + zero == p1, "addition of zero modified point" ) );
    
    mixin( CHECK_MESSAGE( shouldBeZero.isZero(), "p - q with q = p is not zero!" ) );
    return fails;
}

size_t testMultByOrder()
{
    size_t fails = 0;
    
    // generate point
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    PointGFp p = dom_pars.getBasePoint();
    PointGFp shouldBeZero = p * dom_pars.getOrder();
    
    mixin( CHECK_MESSAGE( shouldBeZero.isZero(), "G * order != O" ) );
    return fails;
}

size_t testPointSwap()
{
    size_t fails = 0;
    
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    
    AutoSeededRNG rng;
    
    PointGFp a = PointGFp(createRandomPoint(rng, dom_pars.getCurve()));
    PointGFp b = PointGFp(createRandomPoint(rng, dom_pars.getCurve()));
    b *= BigInt(20);
    
    PointGFp c = PointGFp(a);
    PointGFp d = PointGFp(b);
    
    d.swap(c);
    mixin( CHECK(` a == d `) );
    mixin( CHECK(` b == c `) );
    return fails;
}

/**
* This test verifies that the side channel attack resistant multiplication function
* yields the same result as the normal (insecure) multiplication via operator*=
*/
size_t testMultSecMass()
{
    size_t fails = 0;
    
    AutoSeededRNG rng;
    
    ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
    for(int i = 0; i<50; i++)
    {
        PointGFp a = PointGFp(createRandomPoint(rng, dom_pars.getCurve()));
        BigInt scal = BigInt(BigInt(rng, 40));
        PointGFp b = a * scal;
        PointGFp c = PointGFp(a);
        
        c *= scal;
        mixin( CHECK(` b == c `) );
    }
    return fails;
}

size_t testCurveCpCtor()
{
    try
    {
        ECGroup dom_pars = ECGroup(OID("1.3.132.0.8"));
        CurveGFp curve = CurveGFp(dom_pars.getCurve());
    }
    catch (Throwable)
    {
        return 1;
        
    }
    
    return 0;
}

unittest
{
    size_t fails = 0;
    
    fails += testPointTurnOnSpRedMul();
    fails += testCoordinates();
    fails += testPointTransformation ();
    fails += testPointMult ();
    fails += testPointNegative();
    fails += testZeropoint();
    fails += testZeropointEncDec();
    fails += testCalcWithZeropoint();
    fails += testAddPoint();
    fails += testSubPoint();
    fails += testMultPoint();
    fails += testBasicOperations();
    fails += testEncDecCompressed160();
    fails += testEncDecCompressed256();
    fails += testEncDecUncompressed112();
    fails += testEncDecUncompressed521();
    fails += testEncDecUncompressed521PrimeTooLarge();
    fails += testGfpStoreRestore();
    fails += testCdcCurve33();
    fails += testMoreZeropoint();
    fails += testMultByOrder();
    fails += testPointSwap();
    fails += testMultSecMass();
    fails += testCurveCpCtor();
    
    testReport("ECC", 61, fails);

}