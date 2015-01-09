/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*      2008-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.ec_gfp.point_gfp;

import botan.math.ec_gfp.curve_gfp;
import botan.utils.types;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.math.mp.mp_core;
import std.algorithm : swap;
import std.conv : to;

/**
* Exception thrown if you try to convert a zero point to an affine
* coordinate
*/
class IllegalTransformation : Exception
{
    this(in string err = "Requested transformation is not possible")
    {
        super(err);
    }
}

/**
* Exception thrown if some form of illegal point is decoded
*/
class IllegalPoint : Exception
{
    this(in string err = "Malformed ECP point detected") { super(err); }
}


/**
* This class represents one point on a curve of GF(p)
*/
struct PointGFp
{
public:
    alias CompressionType = ubyte;
    enum : CompressionType {
        UNCOMPRESSED      = 0,
        COMPRESSED        = 1,
        HYBRID            = 2
    }

    /**
    * Construct the zero point
    * @param curve = The base curve
    */
    this(CurveGFp curve) 
    {
        m_curve = curve;
        m_ws = new SecureVector!word;
        (*m_ws).resize(2 * (curve.getPWords() + 2));
        m_coord_x = 0;
        m_coord_y = montyMult(BigInt(1), curve.getR2());
        m_coord_z = 0;
    }

    /**
    * Move Constructor
    */
    this(PointGFp other)
    {
        m_curve = CurveGFp.init;
        this.swap(other);
    }

    /**
    * Move Assignment
    */
    ref PointGFp opAssign(PointGFp other)
    {
        this.swap(other);
        return this;
    }

    /**
    * Construct a point from its affine coordinates
    * @param curve = the base curve
    * @param x = affine x coordinate
    * @param y = affine y coordinate
    */
    this(CurveGFp curve, BigInt x, BigInt y)
    { 
        m_curve = curve;
        m_ws = new SecureVector!word;
        (*m_ws).resize(2 * (curve.getPWords() + 2));
        m_coord_x = montyMult(x, curve.getR2());
        m_coord_y = montyMult(y, curve.getR2());
        m_coord_z = montyMult(BigInt(1), curve.getR2());
    }

    /**
    * += Operator
    * @param rhs = the PointGFp to add to the local value
    * @result resulting PointGFp
    */
    void opOpAssign(string op)(in PointGFp rhs)
        if (op == "+")
    {
        Vector!BigInt ws = Vector!BigInt(9);
        add(rhs, ws);
    }

    /**
    * -= Operator
    * @param rhs = the PointGFp to subtract from the local value
    * @result resulting PointGFp
    */
    void opOpAssign(string op)(in PointGFp rhs)
        if (op == "-")
    {
        PointGFp minus_rhs = PointGFp(rhs.dup).negate();
        
        if (isZero())
            this = minus_rhs;
        else
            this += minus_rhs;
        
    }

    /**
    * *= Operator
    * @param scalar = the PointGFp to multiply with this
    * @result resulting PointGFp
    */
    void opOpAssign(string op)(in BigInt scalar)
        if (op == "*")
    {
        this = this * scalar;
    }

    /**
    * Multiplication Operator
    * @param scalar = the scalar value
    * @param point = the point value
    * @return scalar*point on the curve
    */
    PointGFp opBinary(string op)(in BigInt scalar)
        if (op == "*")
    {
        auto point = this;
        const CurveGFp curve = point.getCurve();
        
        if (scalar.isZero())
            return PointGFp(curve.dup); // zero point
        
        Vector!BigInt ws = Vector!BigInt(9);
        
        if (scalar.abs() <= 2) // special cases for small values
        {
            ubyte value = scalar.abs().byteAt(0);
            
            PointGFp result = point;
            
            if (value == 2)
                result.mult2(ws);
            
            if (scalar.isNegative())
                result.negate();
            
            return result;
        }
        
        const size_t scalar_bits = scalar.bits();
        
        version(none) {
            
            PointGFp x1 = PointGFp(curve);
            PointGFp x2 = point;
            
            size_t bits_left = scalar_bits;
            
            // Montgomery Ladder
            while (bits_left)
            {
                const bool bit_set = scalar.getBit(bits_left - 1);
                
                if (bit_set)
                {
                    x1.add(x2, ws);
                    x2.mult2(ws);
                }
                else
                {
                    x2.add(x1, ws);
                    x1.mult2(ws);
                }
                
                --bits_left;
            }
            
            if (scalar.isNegative())
                x1.negate();
            
            return x1;
            
        } else {
            const size_t window_size = 4;
            
            Vector!PointGFp Ps = Vector!PointGFp(1 << window_size);
            Ps[0] = PointGFp(curve.dup);
            Ps[1] = point;
            
            for (size_t i = 2; i != Ps.length; ++i)
            {
                Ps[i] = Ps[i-1];
                Ps[i].add(point, ws);
            }
            
            PointGFp H = PointGFp(curve.dup); // create as zero
            size_t bits_left = scalar_bits;
            
            while (bits_left >= window_size)
            {
                foreach (size_t i; 0 .. window_size)
                    H.mult2(ws);
                
                const uint nibble = scalar.getSubstring(bits_left - window_size,
                                                         window_size);
                
                H.add(Ps[nibble], ws);
                
                bits_left -= window_size;
            }
            
            while (bits_left)
            {
                H.mult2(ws);
                if (scalar.getBit(bits_left-1))
                    H.add(point, ws);
                
                --bits_left;
            }
            
            if (scalar.isNegative())
                H.negate();
            
            return H;
        }
    }

    /**
    * Multiexponentiation
    * @param p1 = a point
    * @param z1 = a scalar
    * @param p2 = a point
    * @param z2 = a scalar
    * @result (p1 * z1 + p2 * z2)
    */
    static PointGFp multiExponentiate(in PointGFp p1, in BigInt z1,
                               in PointGFp p2, in BigInt z2)
    {
        const PointGFp p3 = p1.dup + p2;
        
        PointGFp H = PointGFp(p1.m_curve.dup); // create as zero
        size_t bits_left = std.algorithm.max(z1.bits(), z2.bits());
        
        Vector!BigInt ws = Vector!BigInt(9);
        
        while (bits_left)
        {
            H.mult2(ws);
            
            const bool z1_b = z1.getBit(bits_left - 1);
            const bool z2_b = z2.getBit(bits_left - 1);
            
            if (z1_b == true && z2_b == true)
                H.add(p3, ws);
            else if (z1_b)
                H.add(p1, ws);
            else if (z2_b)
                H.add(p2, ws);
            
            --bits_left;
        }
        
        if (z1.isNegative() != z2.isNegative())
            H.negate();
        
        return H;
    }

    /**
    * Negate this point
    * @return this
    */
    ref PointGFp negate()
    {
        if (!isZero())
            m_coord_y = m_curve.getP().dup - m_coord_y;
        return this;
    }

    /**
    * Return base curve of this point
    * @result the curve over GF(p) of this point
    */
    const(CurveGFp) getCurve() const { return m_curve; }

    /**
    * get affine x coordinate
    * @result affine x coordinate
    */
    BigInt getAffineX() const
    {
        if (isZero())
            throw new IllegalTransformation("Cannot convert zero point to affine");
        
        const BigInt r2 = m_curve.getR2();
        
        BigInt z2 = montySqr(m_coord_z);
        z2 = inverseMod(z2, m_curve.getP());
        
        z2 = montyMult(z2, r2);
        return montyMult(m_coord_x, z2);
    }

    /**
    * get affine y coordinate
    * @result affine y coordinate
    */
    BigInt getAffineY() const
    {
        if (isZero())
            throw new IllegalTransformation("Cannot convert zero point to affine");
        
        const BigInt r2 = m_curve.getR2();
        
        BigInt z3 = montyMult(m_coord_z, montySqr(m_coord_z));
        z3 = inverseMod(z3, m_curve.getP());
        z3 = montyMult(z3, r2);
        return montyMult(m_coord_y, z3);
    }

    /**
    * Is this the point at infinity?
    * @result true, if this point is at infinity, false otherwise.
    */
    bool isZero() const
    { return (m_coord_x.isZero() && m_coord_z.isZero()); }

    /**
    * Checks whether the point is to be found on the underlying
    * curve; used to prevent fault attacks.
    * @return if the point is on the curve
    */
    bool onTheCurve() const
    {
        /*
        Is the point still on the curve?? (If everything is correct, the
        point is always on its curve; then the function will return true.
        If somehow the state is corrupted, which suggests a fault attack
        (or internal computational error), then return false.
        */
        
        if (isZero())
            return true;
        
        BigInt y2 = montyMult(montySqr(m_coord_y), BigInt(1));
        BigInt x3 = montyMult(m_coord_x, montySqr(m_coord_x));
        
        BigInt ax = montyMult(m_coord_x, m_curve.getAR());
        
        const BigInt b_r = m_curve.getBR();
        
        BigInt z2 = montySqr(m_coord_z);
        
        if (m_coord_z == z2) // Is z equal to 1 (in Montgomery form)?
        {
            if (y2 != montyMult(x3 + ax + b_r, BigInt(1)))
                return false;
        }
        
        BigInt z3 = montyMult(m_coord_z, z2);
        
        BigInt ax_z4 = montyMult(ax, montySqr(z2));
        
        BigInt b_z6 = montyMult(b_r, montySqr(z3));
        
        if (y2 != montyMult(x3 + ax_z4 + b_z6, BigInt(1)))
            return false;
        
        return true;
    }


    /**
    * swaps the states of this and other, does not throw!
    * @param other = the object to swap values with
    */
    void swap(ref PointGFp other)
    {
        m_curve.swap(other.m_curve);
        m_coord_x.swap(other.m_coord_x);
        m_coord_y.swap(other.m_coord_y);
        m_coord_z.swap(other.m_coord_z);
        .swap(m_ws, other.m_ws);
    }

    PointGFp dup() const
    {
        PointGFp ret = PointGFp(m_curve.dup, m_coord_x.dup, m_coord_y.dup);
        ret.m_coord_z = m_coord_z.dup;
        ret.m_ws = new SecureVector!word;

        (*ret.m_ws)[] = (*m_ws).ptr[0 .. (*m_ws).length];
        return ret;
    }

    /**
    * Equality operator
    */
    bool opEquals(in PointGFp other) const
    {
        if (getCurve() != other.getCurve())
            return false;
        
        // If this is zero, only equal if other is also zero
        if (isZero())
            return other.isZero();

        return (getAffineX() == other.getAffineX() &&
                getAffineY() == other.getAffineY());
    }

    @trusted const ~this() { }

private:

    /**
    * Montgomery multiplication/reduction
    * @param x = first multiplicand
    * @param y = second multiplicand
    * @param workspace = temp space
    */
    BigInt montyMult(in BigInt x, in BigInt y) const
    {
        BigInt result;
        montyMult(result, x, y);
        return result;
    }

    /**
    * Montgomery multiplication/reduction
    * @warning z cannot alias x or y
    * @param z = output
    * @param x = first multiplicand
    * @param y = second multiplicand
    */
    // Montgomery multiplication
    void montyMult(ref BigInt z, in BigInt x, in BigInt y) const
    {
        //assert(&z != &x && &z != &y);
        
        if (x.isZero() || y.isZero())
        {
            z = 0;
            return;
        }
        
        const BigInt p = m_curve.getP();
        const size_t p_size = m_curve.getPWords();
        const word p_dash = m_curve.getPDash();
        
        const size_t output_size = 2*p_size + 1;
        
        z.growTo(output_size);
        z.clear();
        
        bigint_monty_mul(z.mutablePtr(), output_size,
                         x.ptr, x.length, x.sigWords(),
                         y.ptr, y.length, y.sigWords(),
                         p.ptr, p_size, p_dash,
                         m_ws.ptr);
    }
    
    /**
    * Montgomery squaring/reduction
    * @param x = multiplicand
    */
    BigInt montySqr(in BigInt x) const
    {
        BigInt result;
        montySqr(result, x);
        return result;
    }

    /**
    * Montgomery squaring/reduction
    * @warning z cannot alias x
    * @param z = output
    * @param x = multiplicand
    */
    void montySqr(ref BigInt z, in BigInt x) const
    {
        //assert(&z != &x);
        
        if (x.isZero())
        {
            z = 0;
            return;
        }
        
        const BigInt p = m_curve.getP();
        const size_t p_size = m_curve.getPWords();
        const word p_dash = m_curve.getPDash();
        
        const size_t output_size = 2*p_size + 1;
        
        z.growTo(output_size);
        z.clear();
        
        bigint_monty_sqr(z.mutablePtr(), output_size,
                         x.ptr, x.length, x.sigWords(),
                         p.ptr, p_size, p_dash,
                         m_ws.ptr);
    }

    /**
    * Point addition
    * @param workspace = temp space, at least 11 elements
    */
    void add(in PointGFp rhs, ref Vector!BigInt ws_bn)
    {
        if (isZero())
        {
            m_coord_x = rhs.m_coord_x.dup;
            m_coord_y = rhs.m_coord_y.dup;
            m_coord_z = rhs.m_coord_z.dup;
            return;
        }
        else if (rhs.isZero())
            return;
        
        const BigInt p = m_curve.getP();
        
        BigInt rhs_z2 = ws_bn[0];
        BigInt U1 = ws_bn[1];
        BigInt S1 = ws_bn[2];
        
        BigInt lhs_z2 = ws_bn[3];
        BigInt U2 = ws_bn[4];
        BigInt S2 = ws_bn[5];
        
        BigInt H = ws_bn[6];
        BigInt r = ws_bn[7];
        
        montySqr(rhs_z2, rhs.m_coord_z);
        montyMult(U1, m_coord_x, rhs_z2);
        montyMult(S1, m_coord_y, montyMult(rhs.m_coord_z, rhs_z2));
        
        montySqr(lhs_z2, m_coord_z);
        montyMult(U2, rhs.m_coord_x, lhs_z2);
        montyMult(S2, rhs.m_coord_y, montyMult(m_coord_z, lhs_z2));
        
        H = U2;
        H -= U1;
        if (H.isNegative())
            H += p;
        
        r = S2;
        r -= S1;
        if (r.isNegative())
            r += p;
        
        if (H.isZero())
        {
            if (r.isZero())
            {
                mult2(ws_bn);
                return;
            }
            
            this = PointGFp(m_curve.dup); // setting myself to zero
            return;
        }
        
        montySqr(U2, H);
        
        montyMult(S2, U2, H);
        
        U2 = montyMult(U1, U2);
        
        montySqr(m_coord_x, r);
        m_coord_x -= S2;
        m_coord_x -= (U2 << 1);
        while (m_coord_x.isNegative())
            m_coord_x += p;
        
        U2 -= m_coord_x;
        if (U2.isNegative())
            U2 += p;
        
        montyMult(m_coord_y, r, U2);
        m_coord_y -= montyMult(S1, S2);
        if (m_coord_y.isNegative())
            m_coord_y += p;
        
        montyMult(m_coord_z, montyMult(m_coord_z, rhs.m_coord_z), H);
    }


    /**
    * Point doubling
    * @param workspace = temp space, at least 9 elements
    */
    void mult2(ref Vector!BigInt ws_bn)
    {
        if (isZero())
            return;
        else if (m_coord_y.isZero())
        {
            this = PointGFp(m_curve); // setting myself to zero
            return;
        }
        
        const BigInt p = m_curve.getP();
        
        BigInt y_2 = ws_bn[0];
        BigInt S = ws_bn[1];
        BigInt z4 = ws_bn[2];
        BigInt a_z4 = ws_bn[3];
        BigInt M = ws_bn[4];
        BigInt U = ws_bn[5];
        BigInt x = ws_bn[6];
        BigInt y = ws_bn[7];
        BigInt z = ws_bn[8];
        
        montySqr(y_2, m_coord_y);
        
        montyMult(S, m_coord_x, y_2);
        S <<= 2; // * 4
        while (S >= p)
            S -= p;
        
        montySqr(z4, montySqr(m_coord_z));
        montyMult(a_z4, m_curve.getAR(), z4);
        
        M = montySqr(m_coord_x);
        M *= 3;
        M += a_z4;
        while (M >= p)
            M -= p;
        
        montySqr(x, M);
        x -= (S << 1);
        while (x.isNegative())
            x += p;
        
        montySqr(U, y_2);
        U <<= 3;
        while (U >= p)
            U -= p;
        
        S -= x;
        while (S.isNegative())
            S += p;
        
        montyMult(y, M, S);
        y -= U;
        if (y.isNegative())
            y += p;
        
        montyMult(z, m_coord_y, m_coord_z);
        z <<= 1;
        if (z >= p)
            z -= p;
        
        m_coord_x = x;
        m_coord_y = y;
        m_coord_z = z;
    }

    // relational operators
    int opCmp(in PointGFp rhs) const
    {
        if  (this == rhs) return 0;
        else return -1;
    }
    
    // arithmetic operators
    ref PointGFp opUnary(string op)()
        if (op == "-")
    {
        return negate();
    }
    
    ref PointGFp opBinary(string op)(in PointGFp rhs)
        if (op == "+")
    {
        this += rhs;
        return this;
    }
    
    ref PointGFp opBinary(string op)(in PointGFp rhs)
        if (op == "-")
    {
        this -= rhs;
        return this;
    }
    
    ref PointGFp opBinary(string op)(in PointGFp point)
        if (op == "*")
    {
        this *= point;
        return this;
    }

    CurveGFp m_curve;
    BigInt m_coord_x, m_coord_y, m_coord_z;
    SecureVector!(word)* m_ws; // workspace for Montgomery
}

// encoding and decoding
SecureVector!ubyte EC2OSP(in PointGFp point, ubyte format)
{
    if (point.isZero())
        return SecureVector!ubyte(1); // single 0 ubyte
    
    const size_t p_bytes = point.getCurve().getP().bytes();
    
    BigInt x = point.getAffineX();
    BigInt y = point.getAffineY();
    
    SecureVector!ubyte bX = BigInt.encode1363(x, p_bytes);
    SecureVector!ubyte bY = BigInt.encode1363(y, p_bytes);
    
    if (format == PointGFp.UNCOMPRESSED)
    {
        SecureVector!ubyte result;
        result.pushBack(0x04);
        
        result ~= bX;
        result ~= bY;
        
        return result;
    }
    else if (format == PointGFp.COMPRESSED)
    {
        SecureVector!ubyte result;
        result.pushBack(0x02 | cast(ubyte)(y.getBit(0)));
        
        result ~= bX;
        
        return result;
    }
    else if (format == PointGFp.HYBRID)
    {
        SecureVector!ubyte result;
        result.pushBack(0x06 | cast(ubyte)(y.getBit(0)));
        
        result ~= bX;
        result ~= bY;
        
        return result;
    }
    else
        throw new InvalidArgument("illegal point encoding format specification");
}

PointGFp OS2ECP(T : CurveGFp)(const(ubyte)* data, size_t data_len, auto ref T curve)
{
    if (data_len <= 1)
        return PointGFp(curve); // return zero
    
    const ubyte pc = data[0];
    
    BigInt x, y;
    
    if (pc == 2 || pc == 3)
    {
        //compressed form
        x = BigInt.decode(&data[1], data_len - 1);
        
        const bool y_mod_2 = ((pc & 0x01) == 1);
        y = decompressPoint(y_mod_2, x, curve);
    }
    else if (pc == 4)
    {
        const size_t l = (data_len - 1) / 2;
        
        // uncompressed form
        x = BigInt.decode(&data[1], l);
        y = BigInt.decode(&data[l+1], l);
    }
    else if (pc == 6 || pc == 7)
    {
        const size_t l = (data_len - 1) / 2;
        
        // hybrid form
        x = BigInt.decode(&data[1], l);
        y = BigInt.decode(&data[l+1], l);
        
        const bool y_mod_2 = ((pc & 0x01) == 1);
        
        if (decompressPoint(y_mod_2, x, curve) != y)
            throw new IllegalPoint("OS2ECP: Decoding error in hybrid format");
    }
    else
        throw new InvalidArgument("OS2ECP: Unknown format type " ~ to!string(pc));
    
    PointGFp result = PointGFp(curve, x, y);
    
    if (!result.onTheCurve())
        throw new IllegalPoint("OS2ECP: Decoded point was not on the curve");
    
    return result;
}

PointGFp OS2ECP(int Alloc, T : CurveGFp)(in FreeListRef!(VectorImpl!( ubyte, Alloc )) data, auto ref T curve)
{ return OS2ECP(data.ptr, data.length, curve); }

void swap(ref PointGFp x, ref PointGFp y)
{ import std.algorithm : swap; x.swap(y); }

private:

BigInt decompressPoint(T : CurveGFp)(bool yMod2,
                                     BigInt x,
                                     auto ref T curve)
{
    BigInt xpow3 = x * x * x;
    
    BigInt g = BigInt(curve.getA()) * x;
    g += xpow3;
    g += curve.getB();
    g = g % curve.getP();
    
    BigInt z = ressol(g, curve.getP().dup);
    
    if (z < 0)
        throw new IllegalPoint("error during decompression");
    
    if (z.getBit(0) != yMod2)
        z = BigInt(curve.getP()) - z;
    
    return z;
}
