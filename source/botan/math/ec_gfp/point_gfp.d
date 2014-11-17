/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*	  2008-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.math.ec_gfp.point_gfp;

import botan.math.ec_gfp.curve_gfp;
import botan.utils.types;
import botan.math.numbertheory.numthry;
import botan.math.numbertheory.reducer;
import botan.math.mp.mp_core;

/**
* Exception thrown if you try to convert a zero point to an affine
* coordinate
*/
class Illegal_Transformation : Exception
{
	this(in string err = "Requested transformation is not possible")
	{
		super(err);
	}
}

/**
* Exception thrown if some form of illegal point is decoded
*/
class Illegal_Point : Exception
{
	this(in string err = "Malformed ECP point detected") { super(err); }
}

/**
* This class represents one point on a curve of GF(p)
*/
struct PointGFp
{
public:
	typedef ubyte Compression_Type;
	enum : Compression_Type {
		UNCOMPRESSED	= 0,
		COMPRESSED		= 1,
		HYBRID		 	= 2
	}

	/**
	* Construct an uninitialized PointGFp
	*/
	this() {}

	/**
	* Construct the zero point
	* @param curve The base curve
	*/
	this(in CurveGFp _curve) 
	{
		curve = _curve;
		ws = 2 * (curve.get_p_words() + 2);
		coord_x = 0;
		coord_y = monty_mult(1, curve.get_r2());
		coord_z = 0;
	}

	/**
	* Copy constructor
	*/
	//PointGFp(in PointGFp) = default;

	/**
	* Move Constructor
	*/
	this(ref PointGFp other)
	{
		this.swap(other);
	}

	/**
	* Standard Assignment
	*/
	//ref PointGFp operator=(in PointGFp) = default;

	/**
	* Move Assignment
	*/
	ref PointGFp opAssign(ref PointGFp other)
	{
		if (this != &other)
			this.swap(other);
		return this;
	}

	/**
	* Construct a point from its affine coordinates
	* @param curve the base curve
	* @param x affine x coordinate
	* @param y affine y coordinate
	*/
	this(in CurveGFp _curve, in BigInt x, in BigInt y)
	{ 
		curve = _curve;
		ws = 2 * (curve.get_p_words() + 2);
		coord_x = monty_mult(x, curve.get_r2());
		coord_y = monty_mult(y, curve.get_r2());
		coord_z = monty_mult(1, curve.get_r2());
	}

	/**
	* += Operator
	* @param rhs the PointGFp to add to the local value
	* @result resulting PointGFp
	*/
	ref PointGFp opOpAssign(string op)(in PointGFp rhs)
		if (op == "+=")
	{
		Vector!BigInt ws = Vector!BigInt(9);
		add(rhs, ws);
		return this;
	}

	/**
	* -= Operator
	* @param rhs the PointGFp to subtract from the local value
	* @result resulting PointGFp
	*/
	ref PointGFp opOpAssign(string op)(in PointGFp rhs)
		if (op == "-=")
	{
		PointGFp minus_rhs = PointGFp(rhs).negate();
		
		if (is_zero())
			this = minus_rhs;
		else
			this += minus_rhs;
		
		return this;
	}

	/**
	* *= Operator
	* @param scalar the PointGFp to multiply with this
	* @result resulting PointGFp
	*/
	ref PointGFp opOpAssign(string op)(in BigInt scalar)
		if (op == "*=")
	{
		this = scalar * this;
		return this;
	}

	/**
	* Multiplication Operator
	* @param scalar the scalar value
	* @param point the point value
	* @return scalar*point on the curve
	*/
	ref PointGFp opBinary(string op)(in BigInt scalar, const ref PointGFp point)
		if (op == "*")
	{
		const CurveGFp curve = point.get_curve();
		
		if (scalar.is_zero())
			return PointGFp(curve); // zero point
		
		Vector!BigInt ws = Vector!BigInt(9);
		
		if (scalar.abs() <= 2) // special cases for small values
		{
			ubyte value = scalar.abs().byte_at(0);
			
			PointGFp result = point;
			
			if (value == 2)
				result.mult2(ws);
			
			if (scalar.is_negative())
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
				const bool bit_set = scalar.get_bit(bits_left - 1);
				
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
			
			if (scalar.is_negative())
				x1.negate();
			
			return x1;
			
		} else {
			const size_t window_size = 4;
			
			Vector!PointGFp Ps = Vector!PointGFp(1 << window_size);
			Ps[0] = PointGFp(curve);
			Ps[1] = point;
			
			for (size_t i = 2; i != Ps.length; ++i)
			{
				Ps[i] = Ps[i-1];
				Ps[i].add(point, ws);
			}
			
			PointGFp H(curve); // create as zero
			size_t bits_left = scalar_bits;
			
			while (bits_left >= window_size)
			{
				foreach (size_t i; 0 .. window_size)
					H.mult2(ws);
				
				const uint nibble = scalar.get_substring(bits_left - window_size,
				                                         window_size);
				
				H.add(Ps[nibble], ws);
				
				bits_left -= window_size;
			}
			
			while (bits_left)
			{
				H.mult2(ws);
				if (scalar.get_bit(bits_left-1))
					H.add(point, ws);
				
				--bits_left;
			}
			
			if (scalar.is_negative())
				H.negate();
			
			return H;
		}
	}

	/**
	* Multiexponentiation
	* @param p1 a point
	* @param z1 a scalar
	* @param p2 a point
	* @param z2 a scalar
	* @result (p1 * z1 + p2 * z2)
	*/
	PointGFp multi_exponentiate(in PointGFp p1, in BigInt z1,
	                            in PointGFp p2, in BigInt z2)
	{
		const PointGFp p3 = p1 + p2;
		
		PointGFp H = PointGFp(p1.curve); // create as zero
		size_t bits_left = std.algorithm.max(z1.bits(), z2.bits());
		
		Vector!BigInt ws = Vector!BigInt(9);
		
		while (bits_left)
		{
			H.mult2(ws);
			
			const bool z1_b = z1.get_bit(bits_left - 1);
			const bool z2_b = z2.get_bit(bits_left - 1);
			
			if (z1_b == true && z2_b == true)
				H.add(p3, ws);
			else if (z1_b)
				H.add(p1, ws);
			else if (z2_b)
				H.add(p2, ws);
			
			--bits_left;
		}
		
		if (z1.is_negative() != z2.is_negative())
			H.negate();
		
		return H;
	}

	/**
	* Negate this point
	* @return this
	*/
	ref PointGFp negate()
	{
		if (!is_zero())
			coord_y = curve.get_p() - coord_y;
		return this;
	}

	/**
	* Return base curve of this point
	* @result the curve over GF(p) of this point
	*/
	const ref CurveGFp get_curve() const { return curve; }

	/**
	* get affine x coordinate
	* @result affine x coordinate
	*/
	BigInt get_affine_x() const
	{
		if (is_zero())
			throw new Illegal_Transformation("Cannot convert zero point to affine");
		
		const BigInt r2 = curve.get_r2();
		
		BigInt z2 = monty_sqr(coord_z);
		z2 = inverse_mod(z2, curve.get_p());
		
		z2 = monty_mult(z2, r2);
		return monty_mult(coord_x, z2);
	}

	/**
	* get affine y coordinate
	* @result affine y coordinate
	*/
	BigInt get_affine_y() const
	{
		if (is_zero())
			throw new Illegal_Transformation("Cannot convert zero point to affine");
		
		const BigInt r2 = curve.get_r2();
		
		BigInt z3 = monty_mult(coord_z, monty_sqr(coord_z));
		z3 = inverse_mod(z3, curve.get_p());
		z3 = monty_mult(z3, r2);
		return monty_mult(coord_y, z3);
	}

	/**
	* Is this the point at infinity?
	* @result true, if this point is at infinity, false otherwise.
	*/
	bool is_zero() const
	{ return (coord_x.is_zero() && coord_z.is_zero()); }

	/**
	* Checks whether the point is to be found on the underlying
	* curve; used to prevent fault attacks.
	* @return if the point is on the curve
	*/
	bool on_the_curve() const
	{
		/*
		Is the point still on the curve?? (If everything is correct, the
		point is always on its curve; then the function will return true.
		If somehow the state is corrupted, which suggests a fault attack
		(or internal computational error), then return false.
		*/
		
		if (is_zero())
			return true;
		
		BigInt y2 = monty_mult(monty_sqr(coord_y), 1);
		BigInt x3 = monty_mult(coord_x, monty_sqr(coord_x));
		
		BigInt ax = monty_mult(coord_x, curve.get_a_r());
		
		const BigInt b_r = curve.get_b_r();
		
		BigInt z2 = monty_sqr(coord_z);
		
		if (coord_z == z2) // Is z equal to 1 (in Montgomery form)?
		{
			if (y2 != monty_mult(x3 + ax + b_r, 1))
				return false;
		}
		
		BigInt z3 = monty_mult(coord_z, z2);
		
		BigInt ax_z4 = monty_mult(ax, monty_sqr(z2));
		
		BigInt b_z6 = monty_mult(b_r, monty_sqr(z3));
		
		if (y2 != monty_mult(x3 + ax_z4 + b_z6, 1))
			return false;
		
		return true;
	}


	/**
	* swaps the states of this and other, does not throw!
	* @param other the object to swap values with
	*/
	void swap(ref PointGFp other)
	{
		curve.swap(other.curve);
		coord_x.swap(other.coord_x);
		coord_y.swap(other.coord_y);
		coord_z.swap(other.coord_z);
		ws.swap(other.ws);
	}

	/**
	* Equality operator
	*/
	bool opEquals(in PointGFp other) const
	{
		if (get_curve() != other.get_curve())
			return false;
		
		// If this is zero, only equal if other is also zero
		if (is_zero())
			return other.is_zero();
		
		return (get_affine_x() == other.get_affine_x() &&
		        get_affine_y() == other.get_affine_y());
	}

private:

	/**
	* Montgomery multiplication/reduction
	* @param x first multiplicand
	* @param y second multiplicand
	* @param workspace temp space
	*/
	BigInt monty_mult(in BigInt x, in BigInt y) const
	{
		BigInt result;
		monty_mult(result, x, y);
		return result;
	}

	/**
	* Montgomery multiplication/reduction
	* @warning z cannot alias x or y
	* @param z output
	* @param x first multiplicand
	* @param y second multiplicand
	*/
	// Montgomery multiplication
	void monty_mult(ref BigInt z, in BigInt x, in BigInt y) const
	{
		//assert(&z != &x && &z != &y);
		
		if (x.is_zero() || y.is_zero())
		{
			z = 0;
			return;
		}
		
		const BigInt p = curve.get_p();
		const size_t p_size = curve.get_p_words();
		const word p_dash = curve.get_p_dash();
		
		const size_t output_size = 2*p_size + 1;
		
		z.grow_to(output_size);
		z.clear();
		
		bigint_monty_mul(z.mutable_data(), output_size,
		                 x.data(), x.length, x.sig_words(),
		                 y.data(), y.length, y.sig_words(),
		                 p.data(), p_size, p_dash,
		                 ws.ptr);
	}
	
	/**
	* Montgomery squaring/reduction
	* @param x multiplicand
	*/
	BigInt monty_sqr(in BigInt x) const
	{
		BigInt result;
		monty_sqr(result, x);
		return result;
	}

	/**
	* Montgomery squaring/reduction
	* @warning z cannot alias x
	* @param z output
	* @param x multiplicand
	*/
	void monty_sqr(ref BigInt z, in BigInt x) const
	{
		//assert(&z != &x);
		
		if (x.is_zero())
		{
			z = 0;
			return;
		}
		
		const BigInt p = curve.get_p();
		const size_t p_size = curve.get_p_words();
		const word p_dash = curve.get_p_dash();
		
		const size_t output_size = 2*p_size + 1;
		
		z.grow_to(output_size);
		z.clear();
		
		bigint_monty_sqr(z.mutable_data(), output_size,
		                 x.data(), x.length, x.sig_words(),
		                 p.data(), p_size, p_dash,
		                 ws.ptr);
	}

	/**
	* Point addition
	* @param workspace temp space, at least 11 elements
	*/
	void add(in PointGFp rhs, ref Vector!BigInt ws_bn)
	{
		if (is_zero())
		{
			coord_x = rhs.coord_x;
			coord_y = rhs.coord_y;
			coord_z = rhs.coord_z;
			return;
		}
		else if (rhs.is_zero())
			return;
		
		const BigInt p = curve.get_p();
		
		BigInt rhs_z2 = ws_bn[0];
		BigInt U1 = ws_bn[1];
		BigInt S1 = ws_bn[2];
		
		BigInt lhs_z2 = ws_bn[3];
		BigInt U2 = ws_bn[4];
		BigInt S2 = ws_bn[5];
		
		BigInt H = ws_bn[6];
		BigInt r = ws_bn[7];
		
		monty_sqr(rhs_z2, rhs.coord_z);
		monty_mult(U1, coord_x, rhs_z2);
		monty_mult(S1, coord_y, monty_mult(rhs.coord_z, rhs_z2));
		
		monty_sqr(lhs_z2, coord_z);
		monty_mult(U2, rhs.coord_x, lhs_z2);
		monty_mult(S2, rhs.coord_y, monty_mult(coord_z, lhs_z2));
		
		H = U2;
		H -= U1;
		if (H.is_negative())
			H += p;
		
		r = S2;
		r -= S1;
		if (r.is_negative())
			r += p;
		
		if (H.is_zero())
		{
			if (r.is_zero())
			{
				mult2(ws_bn);
				return;
			}
			
			this = PointGFp(curve); // setting myself to zero
			return;
		}
		
		monty_sqr(U2, H);
		
		monty_mult(S2, U2, H);
		
		U2 = monty_mult(U1, U2);
		
		monty_sqr(coord_x, r);
		coord_x -= S2;
		coord_x -= (U2 << 1);
		while (coord_x.is_negative())
			coord_x += p;
		
		U2 -= coord_x;
		if (U2.is_negative())
			U2 += p;
		
		monty_mult(coord_y, r, U2);
		coord_y -= monty_mult(S1, S2);
		if (coord_y.is_negative())
			coord_y += p;
		
		monty_mult(coord_z, monty_mult(coord_z, rhs.coord_z), H);
	}


	/**
	* Point doubling
	* @param workspace temp space, at least 9 elements
	*/
	void mult2(ref Vector!BigInt ws_bn)
	{
		if (is_zero())
			return;
		else if (coord_y.is_zero())
		{
			this = PointGFp(curve); // setting myself to zero
			return;
		}
		
		const BigInt p = curve.get_p();
		
		BigInt y_2 = ws_bn[0];
		BigInt S = ws_bn[1];
		BigInt z4 = ws_bn[2];
		BigInt a_z4 = ws_bn[3];
		BigInt M = ws_bn[4];
		BigInt U = ws_bn[5];
		BigInt x = ws_bn[6];
		BigInt y = ws_bn[7];
		BigInt z = ws_bn[8];
		
		monty_sqr(y_2, coord_y);
		
		monty_mult(S, coord_x, y_2);
		S <<= 2; // * 4
		while (S >= p)
			S -= p;
		
		monty_sqr(z4, monty_sqr(coord_z));
		monty_mult(a_z4, curve.get_a_r(), z4);
		
		M = monty_sqr(coord_x);
		M *= 3;
		M += a_z4;
		while (M >= p)
			M -= p;
		
		monty_sqr(x, M);
		x -= (S << 1);
		while (x.is_negative())
			x += p;
		
		monty_sqr(U, y_2);
		U <<= 3;
		while (U >= p)
			U -= p;
		
		S -= x;
		while (S.is_negative())
			S += p;
		
		monty_mult(y, M, S);
		y -= U;
		if (y.is_negative())
			y += p;
		
		monty_mult(z, coord_y, coord_z);
		z <<= 1;
		if (z >= p)
			z -= p;
		
		coord_x = x;
		coord_y = y;
		coord_z = z;
	}

	// relational operators
	bool opCmp(string op)(in PointGFp rhs)
		if (op == "!=")
	{
		return !(this == lhs);
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
		return this += rhs;
	}
	
	ref PointGFp opBinary(string op)(in PointGFp rhs)
		if (op == "-")
	{
		return this -= rhs;
	}
	
	ref PointGFp opBinary(string op)(in PointGFp point)
		if (op == "*")
	{
		return this *= point;
	}

	CurveGFp curve;
	BigInt coord_x, coord_y, coord_z;
	Secure_Vector!word ws; // workspace for Montgomery
}



// encoding and decoding
// encoding and decoding
Secure_Vector!ubyte EC2OSP(in PointGFp point, ubyte format)
{
	if (point.is_zero())
		return Secure_Vector!ubyte(1); // single 0 ubyte
	
	const size_t p_bytes = point.get_curve().get_p().bytes();
	
	BigInt x = point.get_affine_x();
	BigInt y = point.get_affine_y();
	
	Secure_Vector!ubyte bX = BigInt.encode_1363(x, p_bytes);
	Secure_Vector!ubyte bY = BigInt.encode_1363(y, p_bytes);
	
	if (format == UNCOMPRESSED)
	{
		Secure_Vector!ubyte result;
		result.push_back(0x04);
		
		result ~= bX;
		result ~= bY;
		
		return result;
	}
	else if (format == COMPRESSED)
	{
		Secure_Vector!ubyte result;
		result.push_back(0x02 | cast(ubyte)(y.get_bit(0)));
		
		result ~= bX;
		
		return result;
	}
	else if (format == HYBRID)
	{
		Secure_Vector!ubyte result;
		result.push_back(0x06 | cast(ubyte)(y.get_bit(0)));
		
		result ~= bX;
		result ~= bY;
		
		return result;
	}
	else
		throw new Invalid_Argument("illegal point encoding format specification");
}


PointGFp OS2ECP(in ubyte* data, size_t data_len, const ref CurveGFp curve)
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
		y = decompress_point(y_mod_2, x, curve);
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
		
		if (decompress_point(y_mod_2, x, curve) != y)
			throw new Illegal_Point("OS2ECP: Decoding error in hybrid format");
	}
	else
		throw new Invalid_Argument("OS2ECP: Unknown format type " ~ to!string(pc));
	
	PointGFp result = PointGFp(curve, x, y);
	
	if (!result.on_the_curve())
		throw new Illegal_Point("OS2ECP: Decoded point was not on the curve");
	
	return result;
}

PointGFp OS2ECP(Alloc)(in Vector!( ubyte, Alloc ) data, const ref CurveGFp curve)
{ return OS2ECP(data.ptr, data.length, curve); }

void swap(ref PointGFp x, ref PointGFp y)
{ import std.algorithm : swap; x.swap(y); }

private:

BigInt decompress_point(bool yMod2,
                        in BigInt x,
                        const ref CurveGFp curve)
{
	BigInt xpow3 = x * x * x;
	
	BigInt g = curve.get_a() * x;
	g += xpow3;
	g += curve.get_b();
	g = g % curve.get_p();
	
	BigInt z = ressol(g, curve.get_p());
	
	if (z < 0)
		throw new Illegal_Point("error during decompression");
	
	if (z.get_bit(0) != yMod2)
		z = curve.get_p() - z;
	
	return z;
}
