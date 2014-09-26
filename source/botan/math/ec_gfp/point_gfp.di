/*
* Point arithmetic on elliptic curves over GF(p)
*
* (C) 2007 Martin Doering, Christoph Ludwig, Falko Strenzke
*	  2008-2011 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/curve_gfp.h>
#include <vector>
/**
* Exception thrown if you try to convert a zero point to an affine
* coordinate
*/
struct Illegal_Transformation : public Exception
{
	Illegal_Transformation(in string err =
								  "Requested transformation is not possible") :
		Exception(err) {}
};

/**
* Exception thrown if some form of illegal point is decoded
*/
struct Illegal_Point : public Exception
{
	Illegal_Point(in string err = "Malformed ECP point detected") :
		Exception(err) {}
};

/**
* This class represents one point on a curve of GF(p)
*/
class PointGFp
{
	public:
		enum Compression_Type {
			UNCOMPRESSED = 0,
			COMPRESSED	= 1,
			HYBRID		 = 2
	};

		/**
		* Construct an uninitialized PointGFp
		*/
		PointGFp() {}

		/**
		* Construct the zero point
		* @param curve The base curve
		*/
		PointGFp(in CurveGFp curve);

		/**
		* Copy constructor
		*/
		PointGFp(in PointGFp) = default;

		/**
		* Move Constructor
		*/
		PointGFp(PointGFp&& other)
		{
			this->swap(other);
		}

		/**
		* Standard Assignment
		*/
		PointGFp& operator=(in PointGFp) = default;

		/**
		* Move Assignment
		*/
		PointGFp& operator=(PointGFp&& other)
		{
			if(this != &other)
				this->swap(other);
			return (*this);
		}

		/**
		* Construct a point from its affine coordinates
		* @param curve the base curve
		* @param x affine x coordinate
		* @param y affine y coordinate
		*/
		PointGFp(in CurveGFp curve, in BigInt x, in BigInt y);

		/**
		* += Operator
		* @param rhs the PointGFp to add to the local value
		* @result resulting PointGFp
		*/
		PointGFp& operator+=(in PointGFp rhs);

		/**
		* -= Operator
		* @param rhs the PointGFp to subtract from the local value
		* @result resulting PointGFp
		*/
		PointGFp& operator-=(in PointGFp rhs);

		/**
		* *= Operator
		* @param scalar the PointGFp to multiply with *this
		* @result resulting PointGFp
		*/
		PointGFp& operator*=(in BigInt scalar);

		/**
		* Multiplication Operator
		* @param scalar the scalar value
		* @param point the point value
		* @return scalar*point on the curve
		*/
		friend PointGFp operator*(in BigInt scalar, in PointGFp point);

		/**
		* Multiexponentiation
		* @param p1 a point
		* @param z1 a scalar
		* @param p2 a point
		* @param z2 a scalar
		* @result (p1 * z1 + p2 * z2)
		*/
		friend PointGFp multi_exponentiate(
		  in PointGFp p1, in BigInt z1,
		  in PointGFp p2, in BigInt z2);

		/**
		* Negate this point
		* @return *this
		*/
		PointGFp& negate()
		{
			if(!is_zero())
				coord_y = curve.get_p() - coord_y;
			return *this;
		}

		/**
		* Return base curve of this point
		* @result the curve over GF(p) of this point
		*/
		const CurveGFp& get_curve() const { return curve; }

		/**
		* get affine x coordinate
		* @result affine x coordinate
		*/
		BigInt get_affine_x() const;

		/**
		* get affine y coordinate
		* @result affine y coordinate
		*/
		BigInt get_affine_y() const;

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
		bool on_the_curve() const;

		/**
		* swaps the states of *this and other, does not throw!
		* @param other the object to swap values with
		*/
		void swap(PointGFp& other);

		/**
		* Equality operator
		*/
		bool operator==(in PointGFp other) const;
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
		void monty_mult(BigInt& z, in BigInt x, in BigInt y) const;

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
		void monty_sqr(BigInt& z, in BigInt x) const;

		/**
		* Point addition
		* @param workspace temp space, at least 11 elements
		*/
		void add(in PointGFp other, Vector!( BigInt )& workspace);

		/**
		* Point doubling
		* @param workspace temp space, at least 9 elements
		*/
		void mult2(Vector!( BigInt )& workspace);

		CurveGFp curve;
		BigInt coord_x, coord_y, coord_z;
		mutable secure_vector<word> ws; // workspace for Montgomery
};

// relational operators
 bool operator!=(in PointGFp lhs, in PointGFp rhs)
{
	return !(rhs == lhs);
}

// arithmetic operators
 PointGFp operator-(in PointGFp lhs)
{
	return PointGFp(lhs).negate();
}

 PointGFp operator+(in PointGFp lhs, in PointGFp rhs)
{
	PointGFp tmp(lhs);
	return tmp += rhs;
}

 PointGFp operator-(in PointGFp lhs, in PointGFp rhs)
{
	PointGFp tmp(lhs);
	return tmp -= rhs;
}

 PointGFp operator*(in PointGFp point, in BigInt scalar)
{
	return scalar * point;
}

// encoding and decoding
SafeVector!byte EC2OSP(in PointGFp point, byte format);

PointGFp OS2ECP(in byte* data, size_t data_len,
								  const CurveGFp& curve);

PointGFp OS2ECP(Alloc)(in Vector!( byte, Alloc ) data, const CurveGFp& curve)
{ return OS2ECP(&data[0], data.size(), curve); }

}

namespace std {

template<>
 void swap<Botan::PointGFp>(Botan::PointGFp& x, Botan::PointGFp& y)
{ x.swap(y); }