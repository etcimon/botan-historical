/*
* MPI Algorithms
* (C) 1999-2010 Jack Lloyd
*	  2006 Luca Piccarreta
*
* Distributed under the terms of the botan license.
*/

import botan.mp_types;
/*
* The size of the word type, in bits
*/
const size_t MP_WORD_BITS = BOTAN_MP_WORD_BITS;

extern "C" {

/**
* Two operand addition
* @param x the first operand (and output)
* @param x_size size of x
* @param y the second operand
* @param y_size size of y (must be >= x_size)
*/
void bigint_add2(word x[], size_t x_size,
					  const word y[], size_t y_size);

/**
* Three operand addition
*/
void bigint_add3(word z[],
					  const word x[], size_t x_size,
					  const word y[], size_t y_size);

/**
* Two operand addition with carry out
*/
word bigint_add2_nc(word x[], size_t x_size, const word y[], size_t y_size);

/**
* Three operand addition with carry out
*/
word bigint_add3_nc(word z[],
						  const word x[], size_t x_size,
						  const word y[], size_t y_size);

/**
* Two operand subtraction
*/
word bigint_sub2(word x[], size_t x_size,
					  const word y[], size_t y_size);

/**
* Two operand subtraction, x = y - x; assumes y >= x
*/
void bigint_sub2_rev(word x[], const word y[], size_t y_size);

/**
* Three operand subtraction
*/
word bigint_sub3(word z[],
					  const word x[], size_t x_size,
					  const word y[], size_t y_size);

/*
* Shift Operations
*/
void bigint_shl1(word x[], size_t x_size,
					  size_t word_shift, size_t bit_shift);

void bigint_shr1(word x[], size_t x_size,
					  size_t word_shift, size_t bit_shift);

void bigint_shl2(word y[], const word x[], size_t x_size,
					  size_t word_shift, size_t bit_shift);

void bigint_shr2(word y[], const word x[], size_t x_size,
					  size_t word_shift, size_t bit_shift);

/*
* Simple O(N^2) Multiplication and Squaring
*/
void bigint_simple_mul(word z[],
							  const word x[], size_t x_size,
							  const word y[], size_t y_size);

void bigint_simple_sqr(word z[], const word x[], size_t x_size);

/*
* Linear Multiply
*/
void bigint_linmul2(word x[], size_t x_size, word y);
void bigint_linmul3(word z[], const word x[], size_t x_size, word y);

/**
* Montgomery Reduction
* @param z integer to reduce, of size exactly 2*(p_size+1).
			  Output is in the first p_size+1 words, higher
			  words are set to zero.
* @param p modulus
* @param p_size size of p
* @param p_dash Montgomery value
* @param workspace array of at least 2*(p_size+1) words
*/
void bigint_monty_redc(word z[],
							  const word p[], size_t p_size,
							  word p_dash,
							  word workspace[]);

/*
* Montgomery Multiplication
*/
void bigint_monty_mul(word z[], size_t z_size,
							 const word x[], size_t x_size, size_t x_sw,
							 const word y[], size_t y_size, size_t y_sw,
							 const word p[], size_t p_size, word p_dash,
							 word workspace[]);

/*
* Montgomery Squaring
*/
void bigint_monty_sqr(word z[], size_t z_size,
							 const word x[], size_t x_size, size_t x_sw,
							 const word p[], size_t p_size, word p_dash,
							 word workspace[]);

/**
* Compare x and y
*/
s32bit bigint_cmp(const word x[], size_t x_size,
						const word y[], size_t y_size);

/**
* Compute ((n1<<bits) + n0) / d
*/
word bigint_divop(word n1, word n0, word d);

/**
* Compute ((n1<<bits) + n0) % d
*/
word bigint_modop(word n1, word n0, word d);

/*
* Comba Multiplication / Squaring
*/
void bigint_comba_mul4(word z[8], const word x[4], const word y[4]);
void bigint_comba_mul6(word z[12], const word x[6], const word y[6]);
void bigint_comba_mul8(word z[16], const word x[8], const word y[8]);
void bigint_comba_mul16(word z[32], const word x[16], const word y[16]);

void bigint_comba_sqr4(word output[8], const word input[4]);
void bigint_comba_sqr6(word output[12], const word input[6]);
void bigint_comba_sqr8(word output[16], const word input[8]);
void bigint_comba_sqr16(word output[32], const word input[16]);

}

/*
* High Level Multiplication/Squaring Interfaces
*/
void bigint_mul(word z[], size_t z_size, word workspace[],
					 const word x[], size_t x_size, size_t x_sw,
					 const word y[], size_t y_size, size_t y_sw);

void bigint_sqr(word z[], size_t z_size, word workspace[],
					 const word x[], size_t x_size, size_t x_sw);