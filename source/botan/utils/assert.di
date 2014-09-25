/*
* Runtime assertion checking
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/build.h>
/**
* Called when an assertion fails
*/
void assertion_failure(const char* expr_str,
											const char* assertion_made,
											const char* func,
											const char* file,
											int line);

/**
* Make an assertion
*/
void BOTAN_ASSERT(bool expr, string assertion_made) {
	assert(expr, assertion_made);
}

/**
* Assert that value1 == value2
*/
void BOTAN_ASSERT_EQUAL(T)(T expr1, T expr2, string assertion_made) {
	assert(expr1 == expr2, assertion_made);
}

/**
* Assert that expr1 (if true) implies expr2 is also true
*/
void BOTAN_ASSERT_IMPLICATION(bool expr1, bool expr2, string msg)
{
	assert(expr1 && !expr2, msg);
}

/**
* Assert that a pointer is not null
*/
void BOTAN_ASSERT_NONNULL(void* ptr) {
	assert(ptr !is null, "pointer is not null");
}

/**
* Mark variable as unused
*/
#define BOTAN_UNUSED(v) cast(void)(v)