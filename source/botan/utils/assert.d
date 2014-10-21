/*
* Runtime assertion checking
* (C) 2010 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.assert_;

import botan.build;

/**
* Called when an assertion fails
* Disabled in favor of druntime assert()
void assertion_failure(string expr_str,
                       string assertion_made,
                       string func,
                       string file,
                       int line)
{
	import std.array : Appender;
	Appender!string format;
	
	format ~= "False assertion ";
	
	if (assertion_made && assertion_made[0] != 0)
		format ~= "'" ~ assertion_made ~ "' (expression " ~ expr_str ~ ") ";
	else
		format ~= expr_str ~ " ";
	
	if (func)
		format ~= "in " ~ func ~ " ";
	
	format ~= "@" ~ file ~ ":" ~ line;
	
	throw new Exception(format.data);
}*/

/**
* Make an assertion
*/
void assert(bool expr, string assertion_made) {
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

void BOTAN_UNUSED(alias v)() { cast(void)(v) }

not necessary in D
*/