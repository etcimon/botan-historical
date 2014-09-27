/*
* Runtime assertion checking
* (C) 2010,2012 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.exceptn;
import sstream;
void assertion_failure(string expr_str,
							  string assertion_made,
							  string func,
							  string file,
							  int line)
{
	std::ostringstream format;

	format << "False assertion ";

	if (assertion_made && assertion_made[0] != 0)
		format << "'" << assertion_made << "' (expression " << expr_str << ") ";
	else
		format << expr_str << " ";

	if (func)
		format << "in " << func << " ";

	format << "@" << file << ":" << line;

	throw new Exception(format.str());
}

}
