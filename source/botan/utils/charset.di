/*
* Character Set Handling
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

#include <botan/types.h>
#include <string>
/**
* The different charsets (nominally) supported by Botan.
*/
enum Character_Set {
	LOCAL_CHARSET,
	UCS2_CHARSET,
	UTF8_CHARSET,
	LATIN1_CHARSET
};

namespace Charset {

/*
* Character Set Handling
*/
string transcode(in string str,
										  Character_Set to,
										  Character_Set from);

bool is_digit(char c);
bool is_space(char c);
bool caseless_cmp(char x, char y);

byte char2digit(char c);
char digit2char(byte b);

}