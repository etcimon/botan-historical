/*
* BigInt Input/Output
* (C) 1999-2007 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.bigint;
import iostream;
/*
* Write the BigInt into a stream
*/
std::ostream& operator<<(std::ostream& stream, ref const BigInt n)
{
	BigInt::Base base = BigInt::Decimal;
	if (stream.flags() & std::ios::hex)
		base = BigInt::Hexadecimal;
	else if (stream.flags() & std::ios::oct)
		throw new Exception("Octal output of BigInt not supported");

	if (n == 0)
		stream.write("0", 1);
	else
	{
		if (n < 0)
			stream.write("-", 1);
		const Vector!( byte ) buffer = BigInt::encode(n, base);
		size_t skip = 0;
		while(skip < buffer.size() && buffer[skip] == '0')
			++skip;
		stream.write(cast(string)(buffer[0]) + skip,
						 buffer.size() - skip);
	}
	if (!stream.good())
		throw new Stream_IO_Error("BigInt output operator has failed");
	return stream;
}

/*
* Read the BigInt from a stream
*/
std::istream& operator>>(std::istream& stream, ref BigInt n)
{
	string str;
	std::getline(stream, str);
	if (stream.bad() || (stream.fail() && !stream.eof()))
		throw new Stream_IO_Error("BigInt input operator has failed");
	n = BigInt(str);
	return stream;
}

}
