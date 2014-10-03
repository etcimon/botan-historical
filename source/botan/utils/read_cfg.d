/*
* Simple config/test file reader
* (C) 2013,2014 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.parsing;
import ctype.h;
void lex_cfg(std::istream& is,
				void delegate(string) cb)
{
	while(is.good())
	{
		string s;

		std::getline(is, s);

		while(is.good() && s.back() == '\\')
		{
			while(s.size() && (s.back() == '\\' || s.back() == ''))
				s.resize(s.size()-1);

			string x;
			std::getline(is, x);

			size_t i = 0;

			while(i < x.size() && (::isspace(x[i])))
				++i;

			s += x.substr(i);
		}

		auto comment = s.find('#');
		if (comment)
			s = s.substr(0, comment);

		if (s.empty())
			continue;

		auto parts = split_on_pred(s, [](char c) { return ::isspace(c); });

		foreach (ref p; parts)
		{
			if (p.empty())
				continue;

			auto eq = p.find("=");

			if (eq == string::npos || p.size() < 2)
			{
				cb(p);
			}
			else if (eq == 0)
			{
				cb("=");
				cb(p.substr(1, string::npos));
			}
			else if (eq == p.size() - 1)
			{
				cb(p.substr(0, p.size() - 1));
				cb("=");
			}
			else if (eq != string::npos)
			{
				cb(p.substr(0, eq));
				cb("=");
				cb(p.substr(eq + 1, string::npos));
			}
		}
	}
}

void lex_cfg_w_headers(std::istream& is,
							  void delegate(string) cb,
							  void delegate(string) hdr_cb)
{
	auto intercept = [cb,hdr_cb](in string s)
	{
		if (s[0] == '[' && s[s.length()-1] == ']')
			hdr_cb(s.substr(1, s.length()-2));
		else
			cb(s);
	};

	lex_cfg(is, intercept);
}

HashMap<string, HashMap!(string, string)>
	parse_cfg(std::istream& is)
{
	string header = "default";
	HashMap<string, HashMap!(string, string)> vals;
	string key;

	auto header_cb = [&header](const string i) { header = i; };
	auto cb = [&header,&key,&vals](const string s)
	{
		if (s == "=")
		{
			BOTAN_ASSERT(!key.empty(), "Valid assignment in config");
		}
		else if (key.empty())
			key = s;
		else
		{
			vals[header][key] = s;
			key = "";
		}
	};

	lex_cfg_w_headers(is, cb, header_cb);

	return vals;
}

}
