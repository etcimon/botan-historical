/*
* Sketchy HTTP client
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.http_util;
import botan.parsing;
import botan.hex;
import botan.internal.stl_util;
import sstream;

#if defined(BOTAN_HAS_BOOST_ASIO)
import boost/asio.hpp;
#endif
namespace HTTP {

#if defined(BOTAN_HAS_BOOST_ASIO)
string http_transact_asio(in string hostname,
										 in string message)
{
	using namespace boost::asio::ip;

	boost::asio::ip::tcp::iostream tcp;

	tcp.connect(hostname, "http");

	if (!tcp)
		throw new Exception("HTTP connection to " ~ hostname ~ " failed");

	tcp << message;
	tcp.flush();

	std::ostringstream oss;
	oss << tcp.rdbuf();

	return oss.str();
}
#endif

string http_transact_fail(in string hostname,
										 in string)
{
	throw new Exception("Cannot connect to " ~ hostname +
									 ": network code disabled in build");
}

string url_encode(in string input)
{
	std::ostringstream out;

	foreach (c; input)
	{
		if (c >= 'A' && c <= 'Z')
			out << c;
		else if (c >= 'a' && c <= 'z')
			out << c;
		else if (c >= '0' && c <= '9')
			out << c;
		else if (c == '-' || c == '_' || c == '.' || c == '~')
			out << c;
		else
			out << '%' << hex_encode(cast(byte*)(&c), 1);
	}

	return out.str();
}

std::ostream& operator<<(std::ostream& o, const Response& resp)
{
	o << "HTTP " << resp.status_code() << " " << resp.status_message() << "";
	foreach (h; resp.headers())
		o << "Header '" << h.first << "' = '" << h.second << "'";
	o << "Body " << std.conv.to!string(resp.body().size()) << " bytes:";
	o.write(cast(string)(resp.body()[0]), resp.body().size());
	return o;
}

Response http_sync(http_exch_fn http_transact,
						 in string verb,
						 in string url,
						 in string content_type,
						 in Vector!byte body,
						 size_t allowable_redirects)
{
	const auto protocol_host_sep = url.find("://");
	if (protocol_host_sep == string::npos)
		throw new Exception("Invalid URL " ~ url);
	const string protocol = url.substr(0, protocol_host_sep);

	const auto host_loc_sep = url.find('/', protocol_host_sep + 3);

	string hostname, loc;

	if (host_loc_sep == string::npos)
	{
		hostname = url.substr(protocol_host_sep + 3, string::npos);
		loc = "/";
	}
	else
	{
		hostname = url.substr(protocol_host_sep + 3, host_loc_sep-protocol_host_sep-3);
		loc = url.substr(host_loc_sep, string::npos);
	}

	std::ostringstream outbuf;

	outbuf << verb << " " << loc << " HTTP/1.0\r";
	outbuf << "Host: " << hostname << "\r";

	if (verb == "GET")
	{
		outbuf << "Accept: */*\r";
		outbuf << "Cache-Control: no-cache\r";
	}
	else if (verb == "POST")
		outbuf << "Content-Length: " << body.size() << "\r";

	if (content_type != "")
		outbuf << "Content-Type: " << content_type << "\r";
	outbuf << "Connection: close\r\r";
	outbuf.write(cast(string)(body[0]), body.size());

	std::istringstream io(http_transact(hostname, outbuf.str()));

	string line1;
	std::getline(io, line1);
	if (!io || line1.empty())
		throw new Exception("No response");

	stringstream response_stream(line1);
	string http_version;
	uint status_code;
	string status_message;

	response_stream >> http_version >> status_code;

	std::getline(response_stream, status_message);

	if (!response_stream || http_version.substr(0,5) != "HTTP/")
		throw new Exception("Not an HTTP response");

	HashMap!(string, string) headers;
	string header_line;
	while (std::getline(io, header_line) && header_line != "\r")
	{
		auto sep = header_line.find(": ");
		if (sep == string::npos || sep > header_line.size() - 2)
			throw new Exception("Invalid HTTP header " ~ header_line);
		const string key = header_line.substr(0, sep);

		if (sep + 2 < header_line.size() - 1)
		{
			const string val = header_line.substr(sep + 2, (header_line.size() - 1) - (sep + 2));
			headers[key] = val;
		}
	}

	if (status_code == 301 && headers.count("Location"))
	{
		if (allowable_redirects == 0)
			throw new Exception("HTTP redirection count exceeded");
		return GET_sync(headers["Location"], allowable_redirects - 1);
	}

	Vector!byte resp_body;
	Vector!byte buf(4096);
	while(io.good())
	{
		io.read(cast(char*)(&buf[0]), buf.size());
		resp_body.insert(resp_body.end(), &buf[0], &buf[io.gcount()]);
	}

	const string header_size = search_map(headers, string("Content-Length"));

	if (header_size != "")
	{
		if (resp_body.size() != to_uint(header_size))
			throw new Exception("Content-Length disagreement, header says " ~
											 header_size ~ " got " ~ std.conv.to!string(resp_body.size()));
	}

	return Response(status_code, status_message, resp_body, headers);
}

Response http_sync(in string verb,
						 in string url,
						 in string content_type,
						 in Vector!byte body,
						 size_t allowable_redirects)
{
	return http_sync(
#if defined(BOTAN_HAS_BOOST_ASIO)
		http_transact_asio,
#else
		http_transact_fail,
#endif
		verb,
		url,
		content_type,
		body,
		allowable_redirects);
}

Response GET_sync(in string url, size_t allowable_redirects)
{
	return http_sync("GET", url, "", Vector!byte(), allowable_redirects);
}

Response POST_sync(in string url,
						 in string content_type,
						 in Vector!byte body,
						 size_t allowable_redirects)
{
	return http_sync("POST", url, content_type, body, allowable_redirects);
}

std::future<Response> GET_async(in string url, size_t allowable_redirects)
{
	return std::async(std::launch::async, GET_sync, url, allowable_redirects);
}

}

}
