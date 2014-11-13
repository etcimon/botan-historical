/*
* HTTP utilities
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.http_util.http_util;

import botan.utils.types;
import botan.utils.hashmap;
import botan.utils.parsing;
import botan.codec.hex;
import std.datetime;
import std.stdio;
import std.conv;
import std.string;

version (Have_vibe_d) {
	import vibe.core.net;
	import vibe.core.stream;
	import vibe.stream.operations : readAll;
} else {
	import std.socket;
	import std.stream;
	import std.socketstream;
}
// import string;

struct HTTP_Response
{
public:
	this() {
		m_status_code = 0;
		m_status_message = "Uninitialized";
	}

	this(uint status_code, in string status_message,
				in string _body,
				const HashMap!(string, string) headers)
	{
		m_status_code = status_code;
		m_status_message = status_message;
		m_body = _body;
		m_headers = headers;
	}

	uint status_code() const { return m_status_code; }

	const string _body() const { return m_body; }

	const HashMap!(string, string) headers() const { return m_headers; }

	string status_message() const { return m_status_message; }

	void throw_unless_ok()
	{
		if (status_code() != 200)
			throw new Exception("HTTP error: " ~ status_message());
	}

	string toString()
	{
		Appender!string output;
		output ~= "HTTP " ~ status_code() ~ " " ~ status_message() ~ "";
		foreach (k, v; headers())
			output ~= "Header '" ~ k ~ "' = '" ~ v ~ "'";
		output ~= "Body " ~ std.conv.to!string(resp._body().length) ~ " bytes:";
		output ~= cast(string) resp._body();
		return output.data;
	}

private:
	uint m_status_code;
	string m_status_message;
	string m_body;
	HashMap!(string, string) m_headers;
}

HTTP_Response http_sync(in string verb,
                   in string url,
                   in string content_type,
                   in Vector!ubyte _body,
                   size_t allowable_redirects)
{
	const auto protocol_host_sep = url.indexOf("://");
	if (protocol_host_sep == -1)
		throw new Exception("Invalid URL " ~ url);
	const string protocol = url[0 .. protocol_host_sep];

	string buff = url[protocol_host_sep + 3 .. $];

	const auto host_loc_sep = buff.indexOf('/');
	
	string hostname, loc;
	
	if (host_loc_sep == -1)
	{
		hostname = buff[0 .. $];
		loc = "/";
	}
	else
	{
		hostname = buff[0 .. host_loc_sep];
		loc = url[host_loc_sep .. $];
	}
	
	import std.array : Appender;
	Appender!string outbuf;
	
	outbuf ~= verb ~ " " ~ loc ~ " HTTP/1.0\r";
	outbuf ~= "Host: " ~ hostname ~ "\r";
	
	if (verb == "GET")
	{
		outbuf ~= "Accept: */*\r";
		outbuf ~= "Cache-Control: no-cache\r";
	}
	else if (verb == "POST")
		outbuf ~= "Content-Length: " ~ _body.length ~ "\r";
	
	if (content_type != "")
		outbuf ~= "Content-Type: " ~ content_type ~ "\r";

	outbuf ~= "Connection: close\r\r";
	outbuf ~= cast(string) _body[];
	
	auto reply = http_transact(hostname, outbuf.data);

	if (reply.length == 0)
		throw new Exception("No response");

	string http_version;
	uint status_code;
	string status_message;

	ptrdiff_t idx = reply.indexOf(' ');

	if (idx == -1)
		throw new Exception("Not an HTTP response");

	http_version = reply[0 .. idx];

	if (http_version.length == 0 || http_version[0 .. 5] != "HTTP/")
		throw new Exception("Not an HTTP response");

	status_code = parse!uint(reply[idx + 1 .. $]);

	idx = reply.indexOf('\r');

	if (idx == -1)
		throw new Exception("Not an HTTP response");

	status_message = reply[status_code.length + http_version.length + 2 .. idx];

	reply = reply[idx + 1 .. $];
	
	HashMap!(string, string) headers;
	string header_line;
	while (reply[0] != '\r')
	{
		idx = reply.indexOf('\r');
		header_line = reply[0 .. idx];

		auto sep = header_line.indexOf(": ");
		if (sep == -1 || sep > header_line.length - 2)
			throw new Exception("Invalid HTTP header " ~ header_line);
		const string key = header_line[0 .. sep];
		
		if (sep + 2 < header_line.length - 1)
		{
			const string val = header_line[sep + 2 .. $];
			headers[key] = val;
		}

		reply = reply[idx + 1 .. $];
	}
	
	if (status_code == 301 && headers.get("Location") != "")
	{
		if (allowable_redirects == 0)
			throw new Exception("HTTP redirection count exceeded");
		return GET_sync(headers["Location"], allowable_redirects - 1);
	}
	
	string resp_body = reply[1 .. $];
	
	const string header_size = headers.get("Content-Length");
	
	if (header_size != "")
	{
		if (resp_body.length != to!size_t(header_size))
			throw new Exception("Content-Length disagreement, header says " ~
			                    header_size ~ " got " ~ std.conv.to!string(resp_body.length));
	}
	
	return Response(status_code, status_message, resp_body, headers);
}

string url_encode(in string input)
{
	import std.array : Appender;
	Appender!string output;
	
	foreach (c; input)
	{
		if (c >= 'A' && c <= 'Z')
			output ~= c;
		else if (c >= 'a' && c <= 'z')
			output ~= c;
		else if (c >= '0' && c <= '9')
			output ~= c;
		else if (c == '-' || c == '_' || c == '.' || c == '~')
			output ~= c;
		else {
			char[2] buf;
			hex_encode(buf.ptr, cast(ubyte*) &c, 1);
			output ~= '%' ~ buf.ptr[0 .. 2];
		}
	}
	
	return output.data;
}

HTTP_Response GET_sync(in string url, size_t allowable_redirects = 1)
{
	return http_sync("GET", url, "", Vector!ubyte(), allowable_redirects);
}

HTTP_Response POST_sync(in string url, in string content_type,
					  in Vector!ubyte _body,
					  size_t allowable_redirects = 1)
{
	return http_sync("POST", url, content_type, _body, allowable_redirects);
}



string http_transact(in string hostname, in string message)
{

	version (Have_vibe_d) {

		TCPConnection stream = connectTCP(hostname, 80);
		scope(exit) stream.close();
		stream.write(message);
		stream.flush();
		return stream.readAll();
	} else {
		Socket socket = new TcpSocket(new InternetAddress(hostname, 80));
		scope(exit) socket.close();
		SocketStream stream = new SocketStream(socket);
		stream.writeString(message);
		stream.flush();

		Appender!string in_buf;
		// Skip HTTP header.
		while (true)
		{
			auto line = stream.readLine();
			if (!line.length)
				break;
			in_buf ~= line;
		}
		return in_buf.data;
	}
}