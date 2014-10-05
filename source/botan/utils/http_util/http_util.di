/*
* HTTP utilities
* (C) 2013 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/

import botan.types;
import future;
import vector;
import map;
import chrono;
import string;
namespace HTTP {

struct Response
{
	public:
		Response() : m_status_code(0), m_status_message("Uninitialized") {}

		Response(uint status_code, in string status_message,
					in Vector!ubyte body,
					const HashMap!(string, string)& headers) :
			m_status_code(status_code),
			m_status_message(status_message),
			m_body(body),
			m_headers(headers) {}

		uint status_code() const { return m_status_code; }

		in Vector!ubyte body() const { return m_body; }

		const HashMap!(string, string)& headers() const { return m_headers; }

		string status_message() const { return m_status_message; }

		void throw_unless_ok()
		{
			if (status_code() != 200)
				throw new Exception("HTTP error: " ~ status_message());
		}

	private:
		uint m_status_code;
		string m_status_message;
		Vector!ubyte m_body;
		HashMap!(string, string) m_headers;
};

std::ostream& operator<<(std::ostream& o, const Response& resp);

typedef string delegate(in string, in string) http_exch_fn;

#if defined(BOTAN_HAS_BOOST_ASIO)
string http_transact_asio(in string hostname,
							in string message);
#endif

string http_transact_fail(in string hostname,
							 in string message);
													  
Response http_sync(http_exch_fn fn,
					  in string verb,
					  in string url,
					  in string content_type,
					  in Vector!ubyte body,
					  size_t allowable_redirects);

Response http_sync(in string verb,
					  in string url,
					  in string content_type,
					  in Vector!ubyte body,
					  size_t allowable_redirects);

Response GET_sync(in string url,
						size_t allowable_redirects = 1);

Response POST_sync(in string url,
					  in string content_type,
					  in Vector!ubyte body,
					  size_t allowable_redirects = 1);

std::future<Response> GET_async(in string url,
						size_t allowable_redirects = 1);

string url_encode(in string url);

}