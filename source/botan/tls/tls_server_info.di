/*
* TLS Server Information
* (C) 2012 Jack Lloyd
*
* Released under the terms of the botan license.
*/

#include <botan/types.h>
#include <string>
namespace TLS {

/**
* Represents information known about a TLS server.
*/
class Server_Information
{
	public:
		/**
		* An empty server info - nothing known
		*/
		Server_Information() : m_hostname(""), m_service(""), m_port(0) {}

		/**
		* @param hostname the host's DNS name, if known
		* @param port specifies the protocol port of the server (eg for
		*		  TCP/UDP). Zero represents unknown.
		*/
		Server_Information(in string hostname,
								ushort port = 0) :
			m_hostname(hostname), m_service(""), m_port(port) {}

		/**
		* @param hostname the host's DNS name, if known
		* @param service is a text string of the service type
		*		  (eg "https", "tor", or "git")
		* @param port specifies the protocol port of the server (eg for
		*		  TCP/UDP). Zero represents unknown.
		*/
		Server_Information(in string hostname,
								in string service,
								ushort port = 0) :
			m_hostname(hostname), m_service(service), m_port(port) {}

		string hostname() const { return m_hostname; }

		string service() const { return m_service; }

		ushort port() const { return m_port; }

		bool empty() const { return m_hostname.empty(); }

	private:
		string m_hostname, m_service;
		ushort m_port;
};

 bool operator==(in Server_Information a, const Server_Information& b)
{
	return (a.hostname() == b.hostname()) &&
			 (a.service() == b.service()) &&
			 (a.port() == b.port());

}

 bool operator!=(in Server_Information a, const Server_Information& b)
{
	return !(a == b);
}

 bool operator<(in Server_Information a, const Server_Information& b)
{
	if (a.hostname() != b.hostname())
		return (a.hostname() < b.hostname());
	if (a.service() != b.service())
		return (a.service() < b.service());
	if (a.port() != b.port())
		return (a.port() < b.port());
	return false; // equal
}

}