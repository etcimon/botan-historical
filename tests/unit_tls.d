
#include "tests.h"

#if defined(BOTAN_HAS_TLS)

#include <botan/auto_rng.h>
#include <botan/tls_server.h>
#include <botan/tls_client.h>
#include <botan/pkcs10.h>
#include <botan/x509self.h>
#include <botan/rsa.h>
#include <botan/x509_ca.h>
#include <botan/hex.h>

#include <iostream>
#include <vector>
#include <memory>



namespace {

class Credentials_Manager_Test : public Credentials_Manager
{
	public:
		Credentials_Manager_Test(const X509_Certificate server_cert,
										 const X509_Certificate ca_cert,
										 Private_Key* server_key) :
			m_server_cert(server_cert),
			m_ca_cert(ca_cert),
			m_key(server_key)
		{
			auto store = new Certificate_Store_In_Memory;
			store.add_certificate(m_ca_cert);
			m_stores.push_back(store);
		}

		std::vector<Certificate_Store*>
		trusted_certificate_authorities(string,
												  string) override
		{
			return m_stores;
		}

		std::vector<X509_Certificate> cert_chain(
			in Vector!string cert_key_types,
			string type,
			string) override
		{
			std::vector<X509_Certificate> chain;

			if(type == "tls-server")
			{
				bool have_match = false;
				for(size_t i = 0; i != cert_key_types.length; ++i)
					if(cert_key_types[i] == m_key.algo_name())
						have_match = true;

				if(have_match)
				{
					chain.push_back(m_server_cert);
					chain.push_back(m_ca_cert);
				}
			}

			return chain;
		}

		void verify_certificate_chain(
			string type,
			string purported_hostname,
			const std::vector<X509_Certificate>& cert_chain) override
		{
			try
			{
				Credentials_Manager::verify_certificate_chain(type,
																			 purported_hostname,
																			 cert_chain);
			}
			catch(Exception e)
			{
				writeln("Certificate verification failed - " ~ e.msg " ~ - but will ignore");
			}
		}

		Private_Key* private_key_for(const X509_Certificate,
											  string,
											  string) override
		{
			return m_key;
		}
	public:
		X509_Certificate m_server_cert, m_ca_cert;
		Private_Key* m_key;
		std::vector<Certificate_Store*> m_stores;
};

Credentials_Manager* create_creds(RandomNumberGenerator rng)
{
	std::auto_ptr<Private_Key> ca_key(new RSA_PrivateKey(rng, 1024));

	X509_Cert_Options ca_opts;
	ca_opts.common_name = "Test CA";
	ca_opts.country = "US";
	ca_opts.CA_key(1);

	X509_Certificate ca_cert =
		X509::create_self_signed_cert(ca_opts,
												*ca_key,
												"SHA-256",
												rng);

	Private_Key* server_key = new RSA_PrivateKey(rng, 1024);

	X509_Cert_Options server_opts;
	server_opts.common_name = "localhost";
	server_opts.country = "US";

	PKCS10_Request req = X509::create_cert_req(server_opts,
															 *server_key,
															 "SHA-256",
															 rng);

	X509_CA ca(ca_cert, *ca_key, "SHA-256");

	auto now = std::chrono::system_clock::now();
	X509_Time start_time(now);
	typedef std::chrono::duration<int, std::ratio<31556926>> years;
	X509_Time end_time(now + years(1));

	X509_Certificate server_cert = ca.sign_request(req,
																  rng,
																  start_time,
																  end_time);

	return new Credentials_Manager_Test(server_cert, ca_cert, server_key);
}

size_t basic_test_handshake(RandomNumberGenerator rng,
									 Protocol_Version offer_version,
									 Credentials_Manager creds,
									 Policy policy)
{
	Session_Manager_In_Memory server_sessions(rng);
	Session_Manager_In_Memory client_sessions(rng);

	Vector!ubyte c2s_q, s2c_q, c2s_data, s2c_data;

	auto handshake_complete = (in Session session)
	{
			if(session.version() != offer_version)
				writeln("Wrong version negotiated");
			return true;
	};

	auto print_alert = (Alert alert, in ubyte[])
	{
			if(alert.is_valid())
				writeln("Server recvd alert " ~ alert.type_string());
	};

	auto save_server_data = (in ubyte[] buf)
	{
			c2s_data.insert(buf);
	};

	auto save_client_data = (in ubyte[] buf)
	{
			s2c_data.insert(buf);
	};

	Server server((in ubyte[] buf){ s2c_q.insert(buf); },
					 save_server_data,
					 print_alert,
					 handshake_complete,
					 server_sessions,
					 creds,
					 policy,
					 rng,
					 { "test/1", "test/2" });

	auto next_protocol_chooser = (Vector!string protos) {
		if(protos.length != 2)
			writeln("Bad protocol size");
		if(protos[0] != "test/1" || protos[1] != "test/2")
			writeln("Bad protocol values");
		return "test/3";
	};

	Client client((in ubyte[] buf)
				 { c2s_q.insert(buf); },
				 save_client_data,
				 print_alert,
				 handshake_complete,
				 client_sessions,
				 creds,
				 policy,
				 rng,
				 Server_Information(),
				 offer_version,
				 next_protocol_chooser);

	while(true)
	{
		if(client.is_active())
			client.send("1");
		if(server.is_active())
		{
			if(server.next_protocol() != "test/3")
				writeln("Wrong protocol " ~ server.next_protocol());
			server.send("2");
		}

		/*
		* Use this as a temp value to hold the queues as otherwise they
		* might end up appending more in response to messages during the
		* handshake.
		*/
		Vector!ubyte input;
		std::swap(c2s_q, input);

		try
		{
			server.received_data(&input[0], input.length);
		}
		catch(Exception e)
		{
			writeln("Server error - " ~ e.msg);
			break;
		}

		input.clear();
		std::swap(s2c_q, input);

		try
		{
			client.received_data(&input[0], input.length);
		}
		catch(Exception e)
		{
			writeln("Client error - " ~ e.msg);
			break;
		}

		if(c2s_data.length)
		{
			if(c2s_data[0] != '1')
			{
				writeln("Error");
				return 1;
			}
		}

		if(s2c_data.length)
		{
			if(s2c_data[0] != '2')
			{
				writeln("Error");
				return 1;
			}
		}

		if(s2c_data.length && c2s_data.length)
			break;
	}

	return 0;
}

class Test_Policy : public Policy
{
	public:
		bool acceptable_protocol_version(Protocol_Version) const { return true; }
};

}

size_t test_tls()
{
	size_t errors = 0;

	Test_Policy default_policy;
	AutoSeeded_RNG rng;
	std::auto_ptr<Credentials_Manager> basic_creds(create_creds(rng));

	errors += basic_test_handshake(rng, Protocol_Version::SSL_V3, *basic_creds, default_policy);
	errors += basic_test_handshake(rng, Protocol_Version::TLS_V10, *basic_creds, default_policy);
	errors += basic_test_handshake(rng, Protocol_Version::TLS_V11, *basic_creds, default_policy);
	errors += basic_test_handshake(rng, Protocol_Version::TLS_V12, *basic_creds, default_policy);

	test_report("TLS", 4, errors);

	return errors;
}

#else
size_t test_tls() { return 0; }
#endif
