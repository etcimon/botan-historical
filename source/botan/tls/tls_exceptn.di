/*
* Exceptions
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#define BOTAN_TLS_EXCEPTION_H__

#include <botan/exceptn.h>
#include <botan/tls_alert.h>
namespace TLS {

/**
* Exception Base Class
*/
class TLS_Exception : public Exception
{
	public:
		Alert::Type type() const noexcept { return alert_type; }

		TLS_Exception(Alert::Type type,
						  in string err_msg = "Unknown error") :
			Exception(err_msg), alert_type(type) {}

	private:
		Alert::Type alert_type;
};

/**
* Unexpected_Message Exception
*/
struct Unexpected_Message : public TLS_Exception
{
	Unexpected_Message(in string err) :
		TLS_Exception(Alert::UNEXPECTED_MESSAGE, err) {}
};

}