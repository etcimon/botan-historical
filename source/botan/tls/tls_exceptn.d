/*
* Exceptions
* (C) 2004-2006 Jack Lloyd
*
* Released under the terms of the botan license.
*/
module botan.tls.tls_exceptn;

import botan.utils.exceptn;
import botan.tls.tls_alert;

/**
* Exception Base Class
*/
class TLS_Exception : Exception
{
public:
	Alert.Type type() const nothrow { return alert_type; }

	this(Alert.Type type, in string err_msg = "Unknown error") {
		alert_type = type;
		super(err_msg);
	}

private:
	Alert.Type alert_type;
}

/**
* Unexpected_Message Exception
*/
class Unexpected_Message : TLS_Exception
{
	this(in string err) 
	{
		super(Alert.UNEXPECTED_MESSAGE, err);
	}
}