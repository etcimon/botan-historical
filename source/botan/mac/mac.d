/*
* Message Authentication Code base class
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

import botan.mac;
import botan.mem_ops;
/*
* Default (deterministic) MAC verification operation
*/
bool MessageAuthenticationCode::verify_mac(in byte* mac, size_t length)
{
	SafeVector!byte our_mac = flush();

	if (our_mac.size() != length)
		return false;

	return same_mem(&our_mac[0], &mac[0], length);
}

}
