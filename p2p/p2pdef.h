#pragma once

#ifndef MAX_PEERLIST_ENTRIES
#define MAX_PEERLIST_ENTRIES 2500
#endif

#include <Rpc.h>
namespace defs {
	enum connection_types {
		in,
		out,
		both
	};

	enum operation_types :BYTE {
		e_check_peer = 1, //the remote peer is checking to make sure we're a valid peer.
		e_establish_session, //the remote peer wants to establish a session with us.
		e_obtain_peerlist //the remote peer wants to obtain our peer list.
	};

	enum establish_connection_response:BYTE {
		e_success,
		e_already_connected,
		e_toomany_sessions
	};
}


#pragma pack(push, 1)
//this is stored (packed) in the vfs.
struct sPeerDBEntry {
	//char host[NI_MAXHOST]; //we use id<std::wstring> as host.
	WORD wPort;
	DWORD dwSessions; //number of sessions we've established with this ip.
	FILETIME first_connect, last_connect;//GetSystemTimeAsFileTime();
};
#pragma pack(pop)

struct sPeer {
	std::string ip;
	WORD wPort;
};

struct sPeerConnectMsg {
	defs::operation_types connect_type; //1 = verify connection, 2 = establish new session.
	DWORD dwNetworkID; //we check this to make sure we the right network(we might have multiple networks).
	WORD wPort;
	UUID identifier; //this is used to uniquely identify the peer. It's also checked to ensure we don't connect to ourself.
};

struct sPeerListQueryHdr {
	int id;
};

struct sPeerListQueryReq {
	sPeerListQueryReq(int id) {
		this->id = id;
		this->bFulfilled = false;
	};
	sPeerListQueryReq(sPeerListQueryReq&& other) {
		this->id = other.id;
		this->bFulfilled = other.bFulfilled;
		this->results = std::move(other.results);
	};
	int id;
	bool bFulfilled;
	std::mutex m;
	std::condition_variable cv;
	std::list<sPeer> results;
};
