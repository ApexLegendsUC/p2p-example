#define WIN32_LEAN_AND_MEAN
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <wincrypt.h>
#include <Windows.h>
#include <vector>
#include <crypto.h>
#include <map>
#include <mutex>
#include <memory>
#include <sockets/tcp/sync/socket.h>
#include <functional>
#include <chrono>
#include <list>
#include <future>
#include <sockets/tcp/async/socket.h>
#include <vfs.h>
#include <tools/string.h>
#include <memorywriter.h>
#include <thread>
#include <utility>
#include <chrono>

#include <iostream>
using namespace std;

#include "p2pdef.h"
#include "peer.h"
#include "p2p.h"

#ifdef _DEUBG
void debug_msg(const std::string& msg);
#endif

network::p2p::peer_base::peer_base(sockets::tcp::async::io_service & io, SOCKET sSocket, defs::connection_types conn_type):socket(io, sSocket)
{
	this->conn_type = conn_type;
	remote_cfg.bFirewalled = conn_type == defs::in;
	remote_cfg.listening_port = NULL;
}

network::p2p::peer_base::peer_base(sockets::tcp::async::io_service & io, peer_base && other, defs::connection_types conn_type) : socket(io, std::move(other))
{
	this->remote_cfg = other.remote_cfg;
	this->conn_type = conn_type;
}

network::p2p::peer::peer(sockets::tcp::async::io_service & io, temp_peer && other, ::p2p & p2p):peer_base(io, std::move(other), other.connection_type()), network_mgr(p2p)
{
	this->nPeerListReqID = NULL;
	
	this->on("disconnected", [this](const std::vector<BYTE>&) {
		std::lock_guard<std::recursive_mutex> lock(m_peer_list_queries);
		for (auto& req : peer_list_queries)
			req.cv.notify_all();
	});
}

network::p2p::peer::~peer()
{
	//debug_msg("network::p2p::peer::~peer()");
	network_mgr.on_established_peer_disconnect(this);
}

//taken from: https://stackoverflow.com/a/35959376
template <typename Cnt, typename _Pr = std::equal_to<typename Cnt::value_type>>
void remove_duplicates(Cnt& cnt, _Pr cmp = _Pr())
{
	Cnt result;
	//result.reserve(std::size(cnt));  // or cnt.size() if compiler doesn't support std::size()

	std::copy_if(
		std::make_move_iterator(std::begin(cnt))
		, std::make_move_iterator(std::end(cnt))
		, std::back_inserter(result)
		, [&](const typename Cnt::value_type& what)
	{
		return std::find_if(
			std::begin(result)
			, std::end(result)
			, [&](const typename Cnt::value_type& existing) { return cmp(what, existing); }
		) == std::end(result);
	}
	);  // copy_if

	cnt = std::move(result);  // place result in cnt param
}   // remove_duplicates

void remove_bad_peers(std::list<sPeer>& list)
{
	//we don't allow hostnames, because someone could just register a bunch of hostnames to bypass the one connection attempt per ip(list).
	const std::string valid = "0123456789.";
	list.remove_if([&valid](const sPeer& peer) {
		return peer.ip.find_first_not_of(valid) != std::string::npos;
	});
	//warning: IPv6 not supported due to above^

	//to-do: block private ip addresses ( https://en.wikipedia.org/wiki/Private_network#Private_IPv4_addresses ) && localhost -> https://en.wikipedia.org/wiki/Localhost
}

void validate_peer_list(std::list<sPeer>& list)
{
	if (list.empty())
		return;
	//remove duplicates
	/*
	list.remove_if([&](const sPeer& p) {
	return std::find_if(list.begin(), list.end(), [&](const sPeer& p2) {
	return (p.ip == p2.ip) && (&p != &p2);
	}) != list.end();
	});
	*/

	//decided to use a less hacky solution:
	remove_duplicates(list, [](const sPeer& a, const sPeer& b) {
#ifdef DEBUGGING
		return a.ip == b.ip && a.wPort == b.wPort;
#else
		return a.ip == b.ip;
#endif
	});

	if (list.size() > MAX_PEERLIST_ENTRIES)
		list.resize(MAX_PEERLIST_ENTRIES); //resize to maximum allowed entries.

	remove_bad_peers(list);
}

std::list<sPeer> network::p2p::peer::query_peers(std::chrono::milliseconds timeout)
{
	if (!this->connected())
		return std::list<sPeer>();
	std::unique_lock<std::recursive_mutex> lock(m_peer_list_queries);
	auto id = ++nPeerListReqID;
	auto it = peer_list_queries.insert(peer_list_queries.end(), sPeerListQueryReq(id));
	{
		sPeerListQueryHdr hdr{ nPeerListReqID };
		MemoryWriter writer;
		writer.write(&hdr, sizeof(hdr));
		this->write("query_peer_list_req", writer.get_data());
	}
	lock.unlock();
	std::list<sPeer> results;
	{
		std::unique_lock<std::mutex> cv_lock(it->m);
		if (it->cv.wait_until(cv_lock, std::chrono::steady_clock::now() + timeout, [this, &it]() { return it->bFulfilled || this->disconnected(); }))
			results = std::move(it->results);
	}
	lock.lock();
	peer_list_queries.erase(it);
	validate_peer_list(results);
	return results;
}

network::p2p::async_peerlist_req network::p2p::peer::async_query_peers(std::chrono::milliseconds timeout)
{
	std::lock_guard<std::recursive_mutex> lock(m_peer_list_queries);
	auto id = ++nPeerListReqID;
	auto it = peer_list_queries.insert(peer_list_queries.end(), sPeerListQueryReq(id));
	{
		sPeerListQueryHdr hdr{ nPeerListReqID };
		MemoryWriter writer;
		writer.write(&hdr, sizeof(hdr));
		this->write("query_peer_list_req", writer.get_data());
	}
	return async_peerlist_req(*this, it, std::chrono::steady_clock::now() + timeout);
}

//extern bool bMain;

network::p2p::temp_peer::~temp_peer()
{
	/*
	if (bMain) {
		char buf[64];
		sprintf_s(buf, "going to throw, pid=%d", GetCurrentProcessId());
		MessageBoxA(0, buf, "going to throw", 0);
		__debugbreak();
	}*/
	
	//debug_msg("~temp_peer");
	connector.cancel();
	connector.wait();
}

network::p2p::async_peerlist_req::async_peerlist_req(peer & _peer, std::list<sPeerListQueryReq>::iterator req, std::chrono::steady_clock::time_point timeout):_peer(_peer)
{
	this->timeout = timeout;
	this->req = req;
}

network::p2p::async_peerlist_req::async_peerlist_req(async_peerlist_req && other):_peer(other._peer)
{
	this->timeout = other.timeout;
	std::lock_guard<recursive_mutex> lock(_peer.m_peer_list_queries);
	this->req = other.req;
	other.req = _peer.peer_list_queries.end();
}

network::p2p::async_peerlist_req::~async_peerlist_req()
{
	std::lock_guard<recursive_mutex> lock(_peer.m_peer_list_queries);
	if (req != _peer.peer_list_queries.end())
		_peer.peer_list_queries.erase(req);
}

void network::p2p::async_peerlist_req::wait()
{
	std::unique_lock<mutex> lck(req->m);
	if (req->cv.wait_until(lck, timeout, [this]() { return req->bFulfilled || _peer.disconnected(); }))
		return;
}

std::list<sPeer> network::p2p::async_peerlist_req::get(bool bValidatePeerList)
{
	{
		std::lock_guard<recursive_mutex> lock(_peer.m_peer_list_queries);
		if (req == _peer.peer_list_queries.end())
			return std::list<sPeer>();
	}
	std::unique_lock<std::mutex> cv_lock(req->m);
	std::list<sPeer> results;
	if (req->cv.wait_until(cv_lock, timeout, [this]() { return req->bFulfilled || _peer.disconnected(); }))
		results = std::move(req->results);
	if (bValidatePeerList) //we might not want to validate the peerlist if we're going to just pool them together(we'll just check it when they're all pooled together).
		validate_peer_list(results);
	return results;
}