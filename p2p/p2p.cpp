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
#include <memorywriter.h>
#include <thread>
#include <iostream>
#include <string>
using namespace std;
#include "p2pdef.h"
#include "p2p.h"
#include "peer.h"

#ifndef _DEBUG
#include "miniupnpc.h"
#include "upnpcommands.h"
#endif

#pragma comment(lib, "Rpcrt4.lib")
//#pragma comment(lib, "miniupnpc.lib")

#define P2P_WATCHDOG_SLEEPTIME_SEC 30
#define P2P_MINIMUM_OUTGOING_CONNECTIONS 15

#define _SECOND ((uint64_t) 10000000)
#define _MINUTE (60 * _SECOND)
#define _HOUR   (60 * _MINUTE)
#define _DAY    (24 * _HOUR)

using namespace std::chrono_literals;

#ifdef _DEBUG
#pragma message( "Warning: Debug mode is not appropriate for production builds." )
//for debugging purposes, certain security checks are modified to work locally. 
//For example, when establishing 25 connections, in debug mode it includes port # in the already tried list.
//But in production it just checks ip. This allows ez debugging locally, but is very insecure in a production build
//as an attacker could just have them connect to the same ip, but different ports, thus bypassing the debug check.
#endif

#ifdef DEBUGGING

void debug_msg(const std::string& msg)
{
	static std::mutex m;
	std::lock_guard<std::mutex> lock(m);
	cout << msg << endl;
}

#endif

std::vector<BYTE> serialize_peerlist_to_vector(const std::list<sPeer>& peerlist)
{
	MemoryWriter writer;
	for (auto& peer : peerlist) {
		auto size = static_cast<BYTE>(peer.ip.length());
		writer.write(&size, sizeof(size));
		writer.write(peer.ip.data(), peer.ip.length()); //could also convert it to binary from using inet_pton - https://msdn.microsoft.com/en-us/library/windows/desktop/cc805844(v=vs.85).aspx , but i'm too lazy as it would require obtaining the family, and storing an identifier for the family type.
		writer.write(&peer.wPort, sizeof(WORD));
	}
	return writer.get_data();
}

std::list<sPeer> unserialize_vector_to_peerlist(const std::vector<BYTE>& data)
{
	std::list<sPeer> results;
	size_t data_size = data.size(), pos = 0;
	while (data_size) {
		if (data_size < sizeof(BYTE))
			return std::list<sPeer>(); //incorrectly formatted peer list, maybe a new version or an exploit attempt.
		auto len = *PBYTE(&data[pos]);
		data_size -= sizeof(BYTE);
		pos += sizeof(BYTE);
		if (data_size < len)
			break;
		std::string host((const char*)&data[pos], len);
		pos += len;
		data_size -= len;
		if (data_size < sizeof(WORD))
			break;
		WORD wPort = *reinterpret_cast<const WORD*>(&data[pos]);
		pos += sizeof(WORD);
		data_size -= sizeof(WORD);
		results.push_back({ std::move(host), wPort });
	}
	return results;
}

bool is_equal_uuid(const UUID* a, const UUID* b)
{
	RPC_STATUS status;
	return (UuidEqual(const_cast<UUID*>(a), const_cast<UUID*>(b), &status) == TRUE);
}


#define DEFAULT_PEERLIST_ENCKEY_LEN 60
#define DEFAULT_MAX_LISTENING_ATTEMPTS 12

p2p::p2p(const std::wstring & directory, DWORD dwNetworkID):path(directory)
{
	::CreateDirectory(directory.c_str(), nullptr);
	this->cfg.dwNetworkID = dwNetworkID;
	this->cfg.wPort = NULL;
	this->cfg.hWatchDogThrd = INVALID_HANDLE_VALUE;
	this->cfg.bQuit = false;

	if (!fs.settings.open(path + L"p2p.vfs"))
		throw std::exception("Unable to open p2p config vfs.");

	if (fs.settings.find(vfs::id(L"port")) != fs.settings.end()) {
		auto port = fs.settings.read(L"port");
		if (port.size() != sizeof(WORD))
			fs.settings.remove(vfs::id(L"port"));
		else
			this->cfg.wPort = *PWORD(port.data());
	}

	std::vector<BYTE> peerlist_enc_key;

	if (fs.settings.find(vfs::id(L"peerlist_enc_key")) != fs.settings.end()) {
		peerlist_enc_key = fs.settings.read(L"peerlist_enc_key");
	}
	else {
		Crypto::Random r;
		peerlist_enc_key.resize(DEFAULT_PEERLIST_ENCKEY_LEN);
		if (!r.Generate(&peerlist_enc_key[0], DEFAULT_PEERLIST_ENCKEY_LEN))
			throw std::exception("Unable to generate peerlist enc key");
		fs.settings.write(L"peerlist_enc_key", peerlist_enc_key);
	}

	Crypto::AES aes;
	if (!aes.derive_key(Crypto::AES::aes_192, peerlist_enc_key))
		throw std::exception("Unable to derive key");
	fs.peerlist.set(std::move(aes));

	if (!fs.peerlist.open(path + L"peers.vfs"))
		throw std::exception("Unable to open peerlist vfs.");

	auto ret = UuidCreate(&cfg.identifier);
	if (ret != RPC_S_OK && ret != RPC_S_UUID_LOCAL_ONLY)
		throw std::exception("Unable to generate unique identifier.");

	network_encryption.cc.acquire(PROV_RSA_AES);
	network_encryption.aes = Crypto::AES(network_encryption.cc);
	network_encryption.rsa = Crypto::RSA(network_encryption.cc);
	//we use weak encryption because the purpose is just to hide the traffic from static network analysis.
	//secure: aes_256
	if (!network_encryption.aes.generate_key(Crypto::AES::aes_128))
		throw std::exception("Unable to generate encryption key.");
	//secure: rsa_4096
	if (!network_encryption.rsa.generate(Crypto::RSA::Methods::encryption, Crypto::RSA::Algorithms::rsa_1024, CRYPT_EXPORTABLE))
		throw std::exception("Unable to generate transport key."); //this key is used to encrypt the remote symmetric(encryption) key which both sides will use later on.
	
	peers.pending.throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_both, 100 * 1024); //100 KB/s rd/wr(max)
	peers.established.throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_rd, 1 * 1024 * 1024); // 1 MB/s rd
	peers.established.throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_wr, 500 * 1024); // 500 KB/s wr
}

p2p::~p2p()
{
	this->quit();
}

void p2p::set_bootstrap_list(const std::list<sPeer>& peerlist)
{
	cfg.bootstrap_list = peerlist;
}


void p2p::set_on_create_established_session_callback(std::function<std::shared_ptr<network::p2p::peer>(sockets::tcp::async::io_service&io, network::p2p::temp_peer& temp, p2p &p2p)> cb)
{
	callbacks.on_create_session = cb;
}

void p2p::set_on_established_session_callback(std::function<void(const std::shared_ptr<network::p2p::peer>&)> cb)
{
	callbacks.on_established_session_cb = cb;
}

void p2p::quit()
{
	cfg.bQuit = true;

	if (cfg.hWatchDogThrd != INVALID_HANDLE_VALUE) {
		::WaitForSingleObject(cfg.hWatchDogThrd, INFINITE);
		::CloseHandle(cfg.hWatchDogThrd);
		cfg.hWatchDogThrd = INVALID_HANDLE_VALUE;
	}

	peers.pending.clean_shutdown();
	peers.established.clean_shutdown();

}

void p2p::set_max_buffer_size(size_t n)
{
	peers.established.set_max_buffer_size(n);
}

void p2p::set_established_global_bandwidth_cap(sockets::tcp::async::io_cap io_cap, ULONGLONG max_bps)
{
	peers.established.throttle_bandwidth(io_cap, max_bps);
}

size_t p2p::current_network_io(sockets::tcp::async::io_cap io_type)
{
	return peers.pending.current_transfer_rate_bps(io_type) + peers.established.current_transfer_rate_bps(io_type);
}

size_t p2p::current_established_network_io(sockets::tcp::async::io_cap io_type)
{
	return peers.established.current_transfer_rate_bps(io_type);
}

size_t p2p::current_pending_network_io(sockets::tcp::async::io_cap io_type)
{
	return peers.pending.current_transfer_rate_bps(io_type);
}

//basically the two below are just wrappers for io_service's broadcast.
void p2p::broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::shared_ptr<sockets::tcp::async::socket>& exclude)
{
	peers.established.broadcast(name, buffer, exclude);
}

void p2p::broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::list<std::shared_ptr<sockets::tcp::async::socket>>& excluded)
{
	peers.established.broadcast(name, buffer, excluded);
}


bool p2p::initiate(WORD wDefaultPort, bool generate_port_if_taken, bool fail_if_unable_to_listen,  const sockets::tcp::async::listener_flags lf)
{
	WORD port = this->cfg.wPort ? this->cfg.wPort : wDefaultPort;

	for (int i = 0; i < DEFAULT_MAX_LISTENING_ATTEMPTS; i++) {
		if (port == NULL) {
			port = ((GetTickCount64() % 65536) + 1337) % 65536;
			if (port < 1337)
				port += 1337;
		}

		if (listener.listen(port, lf)) {
			cfg.wPort = port;
			break;
		}
		port = NULL;
		if (!generate_port_if_taken)
			return false;
	}

	if (fail_if_unable_to_listen) {
		if (listener.disconnected())
			return false;
	}
	if (listener.disconnected())
		cfg.wPort = NULL;
	else {
		MemoryWriter writer;
		writer.write(&cfg.wPort, sizeof(WORD));
		fs.settings.write_or_update(L"port", writer.get_data());
	}

	listener.accept([this](SOCKET sSocket) {
		if (sSocket == INVALID_SOCKET) {
			//cout << "invalid socket accepted()" << endl;
			return;
		}
		if (peers.pending.size() + peers.established.size() >= cfg.max_allowed_combined_peers ||
			peers.pending.size() >= cfg.max_allowed_pending) {
			::closesocket(sSocket);
			return;
		}
		

		auto client = std::make_shared<network::p2p::temp_peer>(this->peers.pending, sSocket, defs::connection_types::in);
		std::lock(this->peers.pending.sockets_mutex(), this->peers.established.sockets_mutex());
		std::lock_guard<std::recursive_mutex> lk1(this->peers.pending.sockets_mutex(), std::adopt_lock);
		std::lock_guard<std::recursive_mutex> lk2(this->peers.established.sockets_mutex(), std::adopt_lock);
		if (ipcount_pending(client->ip()) >= 2 || ipcount_established(client->ip()) > 0) { //we allow 2 pending, but only if the ip has no established sessions.
#ifdef DEBUGGING
			debug_msg("ipcount check failed for peer: " + client->ip());
#else
			return;
#endif
		}
		
		client->set_deadline(std::chrono::minutes(2));
		client->throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_both, 10 * 1024); //10 KB/s cap
		this->setup_accepted_temporary_peer_callbacks(client);
		this->peers.pending.push(client);
	});

	cfg.hWatchDogThrd = ::CreateThread(nullptr, 1024 * 1024 * 10 /*10 MiB*/, (LPTHREAD_START_ROUTINE)&p2p::static_watchdog, this, NULL, nullptr);
	if (cfg.hWatchDogThrd == INVALID_HANDLE_VALUE)
		throw std::exception("Unable to start watchdog thread");
	return true;
}

#pragma region counters

size_t p2p::ipcount_pending(const std::string & ip) const
{
	auto lock = peers.pending.acquire_sockets_lock();
	size_t n = 0;
	std::for_each(peers.pending.begin(), peers.pending.end(), [&n, &ip](const std::shared_ptr<sockets::tcp::async::socket>& p) {
		auto peer = std::dynamic_pointer_cast<network::p2p::temp_peer>(p);
		if (p->connected() && peer->ip() == ip)
			n++;
	});
	return n;
}

size_t p2p::established_worker_count() const
{
	auto lock = peers.established.acquire_sockets_lock();
	size_t n = 0;
	std::for_each(peers.established.begin(), peers.established.end(), [&n](const std::shared_ptr<sockets::tcp::async::socket>& p) {
		auto peer = std::dynamic_pointer_cast<network::p2p::peer>(p);
		if (p->connected() && peer->firewalled())
			n++;
	});
	return n;
}


size_t p2p::ipcount_established(const std::string & ip) const
{
	auto lock = peers.established.acquire_sockets_lock();
	size_t n = 0;
	std::for_each(peers.established.begin(), peers.established.end(), [&n, &ip](const std::shared_ptr<sockets::tcp::async::socket>& p) {
		auto peer = std::dynamic_pointer_cast<network::p2p::peer>(p);
		if (p->connected() && peer->ip() == ip)
			n++;
	});
	return n;
}

size_t p2p::established_connections_count(defs::connection_types type) const
{
	auto lock = peers.established.acquire_sockets_lock();
	size_t n = 0;
	for (const auto& p : peers.established) {
		if (!p->connected())
			continue;
		auto peer = std::dynamic_pointer_cast<network::p2p::peer_base>(p);
		if (type == defs::both)
			n++;
		else {
			if (peer->connection_type() == type)
				n++;
		}
	}
	return n;
}

size_t p2p::temporary_connections_count(defs::connection_types type) const
{
	auto lock = peers.pending.acquire_sockets_lock();
	size_t n = 0;
	for (const auto& p : peers.pending) {
		if (!p->connected())
			continue;
		auto peer = std::dynamic_pointer_cast<network::p2p::peer_base>(p);
		if (type == defs::both)
			n++;
		else {
			if (peer->connection_type() == type)
				n++;
		}
	}
	return n;
}

#pragma endregion


void p2p::on_established_peer_disconnect(network::p2p::peer * peer)
{
#ifdef DEBUGGING
	debug_msg("established peer disconnected = " + peer->ip() + ":" + std::to_string(peer->remote_port()));
#endif

	if (peer->firewalled())
		return;
#ifdef _DEBUG
	this->create_or_update_peerlist_entry(peer->ip(), peer->remote_port(), [this, peer](sPeerDBEntry* entry) -> bool {
#else
	this->create_or_update_peerlist_entry(peer->ip(), [this, peer](sPeerDBEntry* entry) -> bool {
#endif
		entry->wPort = peer->remote_port();
		GetSystemTimeAsFileTime(&entry->last_connect);
		return true;
	});
}

void p2p::setup_accepted_temporary_peer_callbacks(const std::shared_ptr<network::p2p::temp_peer>& client)
{
	client->on("configure", [this, socket = client.get()](const std::vector<BYTE>& data) {
		if (data.size() < sizeof(sPeerConnectMsg) || socket->state++ != 0) {
#ifdef DEBUGGING
			debug_msg("Protocol Mismatch Error #1 for peer: " + socket->ip());
#endif
			socket->disconnect();
			return;
		}
		auto connect_msg = reinterpret_cast<const sPeerConnectMsg*>(data.data());
		if (this->cfg.dwNetworkID != connect_msg->dwNetworkID) {
#ifdef DEBUGGING
			debug_msg("p2p network id mismatch for peer: " + socket->ip());
#endif
			socket->disconnect();
			return;
		}

		if (is_equal_uuid(&cfg.identifier, const_cast<UUID*>(&connect_msg->identifier))) {
#ifdef DEBUGGING
			debug_msg("self connect blocked for peer: " + socket->ip() + ":" + std::to_string(socket->remote_port()));
#endif
			socket->disconnect();
			return;
		}
		
		switch (connect_msg->connect_type) {
		case defs::operation_types::e_check_peer:
		{
			socket->write("hello", std::vector<BYTE>(), [socket](bool) {
				socket->disconnect();
			});
		}
		break;
		case defs::operation_types::e_establish_session:
		{
			socket->remote_cfg.id = connect_msg->identifier;
			socket->remote_cfg.listening_port = connect_msg->wPort;
			
			{
				std::lock_guard<std::recursive_mutex> lock(this->pending_establishment_connections.m);

#define pec_list this->pending_establishment_connections.my_list //pending establishment list

				if (this->peers.established.size() + pec_list.size() >= cfg.max_allowed_sessions) {
#ifdef DEBUGGING
					debug_msg("too many clients, connection denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->socket::remote_port()));
#endif
					socket->write("establish", std::vector<BYTE>(1, defs::establish_connection_response::e_toomany_sessions), [socket](bool bSuccess) {
						socket->disconnect();
					});
					return;
				}

				if (this->find_established_peer_by_uuid(connect_msg->identifier)) {
#ifdef DEBUGGING
					debug_msg("peer already connected, connection denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->socket::remote_port()));
#endif
					socket->write("establish", std::vector<BYTE>(1, defs::establish_connection_response::e_already_connected), [socket](bool bSuccess) {
						socket->disconnect();
					});
					return;
				}

				if (std::find_if(pec_list.begin(), pec_list.end(), [my_id = socket->remote_cfg.id](const UUID& id) -> bool { return is_equal_uuid(&id, &my_id);  }) != pec_list.end()) {
#ifdef DEBUGGING
					debug_msg("peer is already attempting to establish a connection, thus the connection was denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->socket::remote_port()));
#endif
					socket->write("establish", std::vector<BYTE>(1, defs::establish_connection_response::e_already_connected), [socket](bool bSuccess) {
						socket->disconnect();
					});
					return;
				}
				socket->wrap_conn_est = std::make_unique<p2p_establish_connection_wrapper>(*this, connect_msg->identifier);
			}
		

			if (this->established_worker_count() > this->cfg.max_allowed_workers) {
				if (connect_msg->wPort != NULL) {
					socket->connector.connect(socket->ip(), connect_msg->wPort, std::chrono::seconds(20), [socket, this](SOCKET s) {
						socket->remote_cfg.bFirewalled = s == INVALID_SOCKET;
						if (s != INVALID_SOCKET)
							::closesocket(s);
						std::vector<BYTE> response;
						response.push_back(socket->remote_cfg.bFirewalled ? defs::establish_connection_response::e_toomany_sessions : defs::establish_connection_response::e_success);
						MemoryWriter w;
						w.write(&this->cfg.identifier, sizeof(this->cfg.identifier));
						response.insert(response.end(), w.get_data().begin(), w.get_data().end());
						socket->write("establish", response, [socket, firewalled = socket->remote_cfg.bFirewalled](bool bSuccess) {
							if (firewalled || !bSuccess)
								socket->disconnect();
							else
								socket->bEstablishSession = true;
						});
					});
				}
				else {
					socket->write("establish", std::vector<BYTE>(1, defs::establish_connection_response::e_toomany_sessions), [socket](bool bSuccess) {
						socket->disconnect();
					});
				}

			}
			else {
				
				if (connect_msg->wPort != NULL) {
					socket->connector.connect(socket->ip(), connect_msg->wPort, std::chrono::seconds(20), [socket](SOCKET s) {
						socket->remote_cfg.bFirewalled = s == INVALID_SOCKET;
						if (s != INVALID_SOCKET)
							::closesocket(s);
					});
				}
				socket->bEstablishSession = true;
				std::vector<BYTE> response;
				response.push_back(defs::establish_connection_response::e_success);
				MemoryWriter w;
				w.write(&this->cfg.identifier, sizeof(UUID));
				response.insert(response.end(), w.get_data().begin(), w.get_data().end());
				socket->write("establish", response);
			}

			if (socket->bEstablishSession)
				socket->throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_both, 20 * 1024); //give it more leeway since it's going to establish a connection.
		}
		break;
		case defs::operation_types::e_obtain_peerlist:
		{
			//this is pretty resource intensive, so we should probably limit it.
			//to-do: add a timeout of at least 1 minute per ip before they can request again
			socket->write("peer_list", serialize_peerlist_to_vector(get_current_peer_list()), [socket](bool) {
				socket->disconnect();
			});
		}
		break;
		default:
			socket->disconnect();
		}

	});

	client->on("disconnect_me", [socket = client.get()](const std::vector<BYTE>&) {
		socket->disconnect();
	});

	//the following only applies if the connection type is e_establish_session
	client->on("enc", [this, socket = client.get()](const std::vector<BYTE>& data) {
		//the only purpose to receive an "enc" message is to enable encryption on the socket.
		if (!socket->bEstablishSession || socket->state < 1) {
#ifdef DEBUGGING
			debug_msg("!socket->bEstablishSession || socket->state < 1");
#endif
			socket->disconnect();
			return;
		}
		switch (socket->state++) {
		case 1:
		{
			//encryption has not yet been enabled.
			//The remote host will precede to send us their public rsa encryption key.
			//which we will use to export our private global symmetric key and send to them(once successfully sent, encryption will be applied to the socket through the write callback).
			Crypto::RSA remote_public_key(this->network_encryption.cc);
			if (!remote_public_key.import_public_key(data)) {
#ifdef DEBUGGING
				debug_msg("failed to import remote public key for peer: " + socket->ip());
#endif
				socket->disconnect();
				return;
			}
			auto exported = this->network_encryption.aes.Export(remote_public_key.get());
			socket->write("enc", exported, [this, socket](bool bSuccess) {
				if (bSuccess)
					socket->set_encryption(this->network_encryption.aes);
			});
		}
		break;
		case 2:
		{
			//after the remote host procedes to enable encryption, they will send another enc message(this time encrypted) to verify the encryption was applied.
			//if successful, then the connection is considered established.
			if (!socket->encrypted()) {
				socket->disconnect();
				return;
			}
			socket->connector.wait();
			socket->write("established", std::vector<BYTE>(), [this, socket](bool bSuccess) {
				if (!bSuccess)
					return;
				socket->disable_io(sockets::tcp::async::block_io::_io_wr);

				std::shared_ptr<network::p2p::peer> established_client;

				if (callbacks.on_create_session != nullptr)
					established_client = callbacks.on_create_session(this->peers.established, *socket, *this);
				else
					established_client = std::make_shared<network::p2p::peer>(this->peers.established, std::move(*socket), *this);

				if (!established_client)
					return;

				this->setup_established_peer_callbacks(established_client);

				this->peers.established.push(established_client);
			});
		}
		break;
		}

	});
}

void p2p::setup_established_peer_callbacks(const std::shared_ptr<network::p2p::peer>& client)
{
#ifdef _DEBUG
	debug_msg("semi-completed connection from " + client->ip());
#endif
	client->throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_rd, 125 * 1024); //125 KB/s = default rd
	client->throttle_bandwidth(sockets::tcp::async::io_cap::cap_io_wr, 100 * 1024); //100 KB/s = default wr


	if (this->callbacks.on_established_session_cb)
		this->callbacks.on_established_session_cb(client);

	client->on("complete_connection", [socket = client.get()](const std::vector<BYTE>& data) {
#ifdef _DEBUG
		debug_msg("finally fully established connection from " + socket->ip());
#endif
		socket->enable_io(sockets::tcp::async::_io_wr);
	});

	if (!client->firewalled()) {
		//note: we only write the peer to the peer list AFTER we have established a valid session(otherwise an attacker could just send a list of ip:port that are reachable and fill up the peer list quite easily).
#ifdef _DEBUG
		this->create_or_update_peerlist_entry(client->ip(), client->remote_port(), [this, socket = client.get()](sPeerDBEntry* entry) -> bool{
#else
		this->create_or_update_peerlist_entry(client->ip(), [this, socket = client.get()](sPeerDBEntry* entry) -> bool{
#endif
			entry->wPort = socket->remote_port();
			entry->dwSessions++;
			GetSystemTimeAsFileTime(&entry->last_connect);
			auto first_connect = (((ULONGLONG)entry->first_connect.dwHighDateTime) << 32) + entry->first_connect.dwLowDateTime;
			auto last_connect = (((ULONGLONG)entry->last_connect.dwHighDateTime) << 32) + entry->last_connect.dwLowDateTime;
			if (first_connect == 0 || last_connect < first_connect) //if last connect < first connection then something is wrong, possibly a user has changed the system clock to an earlier date or the DB is corrupted.
				GetSystemTimeAsFileTime(&entry->first_connect);
			return true;
		});
	}

	client->on("query_peer_list_req", [socket = client.get(), this](const std::vector<BYTE>& buffer) {
		if (buffer.size() < sizeof(sPeerListQueryHdr))
			return;
		auto hdr = reinterpret_cast<const sPeerListQueryHdr*>(buffer.data());
		MemoryWriter writer;
		writer.write(hdr, sizeof(sPeerListQueryHdr));
		auto serialized_peerlist = serialize_peerlist_to_vector(get_current_peer_list());
		writer.write(serialized_peerlist.data(), serialized_peerlist.size()); //writer.get_data().insert(writer.get_data().end(), serialized_peerlist.begin(), serialized_peerlist.end());
		socket->write("query_peer_list_resp", writer.get_data());
	});

	client->on("query_peer_list_resp", [socket = client.get()](const std::vector<BYTE>& buffer) {
		if (buffer.size() < sizeof(sPeerListQueryHdr))
			return;
		auto hdr = reinterpret_cast<const sPeerListQueryHdr*>(buffer.data());
		auto queried_list = unserialize_vector_to_peerlist(std::vector<BYTE>(buffer.begin() + sizeof(sPeerListQueryHdr), buffer.end()));
		std::lock_guard<std::recursive_mutex> lock(socket->m_peer_list_queries);
		for (auto& req : socket->peer_list_queries) {
			if (req.id == hdr->id) {
				{
					std::lock_guard<std::mutex> lk(req.m);
					req.bFulfilled = true;
					req.results = std::move(queried_list);
				}
				req.cv.notify_all();
			}
		}

	});

}

void p2p::setup_connected_temporary_peer_callbacks(const std::shared_ptr<network::p2p::temp_peer>& client)
{
	//note: most of the callbacks are handled by the caller. The callee is just responsible for writing the msg to establish the session & setting up encryption.
	client->set_deadline(std::chrono::minutes(2));
	MemoryWriter writer;
	
	sPeerConnectMsg msg;
	this->setup_peerconnectmsg(&msg, defs::operation_types::e_establish_session);

	writer.write(&msg, sizeof(msg));
	client->write("configure", writer.get_data(), [socket = client.get()](bool) {
		socket->state++;
	});

	client->on("enc", [this, socket = client.get()](const std::vector<BYTE>& data) {
		
		if (socket->state++ != 2) {
#ifdef DEBUGGING
			debug_msg("enc - STATE MISMATCH for peer: " + socket->ip());
#endif
			socket->disconnect();
			return;
		}
		socket->encryption = Crypto::AES(this->network_encryption.cc);
		if (!socket->encryption.Import(this->network_encryption.rsa.get(), data)) {
#ifdef DEBUGGING
			debug_msg("Unable to import encryption key for peer: " + socket->ip());
#endif
			socket->disconnect();
			return;
		}
		socket->write("enc", std::vector<BYTE>(), [this, socket](bool bSuccess) {
			if (!bSuccess)
				return;
			std::lock(this->peers.pending.sockets_mutex(), this->peers.established.sockets_mutex());
			std::lock_guard<std::recursive_mutex> lk1(this->peers.pending.sockets_mutex(), std::adopt_lock);
			std::lock_guard<std::recursive_mutex> lk2(this->peers.established.sockets_mutex(), std::adopt_lock);

		});

	});

}


std::list<sPeer> p2p::get_current_peer_list()
{
	std::list<sPeer> peer_list;
	auto lock = peers.established.acquire_sockets_lock();
	//peers that we've connected to are given priority over the position in the peer list.
	for (auto& p : peers.established) {
		auto peer = std::dynamic_pointer_cast<network::p2p::peer>(p);
		if (!peer || peer->firewalled())
			continue;
		peer_list.push_back({ peer->ip(), peer->remote_port() });
	}
	lock.unlock();
	return peer_list;
}

void p2p::setup_peerconnectmsg(sPeerConnectMsg * msg, defs::operation_types op_type)
{
	msg->connect_type = op_type;
	msg->dwNetworkID = cfg.dwNetworkID;
	msg->wPort = cfg.wPort;
	msg->identifier = cfg.identifier;
}

#ifdef _DEBUG

bool p2p::create_or_update_peerlist_entry(const std::string & sIP, WORD wPort, const std::function<bool(sPeerDBEntry*entry)>& cb)
{
	std::wstring wIP(sIP.begin(), sIP.end());
	std::lock_guard<std::mutex> lock(this->fs.m_peerlist);
	for (auto it = fs.peerlist.begin(); it != fs.peerlist.end(); it++) {
		auto data = fs.peerlist.read(*it);
		if (data.size() == sizeof(sPeerDBEntry)) {
			if (reinterpret_cast<sPeerDBEntry*>(data.data())->wPort == wPort && it->get_id<std::wstring>() == wIP) {
				if (!cb(reinterpret_cast<sPeerDBEntry*>(data.data())))
					return false;
				return fs.peerlist.update(vfs::id(wIP), data);
			}
		}
		else //corrupted???
			fs.peerlist.remove(vfs::id(wIP));
	}

	std::vector<BYTE> data;
	data.resize(sizeof(sPeerDBEntry), NULL);
	if (!cb(reinterpret_cast<sPeerDBEntry*>(data.data())))
		return false;
	if (fs.peerlist.write(wIP, data) != fs.peerlist.end())
		return true;
	return false;
}
#else
bool p2p::create_or_update_peerlist_entry(const std::string & sIP, const std::function<bool(sPeerDBEntry*entry)>& cb)
{
	std::wstring wIP(sIP.begin(), sIP.end());
	std::lock_guard<std::mutex> lock(this->fs.m_peerlist);
	if (fs.peerlist.find(vfs::id(wIP)) != fs.peerlist.end()) { //update
		auto data = fs.peerlist.read(wIP);
		if (data.size() == sizeof(sPeerDBEntry)) {
			if (!cb(reinterpret_cast<sPeerDBEntry*>(data.data())))
				return false;
			return fs.peerlist.update(vfs::id(wIP), data);
		}
		else //corrupted???
			fs.peerlist.remove(vfs::id(wIP));
	}
	else { //write new
		std::vector<BYTE> data;
		data.resize(sizeof(sPeerDBEntry), NULL);
		if (!cb(reinterpret_cast<sPeerDBEntry*>(data.data())))
			return false;
		if (fs.peerlist.write(wIP, data) != fs.peerlist.end())
			return true;
	}
	return false;
}
#endif

std::shared_ptr<network::p2p::peer> p2p::find_established_peer_by_ip(const std::string & ip) const
{
	auto lock = peers.established.acquire_sockets_lock();
	auto it = std::find_if(peers.established.begin(), peers.established.end(), [&ip](const std::shared_ptr<sockets::tcp::async::socket>& p) {
		auto peer = std::dynamic_pointer_cast<network::p2p::peer>(p);
		return (peer->ip() == ip);
	});
	if (it != peers.established.end())
		return std::dynamic_pointer_cast<network::p2p::peer>(*it);
	else
		return std::shared_ptr<network::p2p::peer>();
}



std::shared_ptr<network::p2p::peer> p2p::find_established_peer_by_uuid(const UUID & id) const
{
	auto lock = peers.established.acquire_sockets_lock();
	auto it = std::find_if(peers.established.begin(), peers.established.end(), [&id](const std::shared_ptr<sockets::tcp::async::socket>& p) {
		auto peer = std::dynamic_pointer_cast<network::p2p::peer>(p);
		auto peer_uuid = peer->get_uuid();
		return is_equal_uuid(&peer_uuid, &id); //(peer->get_uuid() == id);
	});
	if (it != peers.established.end())
		return std::dynamic_pointer_cast<network::p2p::peer>(*it);
	else
		return std::shared_ptr<network::p2p::peer>();
}

struct sPeerListEntry {
	std::wstring id;
	std::string ip;
	WORD port;
};

void p2p::process_stored_peer_list()
{
	sockets::tcp::async::connector connector;
	std::list<std::shared_ptr<network::p2p::temp_peer>> connections;
	std::list<sPeerListEntry> cached_peers;

	{
		std::lock_guard<std::mutex> lock(fs.m_peerlist);
		for (auto& peer : fs.peerlist) {
			auto id = peer.get_id<std::wstring>();
			auto ip = std::string(id.begin(), id.end());
			auto data = fs.peerlist.read(peer);
			if (data.size() != sizeof(sPeerDBEntry))
				throw std::exception("invalid stored peerlist");
			auto peer_data = reinterpret_cast<sPeerDBEntry*>(&data[0]);
			//if we're already connected then no need to connect again to check if the peer is alive.
			if (find_established_peer_by_ip(ip)) {
				GetSystemTimeAsFileTime(&peer_data->last_connect);
				fs.peerlist.update(vfs::id(id), data);
				continue;
			}
			cached_peers.push_back(sPeerListEntry{ id, ip, peer_data->wPort });
		}

	}

	for (auto& cached_peer : cached_peers) {
		if (connector.size() >= 250)
			connector.wait();
		connector.connect(cached_peer.ip, cached_peer.port, 20s, [this, &cached_peer, &connections](SOCKET s) {
			if (s == INVALID_SOCKET)
				return;
			auto peer = std::make_shared<network::p2p::temp_peer>(this->peers.pending, s, defs::out);
			sPeerConnectMsg msg = {};
			this->setup_peerconnectmsg(&msg, defs::operation_types::e_check_peer);

			MemoryWriter writer;
			writer.write(&msg, sizeof(msg));
			peer->write("configure", writer.get_data());
			peer->set_deadline(1min);
			connections.push_back(peer);
			peer->on("hello", [this, ip = cached_peer.ip, port = cached_peer.port, socket = peer.get()](const std::vector<BYTE>&) {
#ifdef _DEBUG
				this->create_or_update_peerlist_entry(ip, port, [](sPeerDBEntry* entry) -> bool {
#else
				this->create_or_update_peerlist_entry(ip, [](sPeerDBEntry* entry) -> bool {
#endif
					GetSystemTimeAsFileTime(&entry->last_connect);
					return true;
				});
				socket->disconnect();
			});
			this->peers.pending.push(peer);
		});

	}

	connector.wait();

	for (auto& peer : connections) {
		while (peer->connected())
			std::this_thread::sleep_for(1ms);
	}
	connections.clear();

	//now we check the peer list and remove outdated and bad entries.
	std::lock_guard<std::mutex> lock(fs.m_peerlist);

	for (auto it = fs.peerlist.begin(); it != fs.peerlist.end();) {
		auto data = fs.peerlist.read(*it);
		if (data.size() < sizeof(sPeerDBEntry)) {
			it = fs.peerlist.erase(it);
			continue;
		}
		auto peer = reinterpret_cast<sPeerDBEntry*>(data.data());
		LARGE_INTEGER peer_last_connect;
		peer_last_connect.LowPart = peer->last_connect.dwLowDateTime;
		peer_last_connect.HighPart = peer->last_connect.dwHighDateTime;
		FILETIME ftnow;
		GetSystemTimeAsFileTime(&ftnow);
		LARGE_INTEGER now;
		now.HighPart = ftnow.dwHighDateTime;
		now.LowPart = ftnow.dwLowDateTime;
		//A file time is a 64-bit value that represents the number of 100-nanosecond intervals that have elapsed since 12:00 A.M. January 1, 1601 Coordinated Universal Time (UTC)
		//#https://msdn.microsoft.com/en-us/library/windows/desktop/dn553408(v=vs.85).aspx

		if (peer_last_connect.QuadPart > now.QuadPart || now.QuadPart - peer_last_connect.QuadPart > 2 * 7 * _DAY) { //if they've changed the clock to the past || (2 * 7 * 60 * 60 * 24) * 10000000ull haven't connected in 2 weeks
			it = fs.peerlist.erase(it);
			continue;
		}
		++it;
	}

}

size_t get_rep(const sPeerDBEntry& entry)
{
	//(days * 5(adjustment factor)) / connections
	//first caculate the number of days the peer has been connective for.
	auto f1 = ((ULONGLONG)entry.first_connect.dwHighDateTime << 32) + entry.first_connect.dwLowDateTime;
	auto f2 = ((ULONGLONG)entry.last_connect.dwHighDateTime << 32) + entry.last_connect.dwLowDateTime;
	auto days = (f2 - f1 / _DAY);
	return days; //(days * 5) / entry.dwSessions;
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

std::list<sPeer> p2p::get_default_peerlist()
{
	using pair = std::pair<std::string, sPeerDBEntry>;
	std::list<pair> list;
	{
		std::lock_guard<std::mutex> lock(fs.m_peerlist);
		for (auto& peer : fs.peerlist) {
			auto id = peer.get_id<std::wstring>();
			auto ip = std::string(id.begin(), id.end());
			auto rd = fs.peerlist.read(peer);
			sPeerDBEntry* peer_data = reinterpret_cast<sPeerDBEntry*>(rd.data());
			list.emplace_back(pair(ip, *peer_data));
		}
	}

	//http://en.cppreference.com/w/cpp/container/list/sort
	//"comparison function object (i.e. an object that satisfies the requirements of Compare) which returns true if the first argument is less than (i.e. is ordered before) the second. "

	list.sort([](const pair& a, const pair& b) {
		ULARGE_INTEGER u1, u2;
		u1.LowPart = a.second.last_connect.dwLowDateTime;
		u1.HighPart = a.second.last_connect.dwHighDateTime;
		u2.LowPart = b.second.last_connect.dwLowDateTime;
		u2.HighPart = b.second.last_connect.dwHighDateTime;
		return u1.QuadPart > u2.QuadPart;
	});

	list.sort([](const pair& a, const pair& b) {
		//next sort based upon reputation
		return get_rep(a.second) > get_rep(b.second);
	});

	std::list<sPeer> sorted_peers;
	//insert bootstrap list first since they have the highest authority & should be attempted first no matter what.
	sorted_peers.insert(sorted_peers.end(), cfg.bootstrap_list.begin(), cfg.bootstrap_list.end());
	//then do the other peers
	for (auto& peer : list)
		sorted_peers.push_back({ peer.first, peer.second.wPort });
	
	//remove duplicates(in case there are some matches from the bootstrap list & peerlist on disk)
	remove_duplicates(sorted_peers, [](const sPeer& a, const sPeer& b) { return a.ip == b.ip && a.wPort == b.wPort; });

	return sorted_peers;
}

void p2p::scan_peerlist(const std::list<sPeer>& peer_list, int nDepth)
{
	#define info (&this->check_peers_extra_info)

	if (nDepth == 5000) {
#ifdef DEBUGGING
		debug_msg("scan_peerlist - max depth reached(5k).");
#endif
		return; //maximum depth reached.
	}

	if (peer_list.size() == 0 || cfg.bQuit)
		return; //nothing to check, might as well save some time

	int n = 0;
	sockets::tcp::async::connector connector;
	std::list<std::shared_ptr<network::p2p::temp_peer>> temp_connections;
	std::list<std::shared_ptr<network::p2p::peer>> valid;
	std::mutex m_full_valid_peers;
	std::list<sPeer> full_valid_peers; //peers that are valid, but have reached the maximum number of sessions.
	for (auto& peer : peer_list) {
		if (cfg.bQuit)
			return;

		if (n++ == P2P_MINIMUM_OUTGOING_CONNECTIONS * 2) {
			connector.wait(); //waits for all connection attempts to be finished.
			for (auto& p : temp_connections) {
				while (p->connected())
					std::this_thread::sleep_for(10ms);
				p->off(""); //ensure the callback has completed.
			}
			temp_connections.clear();
			n = 1;
		}

		if (this->established_connections_count(defs::connection_types::out) >= P2P_MINIMUM_OUTGOING_CONNECTIONS)
			return;

		//we use this to prevent connecting to peers we're already connected to or have already tried to connect to already.
		{
			std::lock_guard<std::mutex> lock(info->m);
#ifndef _DEBUG
			if (std::find(info->connected.begin(), info->connected.end(), peer.ip) != info->connected.end())
				continue;
#else
			if (std::find_if(info->connected.begin(), info->connected.end(), [&peer](const sPeer& p) {
				return p.ip == peer.ip && p.wPort == peer.wPort;
			}) != info->connected.end())
				continue; //we're already connected to this peer
#endif

			if (std::find_if(info->tried.begin(), info->tried.end(), [&peer](const sPeer& p) {
				return p.ip == peer.ip && p.wPort == peer.wPort;
			}) != info->tried.end())
				continue; //we've already tried to connect to the same ip:port.

			info->tried.push_back(peer);
		}

		connector.connect(peer.ip, peer.wPort, 20s, [this, peer, &full_valid_peers, &temp_connections, &valid, &m_full_valid_peers](SOCKET s) {
			if (s == INVALID_SOCKET) {
				//cout << "Failed to connect to " << peer.ip << ":" << (int)peer.wPort << endl;
				return;
			}

			//update the peerlist on the vfs to note that it's still "alive" regardless of whether or not we can establish a session.
#ifdef _DEBUG
			this->create_or_update_peerlist_entry(peer.ip, peer.wPort, [&peer](sPeerDBEntry* entry) -> bool {
#else
			this->create_or_update_peerlist_entry(peer.ip, [&peer](sPeerDBEntry* entry) -> bool {
#endif
				if (entry->dwSessions == 0) //check if it's not created(dwSessions == 0 is a poor way to check, should probably use first_connect).
					return false;
				entry->wPort = peer.wPort; //in case port was updated.
				GetSystemTimeAsFileTime(&entry->last_connect);
				return true;
			});

			auto client = std::make_shared<network::p2p::temp_peer>(this->peers.pending, s, defs::out);
			this->setup_connected_temporary_peer_callbacks(client);
			
			client->on("establish", [this, socket = client.get(), &full_valid_peers, &valid, &m_full_valid_peers](const std::vector<BYTE>& data) {
				if (data.size() < 1|| socket->state++ != 1) {
					//cout << "data size mismatched || state mismatch:" << data.size() << " || " << socket->state << endl;
#ifdef DEBUGGING
					debug_msg("data size or state mismatch. (ds: " + std::to_string(data.size()) + "), (ss: " + std::to_string(socket->state) + ") for peer: " + socket->ip());
#endif
					socket->disconnect();
					return;
				}

				if (data[0] == defs::establish_connection_response::e_toomany_sessions) { //peer has reached maximum sessions.
										//cout << "reached maximum sessions... :(" << endl;
#ifdef DEBUGGING
					debug_msg("unable to establish session, " + socket->ip() + " has reached maximum sessions.");
#endif
					std::lock_guard<std::mutex> lock(m_full_valid_peers);
					full_valid_peers.push_back({ socket->ip(), socket->remote_port() });
					socket->disconnect();
				}
				else if (data[0] == defs::establish_connection_response::e_success) {
					if (data.size() != 1 + sizeof(UUID)) {
#ifdef DEBUGGING
						debug_msg("data size or state mismatch(2). (ds: " + std::to_string(data.size()) + "), (ss: " + std::to_string(socket->state) + ") for peer: " + socket->ip());
#endif
						socket->disconnect();
						return;
					}
					
					socket->remote_cfg.id = *reinterpret_cast<const UUID*>(&data[1]);

					{
						std::lock_guard<std::recursive_mutex> lock(this->pending_establishment_connections.m);

#define pec_list this->pending_establishment_connections.my_list //pending establishment list
						
						if (this->peers.established.size() + pec_list.size() >= cfg.max_allowed_sessions) {
#ifdef DEBUGGING
							debug_msg("[OUT] too many clients, connection denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->remote_port()));
#endif
							socket->write("disconnect_me", std::vector<BYTE>(), [socket](bool bSuccess) {
								socket->disconnect();
							});
							return;
						}
						

						if (this->find_established_peer_by_uuid(socket->remote_cfg.id)) {
#ifdef DEBUGGING
							debug_msg("[OUT] peer already connected, connection denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->remote_port()));
#endif
							socket->write("disconnect_me", std::vector<BYTE>(), [socket](bool bSuccess) {
								socket->disconnect();
							});
							return;
						}

						if (std::find_if(pec_list.begin(), pec_list.end(), [my_id = socket->remote_cfg.id](const UUID& id) -> bool { return is_equal_uuid(&id, &my_id);  }) != pec_list.end()) {
#ifdef DEBUGGING
							debug_msg("[OUT] peer is already attempting to establish a connection, thus the connection was denied for temp peer: " + socket->ip() + ":" + std::to_string(socket->remote_port()));
#endif
							socket->write("disconnect_me", std::vector<BYTE>(), [socket](bool bSuccess) {
								socket->disconnect();
							});
							return;
						}

						socket->wrap_conn_est = std::make_unique<p2p_establish_connection_wrapper>(*this, socket->remote_cfg.id);
					}

					socket->write("enc", this->network_encryption.rsa.export_public_key());
				}
				else
					socket->disconnect(); //probably defs::establish_connection_response::e_alreadyconnected
			});

			client->on("established", [this, socket = client.get(), &valid](const std::vector<BYTE>&) {
				if (!socket->encrypted() || socket->state != 3) {
					//cout << "established state mismatched / encryption not enabled." << endl;
#ifdef DEBUGGING
					debug_msg("established state mismatched / encryption not enabled.");
#endif
					return;
				}
				//cout << "establishing new session (connected)!" << endl;
				{
					std::lock_guard<std::mutex> lock(info->m);
#ifndef _DEBUG
					info->connected.push_back(socket->ip());
#else
					info->connected.push_back({ socket->ip(), socket->remote_port() });
#endif
				}

				std::shared_ptr<network::p2p::peer> established_client;

				if (callbacks.on_create_session != nullptr)
					established_client = callbacks.on_create_session(this->peers.established, *socket, *this);
				else
					established_client = std::make_shared<network::p2p::peer>(this->peers.established, std::move(*socket), *this);

				if (!established_client)
					return;
				this->setup_established_peer_callbacks(established_client);
				established_client->write("complete_connection"); //the remote peer disabled socket i/o on the new io_handler to prevent a race condition in which the old io_handler handled i/o intended for the new socket(and completed reading an entire msg -> added the msg to the global completed i/o callbacks) -> causing the message to be missed. So out i/o gets temporarily disabled on the other side, and to re-enable it, we have to send this message.
				valid.push_back(established_client);
				this->peers.established.push(established_client);

				//cout << "established new session (connected)!" << endl;
			});
			
			temp_connections.push_back(client); //the async connector relies on only 1 thread, so no need for a mutex. + main thread only accesses temp peers after all connection attempts have finished.
			this->peers.pending.push(client);

		});

	}

	connector.wait();
	for (auto& p : temp_connections) {
		while (p->connected())
			std::this_thread::sleep_for(25ms);
		p->off(""); //just using this to verify the callback has completed.
	}
	temp_connections.clear();

	if (this->established_connections_count(defs::connection_types::out) < P2P_MINIMUM_OUTGOING_CONNECTIONS) {
		if (cfg.bQuit)
			return;
		//cout << "still < 25" << endl;
		//now check our freshly established peers for peer lists.
		/*for (auto& established_peer : valid) {
			if (this->established_connections_count(defs::connection_types::out) >= P2P_MINIMUM_OUTGOING_CONNECTIONS)
				return; //we've reached the optimal number of connections.
			this->scan_peerlist(established_peer->query_peers(25s), nDepth + 1);
		}
		*/

		//refactored (vastly improved) version
		std::list<network::p2p::async_peerlist_req> reqs;
		for (auto& socket : valid)
			reqs.push_back(socket->async_query_peers(30s));
		std::list<sPeer> results;
		for (auto& req : reqs) {
			auto list = req.get();
			results.insert(results.end(), list.begin(), list.end());
		}
		validate_peer_list(results);
		reqs.clear();
		valid.clear();
		scan_peerlist(results);
	}
	else
		return;

	if (this->established_connections_count(defs::connection_types::out) < P2P_MINIMUM_OUTGOING_CONNECTIONS) {
		//still? then check our fullhouse peers(peers that are valid, but can't accept anymore established connections)..
		for (auto& peer : full_valid_peers) {
			if (cfg.bQuit)
				return;
			if (this->established_connections_count(defs::connection_types::out) >= P2P_MINIMUM_OUTGOING_CONNECTIONS)
				break;
			SOCKET s;
			connector.connect(peer.ip, peer.wPort, 20s, [&s](SOCKET sSocket) { s = sSocket; });
			connector.wait();
			if (s == INVALID_SOCKET)
				continue;
			auto client = std::make_shared<network::p2p::temp_peer>(this->peers.pending, s, defs::out);
			client->set_deadline(std::chrono::seconds(30));
			MemoryWriter writer;
			sPeerConnectMsg msg;
			this->setup_peerconnectmsg(&msg, defs::operation_types::e_obtain_peerlist);
			writer.write(&msg, sizeof(msg));
			client->write("configure", writer.get_data());
			std::list<sPeer> results;
			client->on("peer_list", [socket = client.get(), &results](const std::vector<BYTE>& data) {
				results = unserialize_vector_to_peerlist(data);
				validate_peer_list(results);
				socket->disconnect();
			});
			peers.pending.push(client);
			while (!client->disconnected())
				Sleep(10);
			client->off(""); //ensure callback is completed.
			scan_peerlist(results, nDepth + 1);
		}
	}

}

void p2p::setup_prescan_prequisities()
{
	std::unique_lock<std::recursive_mutex> lk1(this->peers.pending.sockets_mutex(), std::defer_lock);
	std::unique_lock<std::recursive_mutex> lk2(this->peers.established.sockets_mutex(), std::defer_lock);
	std::lock(lk1, lk2);

	check_peers_extra_info.tried.clear();
	check_peers_extra_info.connected.clear();

#ifdef _DEBUG
	auto current_peerlist = get_current_peer_list();
	for (auto& peer : current_peerlist)
		check_peers_extra_info.connected.push_back({ peer.ip, peer.wPort });
	for (auto& peer : this->peers.pending) {
		auto p = std::dynamic_pointer_cast<network::p2p::peer_base>(peer);
		if (p)
			check_peers_extra_info.connected.push_back({ p->ip(), p->remote_port() });
	}
#else
	for (auto& peer : this->peers.established)
		check_peers_extra_info.connected.push_back(peer->ip());
	for (auto& peer : this->peers.pending)
		check_peers_extra_info.connected.push_back(peer->ip());
#endif


	lk1.unlock(); lk2.unlock();
}

#ifndef _DEBUG
bool port_forward(const std::string& port, const std::string& name)
{
	//(devlist = upnpDiscover(2000, multicastif, minissdpdpath, localport, ipv6, ttl, &error)))
	unsigned char ttl = 2;	/* defaulting to 2 */

	int error = 0;
	struct UPNPDev *upnp_dev = upnpDiscover(
		2000, // time to wait (milliseconds)
		nullptr, // multicast interface (or null defaults to 239.255.255.250)
		nullptr, // path to minissdpd socket (or null defaults to /var/run/minissdpd.sock)
		0, // source port to use (or zero defaults to port 1900)
		0, // 0==IPv4, 1==IPv6
		ttl,
		&error); // error condition

	if (!upnp_dev)
		return false;

	char lan_address[64];
	UPNPUrls upnp_urls {};
	IGDdatas upnp_data{};
	int status = UPNP_GetValidIGD(upnp_dev, &upnp_urls, &upnp_data, lan_address, sizeof(lan_address));
	if (status == 0) {
		freeUPNPDevlist(upnp_dev);
		return false;
	}

	// look up possible "status" values, the number "1" indicates a valid IGD was found
	//cout << "UPNP_GetValidIGD, status = " << status << endl;
	//cout << "lan = " << lan_address << endl;


	// get the external (WAN) IP address
	//char wan_address[64];
	//UPNP_GetExternalIPAddress(upnp_urls.controlURL, upnp_data.first.servicetype, wan_address);
	//cout << "WAN = " << wan_address << endl;

	// add a new TCP port mapping from WAN port 12345 to local host port 24680
	error = UPNP_AddPortMapping(
		upnp_urls.controlURL,
		upnp_data.first.servicetype,
		port.c_str(),  // external (WAN) port requested
		port.c_str(),  // internal (LAN) port to which packets will be redirected
		lan_address, // internal (LAN) address to which packets will be redirected
		name.c_str(), // text description to indicate why or who is responsible for the port mapping
		"TCP", // protocol must be either TCP or UDP
		nullptr, //remote host
		"86400");// port map lease duration (in seconds) or zero for "as long as possible", 86400
	
	/*
	// list all port mappings
	size_t index = 0;
	while (true)
	{
		char map_wan_port[200] = "";
		char map_lan_address[200] = "";
		char map_lan_port[200] = "";
		char map_protocol[200] = "";
		char map_description[200] = "";
		char map_mapping_enabled[200] = "";
		char map_remote_host[200] = "";
		char map_lease_duration[200] = ""; // original time, not remaining time :(

		error = UPNP_GetGenericPortMappingEntry(
			upnp_urls.controlURL,
			upnp_data.first.servicetype,
			std::to_string(index).c_str(),
			map_wan_port,
			map_lan_address,
			map_lan_port,
			map_protocol,
			map_description,
			map_mapping_enabled,
			map_remote_host,
			map_lease_duration);

		if (error)
		{
			break; // no more port mappings available
		}
		index++;

		cout << map_wan_port << "=" << map_lan_address << "=" << map_lan_port << "=" << map_protocol << "=" << map_description << "=" << map_mapping_enabled << "=" << map_remote_host << "=" << map_lease_duration << "=" << endl;
	}
	*/

	FreeUPNPUrls(&upnp_urls);
	freeUPNPDevlist(upnp_dev);

	return error == 0;
}
#endif

void p2p::watchdog()
{
	std::chrono::time_point<std::chrono::steady_clock> last_check, last_pf_check;

	//every 120 minutes we need

	while (!cfg.bQuit) {
		//cfg.minimum_outgoing_connections
		//check stored peer list every 6 hr and upon first run.
		if (last_check == std::chrono::steady_clock::time_point() || std::chrono::steady_clock::now() > last_check + 6h) {
			this->process_stored_peer_list(); //verifies peer list and erases bad peers. Any peers that are already connected are automatically updated as valid.
			last_check = std::chrono::steady_clock::now();
		}

#ifndef _DEBUG

		if (last_pf_check == std::chrono::steady_clock::time_point() || std::chrono::steady_clock::now() >= last_pf_check + 2h) {
			if (this->cfg.wPort != NULL)
				port_forward(std::to_string(this->cfg.wPort), "p2p_" + std::to_string(this->cfg.wPort));
			last_pf_check = std::chrono::steady_clock::now();
		}

#endif

		if (this->established_connections_count(defs::connection_types::out) < P2P_MINIMUM_OUTGOING_CONNECTIONS) {
			//we try to maintain at least P2P_MINIMUM_OUTGOING_CONNECTIONS(25) outgoing connections.
			setup_prescan_prequisities();
			scan_peerlist(get_default_peerlist()); //check our default peer list

			if (this->established_connections_count(defs::connection_types::out) < P2P_MINIMUM_OUTGOING_CONNECTIONS) {
				setup_prescan_prequisities();
				
				std::list<std::shared_ptr<network::p2p::peer>> sockets;
				{
					auto lock = this->peers.established.acquire_sockets_lock();
					for (auto& peer : this->peers.established)
						if (peer->connected())
							sockets.push_back(std::dynamic_pointer_cast<network::p2p::peer>(peer));
				}

				/*
				for (auto& socket : sockets) {
					if (this->established_connections_count(defs::connection_types::out) > P2P_MINIMUM_OUTGOING_CONNECTIONS)
						break;
					auto list = socket->query_peers(20s);
					//debug_msg("app::p2p_watchdog()  - queried peer list, size = " + list.size());
					scan_peerlist(list);
				}
				*/
				//refactored version
				std::list<network::p2p::async_peerlist_req> reqs;
				for (auto& socket : sockets)
					reqs.push_back(socket->async_query_peers(30s));
				std::list<sPeer> results;
				for (auto& req : reqs) {
					auto list = req.get();
					results.insert(results.end(), list.begin(), list.end());
					if (list.size() >= MAX_PEERLIST_ENTRIES / 2) {
						validate_peer_list(results);
						scan_peerlist(results);
						results.clear();
					}
				}
				validate_peer_list(results);
				reqs.clear();
				sockets.clear();
				scan_peerlist(results);
			}

		}

#ifdef DEBUGGING
		cout << "---------------------------" << endl;
		cout << "established out connections: " << this->established_connections_count(defs::connection_types::out) << endl;
		cout << "Workers: " << this->established_worker_count() << endl;
		cout << "established in connections: " << this->established_connections_count(defs::connection_types::in) << endl;
		cout << "pending out connections: " << this->temporary_connections_count(defs::connection_types::out) << endl;
		cout << "pending in connections: " << this->temporary_connections_count(defs::connection_types::in) << endl;
		for (auto& p : get_current_peer_list())
			cout << "peer: " << p.ip << ":" << p.wPort << endl;
#endif

		//looped P2P_WATCHDOG_SLEEPTIME_SEC sleep while also checking bQuit in order to shutdown as fast as possible if bQuit flag is set.
		for (int i = 0; i < P2P_WATCHDOG_SLEEPTIME_SEC; i++) {
			if (cfg.bQuit)
				break;
			std::this_thread::sleep_for(1s);
		}

	}

}

#define thelist network.pending_establishment_connections.my_list
p2p_establish_connection_wrapper::p2p_establish_connection_wrapper(p2p & network, UUID my_uuid):network(network)
{
	std::lock_guard<std::recursive_mutex> lock(network.pending_establishment_connections.m);
	my_uid = thelist.insert(thelist.end(), my_uuid);
	bDestroyed = false;
}

p2p_establish_connection_wrapper::p2p_establish_connection_wrapper(p2p_establish_connection_wrapper && other):network(other.network)
{
	std::lock_guard<std::recursive_mutex> lock(network.pending_establishment_connections.m);
	my_uid = other.my_uid;
	other.my_uid = thelist.end();
	other.bDestroyed = true;
}

p2p_establish_connection_wrapper::~p2p_establish_connection_wrapper()
{
	std::lock_guard<std::recursive_mutex> lock(network.pending_establishment_connections.m);
	if (my_uid != thelist.end())
		thelist.erase(my_uid);
}