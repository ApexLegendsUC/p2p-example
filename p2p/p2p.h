#pragma once

namespace network {
	namespace p2p {
		class peer_base;
		class temp_peer;
		class peer;
	};
};

typedef std::list<UUID> pending_establish_conn;
typedef pending_establish_conn::iterator pec_it;


class p2p;
class p2p_establish_connection_wrapper {
public:
	p2p_establish_connection_wrapper(p2p& network, UUID my_uuid);
	p2p_establish_connection_wrapper(p2p_establish_connection_wrapper&& other);
	~p2p_establish_connection_wrapper();
private:
	bool bDestroyed;
	pec_it my_uid;
	p2p & network;
};

class p2p {
public:
	p2p(const std::wstring& directory, DWORD dwNetworkID = 1);
	~p2p();

	void set_bootstrap_list(const std::list<sPeer>& peerlist);

	bool initiate(WORD wDefaultPort, bool generate_port_if_taken, bool fail_if_unable_to_listen = false, const sockets::tcp::async::listener_flags lf = sockets::tcp::async::listener_flags::IPv4 | /*sockets::tcp::async::listener_flags::IPv6 |*/ sockets::tcp::async::listener_flags::ANY);

	size_t established_connections_count(defs::connection_types type) const;
	size_t temporary_connections_count(defs::connection_types type) const;
	size_t ipcount_established(const std::string & ip) const;
	size_t ipcount_pending(const std::string & ip) const;
	size_t established_worker_count() const;
	std::shared_ptr<network::p2p::peer> find_established_peer_by_ip(const std::string & ip) const;
	std::shared_ptr<network::p2p::peer> find_established_peer_by_uuid(const UUID & id) const;

	void broadcast(const std::string & name, const std::vector<BYTE>& buffer = std::vector<BYTE>(), const std::shared_ptr<sockets::tcp::async::socket>& exclude = std::shared_ptr<sockets::tcp::async::socket>()); //broadcasts a message to all except for the excluded peer.
	void broadcast(const std::string & name, const std::vector<BYTE>& buffer, const std::list<std::shared_ptr<sockets::tcp::async::socket>>& excluded/* = std::list<std::shared_ptr<socket>>()*/); //same as above, except you can specify multiple excluded peers.

	void set_on_create_established_session_callback(std::function<std::shared_ptr<network::p2p::peer>(sockets::tcp::async::io_service& io, network::p2p::temp_peer& temp, p2p& p2p)> cb);
	void set_on_established_session_callback(std::function<void(const std::shared_ptr<network::p2p::peer>&)> cb); //must be set beforehand, cannot be removed once set as there is no thread safety.

	WORD port() const { return cfg.wPort; };

	void quit();

	void set_max_buffer_size(size_t n);
	void set_established_global_bandwidth_cap(sockets::tcp::async::io_cap io_cap, ULONGLONG max_bps);
	size_t current_network_io(sockets::tcp::async::io_cap io_type);
	size_t current_established_network_io(sockets::tcp::async::io_cap io_type);
	size_t current_pending_network_io(sockets::tcp::async::io_cap io_type);
private:
	struct {
		std::recursive_mutex m;
		pending_establish_conn my_list;
	}pending_establishment_connections;

	friend class p2p_establish_connection_wrapper;
	friend class network::p2p::peer;
	

	static DWORD WINAPI static_watchdog(p2p* p)
	{
		p->watchdog();
		return 0;
	};
	
	std::wstring path;
	struct {
		std::function<std::shared_ptr<network::p2p::peer>(sockets::tcp::async::io_service& io, network::p2p::temp_peer& temp, p2p& p2p)> on_create_session;
		std::function<void(const std::shared_ptr<network::p2p::peer>&)> on_established_session_cb;
	}callbacks;

	struct {
		WORD wPort;
		DWORD dwNetworkID;
		UUID identifier; //used to uniquely identify each peer.
		HANDLE hWatchDogThrd;
		bool bQuit;
		int max_allowed_combined_peers = 2000, max_allowed_pending = 400, max_allowed_sessions = 1000, max_allowed_workers = 800;
		//size_t pending_establishment_connections = 0;
		std::list<sPeer> bootstrap_list;
	}cfg;

	struct {
		sockets::tcp::async::io_service pending, established;
	}peers;

	struct {
		std::mutex m_peerlist;

		vfs::system settings;
		vfs::encrypted_system peerlist;
	}fs;

	struct {
		Crypto::RSA rsa;
		Crypto::AES aes;
		Crypto::CryptContext cc;
	}network_encryption;

	sockets::tcp::async::listener listener;


	void process_stored_peer_list();
	void watchdog();

	struct sCheckPeersExtraInfo {
		std::list<sPeer> tried;
#ifdef _DEBUG
		std::list<sPeer> connected; //to-do: synchronize the list with the state they are in in the i/o handler (peers.established), e.g. keep the list "live"
#else
		std::list<std::string> connected;
#endif
		std::mutex m;
	}check_peers_extra_info;

	void scan_peerlist(const std::list<sPeer>& peer_list, int nDepth = 1); //warning: recursive
	std::list<sPeer> get_default_peerlist();

	void on_established_peer_disconnect(network::p2p::peer* peer);
	void setup_accepted_temporary_peer_callbacks(const std::shared_ptr<network::p2p::temp_peer>& client);
	void setup_established_peer_callbacks(const std::shared_ptr<network::p2p::peer>& client);
	void setup_connected_temporary_peer_callbacks(const std::shared_ptr<network::p2p::temp_peer>& client);

#ifdef _DEBUG
	bool create_or_update_peerlist_entry(const std::string & sIP, WORD wPort, const std::function<bool(sPeerDBEntry*entry)>& cb);
#else
	bool create_or_update_peerlist_entry(const std::string & sIP, const std::function<bool(sPeerDBEntry*entry)>& cb);
#endif
	std::list<sPeer> get_current_peer_list();

	void setup_prescan_prequisities();
	void setup_peerconnectmsg(sPeerConnectMsg* msg, defs::operation_types op);
};