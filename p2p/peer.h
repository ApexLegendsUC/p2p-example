#pragma once

class p2p;

struct sRemoteCfg {
	WORD listening_port;
	bool bFirewalled;
	UUID id;
};

class p2p_establish_connection_wrapper;

namespace network {
	namespace p2p {
		class peer;
		class temp_peer;

		class peer_base :public sockets::tcp::async::socket {
		public:
			peer_base(sockets::tcp::async::io_service& io, SOCKET sSocket, defs::connection_types conn_type);
			peer_base(sockets::tcp::async::io_service& io, peer_base&& other, defs::connection_types conn_type);
			
			defs::connection_types connection_type() const {
				return conn_type;
			};

			bool firewalled() const { return remote_cfg.bFirewalled; };
			WORD remote_port() const { return connection_type() == defs::in ? remote_cfg.listening_port : socket::remote_port(); }; //overrides sockets::tcp::async::socket::remote_port for specific implementation.
			UUID get_uuid() const { return remote_cfg.id; };
		private:
			friend class ::p2p;
			friend class peer;
			friend class temp_peer;
			sRemoteCfg remote_cfg;
			defs::connection_types conn_type;
		};

		
		class temp_peer :public peer_base {
		public:
			using peer_base::peer_base;
			~temp_peer();
		private:
			std::unique_ptr<p2p_establish_connection_wrapper> wrap_conn_est;
			friend class ::p2p;
			sockets::tcp::async::connector connector;
			bool bEstablishSession = false;
			int state = 0;
		};

		//WARNING: must have a shared_ptr to peer that's in scope to use the async peerlist query req func
		class async_peerlist_req {
		public:
			async_peerlist_req(peer& _peer, std::list<sPeerListQueryReq>::iterator req, std::chrono::steady_clock::time_point timeout);
			async_peerlist_req(async_peerlist_req&& other);
			async_peerlist_req(const async_peerlist_req&) = delete;
			~async_peerlist_req();
			void wait();
			std::list<sPeer> get(bool bValidatePeerList = true);
		private:
			std::chrono::steady_clock::time_point timeout;
			std::list<sPeerListQueryReq>::iterator req;
			peer& _peer;
		};

		class peer :public peer_base {
		public:
			peer(sockets::tcp::async::io_service& io, temp_peer&& other, ::p2p& p2p);
			virtual ~peer();

			std::list<sPeer> query_peers(std::chrono::milliseconds timeout); //warning: will block
			async_peerlist_req async_query_peers(std::chrono::milliseconds timeout);
		private:
			friend class ::p2p;
			friend class async_peerlist_req;
			::p2p & network_mgr;
			std::recursive_mutex m_peer_list_queries;
			std::list<sPeerListQueryReq> peer_list_queries;
			int nPeerListReqID;
		};


	}

}

void validate_peer_list(std::list<sPeer>& list);