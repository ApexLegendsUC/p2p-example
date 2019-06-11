#pragma once
#include <bitflg.hpp>

namespace vfs {

	class system;
	class encrypted_system;

	enum file_identifier_types :BYTE {
		integral,
		str
	};

	class id {
	public:
		explicit id(ULONGLONG id);
		explicit id(const std::wstring& id);
		id(id&& other);
		id(const id& other);
		file_identifier_types type() const { return _type; };
		template <typename T>
		T get() const;
		bool operator==(const id& other);
		void operator=(const id& other) {
			this->_type = other._type;
			this->_id.ws = other._id.ws;
			this->_id.v = other._id.v;
		};
	private:
		file_identifier_types _type;
		struct {
			std::wstring ws;
			ULONGLONG v;
		}_id;
	};

	template<>
	inline std::wstring id::get() const
	{
		if (type() == str)
			return _id.ws;
		throw std::exception("Type mismatch"); //return L"";
	}

	template<>
	inline std::string id::get() const
	{
		if (type() == str)
			return std::string(_id.ws.begin(), _id.ws.end());
		throw std::exception("Type mismatch"); //return L"";
	}

	template<>
	inline ULONGLONG id::get() const
	{
		if (type() == integral)
			return _id.v;
		throw std::exception("Type mismatch"); //return NULL;
	}

	template<>
	inline DWORD id::get() const
	{
		if (type() == integral)
			return static_cast<DWORD>(_id.v);
		throw std::exception("Type mismatch"); //return NULL;
	}

	template<>
	inline int id::get() const
	{
		if (type() == integral)
			return static_cast<int>(_id.v);
		throw std::exception("Type mismatch"); //return NULL;
	}

	class file {
	public:
		file(id&& id, size_t file_id, DWORD data_size, LONGLONG offset);
		file(file&& other);
		file(const file&) = delete;
		file_identifier_types type() const { return identifier.type(); };
		size_t fid() const { return file_id; };
		DWORD get_size() const { return file_size; };
		template <typename T>
		T get_id() const { return identifier.get<T>(); };
		bool operator==(const file& other) { return this->fid() == other.fid(); };
		void operator=(file&& other) {
			file_size = other.file_size;
			file_id = other.file_id;
			offset = other.offset;
			identifier = other.identifier;
		};
	private:
		friend class system;
		friend class encrypted_system;
		DWORD file_size;
		size_t file_id;
		LONGLONG offset;
		id identifier;
	};

	enum options {
		rd = BitFlags::option1,
		wr = BitFlags::option2,
		share_rd = BitFlags::option3,
		share_wr = BitFlags::option4,
		existing = BitFlags::option5
	};
};

inline vfs::options operator| (vfs::options a, vfs::options b) { return static_cast<vfs::options>(static_cast<int>(a) | static_cast<int>(b)); };

namespace vfs{
	
	class system {
	public:
		system();
		~system();
		system(system&&) = delete;
		system(const system&) = delete;
		bool open(const std::string& filename, options mode = rd | wr | share_rd);
		bool open(const std::wstring& filename, options mode = rd | wr | share_rd);

		std::list<file>::iterator write(ULONGLONG id, const std::vector<BYTE>& data);
		std::list<file>::iterator write(const std::wstring& id, const std::vector<BYTE>& data);
		std::list<file>::iterator write_or_update(ULONGLONG id, const std::vector<BYTE>& data);
		std::list<file>::iterator write_or_update(const std::wstring& id, const std::vector<BYTE>& data);

		virtual std::list<file>::iterator write(ULONGLONG id, LPCVOID data, DWORD size);
		virtual std::list<file>::iterator write(const std::wstring& id, LPCVOID data, DWORD size);

		std::vector<BYTE> read(ULONGLONG id);
		std::vector<BYTE> read(const std::wstring& id);
		virtual std::vector<BYTE> read(const file& id);

		bool update(const vfs::id& id, const std::vector<BYTE>& data);
		//bool update(DWORD id, const std::vector<BYTE>& data);
		//bool update(const std::wstring& id, const std::vector<BYTE>& data);
		bool update(ULONGLONG id, LPCVOID data, DWORD size);
		bool update(const std::wstring& id, LPCVOID data, DWORD size);
		virtual bool update(const file& id, LPCVOID data, DWORD size);

		void remove(const file& file);
		void remove(const vfs::id& id);

		std::list<file>::iterator erase(std::list<file>::iterator file);

		//std::list<file>::iterator find(const std::wstring& id);
		//std::list<file>::iterator find(const ULONGLONG& id);
		std::list<file>::iterator find(const vfs::id& id);

		std::list<file>::iterator find_by_fid(const size_t& fid);


		std::list<file>::iterator begin() { return files.begin(); };
		std::list<file>::iterator end() { return files.end(); };
		std::list<file>::const_iterator cbegin() const { return files.cbegin(); };
		std::list<file>::const_iterator cend() const { return files.cend(); };

		void clear();

		bool is_opened() { return hFile != INVALID_HANDLE_VALUE; };
		void close();
		void cleanup();
		options g_mode() const { return _mode; };
		size_t file_count() const { return files.size(); };
		std::wstring get_filename() const { return filename; };
		LONGLONG size_on_hd() const;
		LONGLONG junksize() const;
	private:
		void move_data(OVERLAPPED& ovl_old, OVERLAPPED& ovl_new, LONGLONG chunk_size);
		void parse_vfs();
	protected:
		HANDLE hFile;
		size_t fid_counter;
		options _mode;
		std::list<file> files;
		std::wstring filename;
	};

	//to use encrypted_system you must #include <crypto.h> before #include <vfs.h>
#ifdef _CRYPTO_H

	class encrypted_system :public system {
	public:
		using system::system;
		~encrypted_system() {};
		void set(Crypto::AES&& encryption);
		using system::write;
		std::list<file>::iterator write(ULONGLONG id, LPCVOID data, DWORD size) override;
		std::list<file>::iterator write(const std::wstring& id, LPCVOID data, DWORD size) override;
		using system::read;
		std::vector<BYTE> read(const file& id) override;
		bool update(const file& id, LPCVOID data, DWORD size) override;
		using system::update;
	private:
		Crypto::AES encryption;
	};

#endif


};