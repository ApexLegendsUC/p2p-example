#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <wincrypt.h>
#include <list>
#include <locale>
#include <string>
#include <vector>
#include <crypto.h>
#include "vfs.h"
#include <algorithm>

#pragma warning(disable:4267)

#pragma pack(push, 1) //https://stackoverflow.com/a/3318475

struct sFile_Base {
	vfs::file_identifier_types type;
	bool bDeleted;
	DWORD file_size;
};

struct sFile_integral_ID:public sFile_Base {
	ULONGLONG id;
};

struct sFile_string_ID :public sFile_Base {
	WORD id_len;
	//wchar_t id[id_len];
};

#pragma pack(pop)

vfs::id::id(ULONGLONG id)
{
	_type = integral;
	this->_id.v = id;
}

vfs::id::id(const std::wstring & id)
{
	_type = str;
	this->_id.ws = id;
}

vfs::id::id(id && other)
{
	this->_type = other._type;
	this->_id.v = other._id.v;
	this->_id.ws = std::move(other._id.ws);
}

vfs::id::id(const id & other)
{
	this->_type = other._type;
	this->_id.v = other._id.v;
	this->_id.ws = other._id.ws;
}

bool vfs::id::operator==(const id & other)
{
	switch (type()) {
	case integral:
		return this->_id.v == other._id.v;
		break;
	case str:
		return this->_id.ws == other._id.ws;
		break;
	}
	return false;
}


vfs::file::file(id && id, size_t file_id, DWORD data_size, LONGLONG offset):identifier(std::move(id))
{
	this->file_id = file_id;
	this->file_size = data_size;
	this->offset = offset;
}

vfs::file::file(file && other):identifier(std::move(other.identifier))
{
	this->file_id = other.file_id;
	this->file_size = other.file_size;
	this->offset = other.offset;
}

vfs::system::system()
{
	hFile = INVALID_HANDLE_VALUE;
	fid_counter = NULL;
}

vfs::system::~system()
{
	try {
		this->cleanup();
	}
	catch (std::exception& e) {
		UNREFERENCED_PARAMETER(e);
	}
	this->close();
}

bool vfs::system::open(const std::string & filename, options mode)
{
	return open(std::wstring(filename.begin(), filename.end()), mode);
}

bool vfs::system::open(const std::wstring & filename, options mode)
{
	this->close();
	DWORD dwDesiredAccess = 0;
	if (mode & options::rd)
		dwDesiredAccess |= GENERIC_READ;
	if (mode & options::wr)
		dwDesiredAccess |= GENERIC_WRITE;
	if (dwDesiredAccess == NULL)
		throw std::exception("Invalid mode");
	DWORD dwShareMode = 0;
	if (mode & share_rd)
		dwShareMode |= FILE_SHARE_READ;
	if (mode & share_wr)
		dwShareMode |= FILE_SHARE_WRITE;

	DWORD dwCreationDisposition = (mode & existing) ? OPEN_EXISTING : OPEN_ALWAYS;

	this->_mode = mode;
	this->filename = filename;
	hFile = ::CreateFile(this->filename.c_str(), dwDesiredAccess, dwShareMode, nullptr, dwCreationDisposition, FILE_ATTRIBUTE_NORMAL, 0);
	//printf("gle: %X\n", GetLastError());
	//if GetLastError() == ERROR_SHARING_VIOLATION \/
	//warning: You cannot request a sharing mode that conflicts with the access mode that is specified in an existing request that has an open handle. CreateFile would fail and the GetLastError function would return ERROR_SHARING_VIOLATION.
	//this problem was occuring on my Windows Server 2016 rdp, to solve, simply supply share_rd | share_wr when opening the existing file that has been opened by another process.

	this->parse_vfs();
	return hFile != INVALID_HANDLE_VALUE;
}

std::list<::vfs::file>::iterator vfs::system::write(ULONGLONG id, const std::vector<BYTE>& data)
{
	return write(id, data.data(), data.size());
}

std::list<::vfs::file>::iterator vfs::system::write(const std::wstring & id, const std::vector<BYTE>& data)
{
	return write(id, data.data(), data.size());
}

std::list<::vfs::file>::iterator vfs::system::write_or_update(ULONGLONG id, const std::vector<BYTE>& data)
{
	auto it = find(vfs::id(id));
	if (it == end())
		return write(id, data);
	else {
		if (update(vfs::id(id), data))
			return it;
		else
			return end();
	}
}

std::list<::vfs::file>::iterator vfs::system::write_or_update(const std::wstring & id, const std::vector<BYTE>& data)
{
	auto it = find(vfs::id(id));
	if (it == end())
		return write(id, data);
	else {
		if (update(vfs::id(id), data))
			return it;
		else
			return end();
	}
}

std::list<::vfs::file>::iterator vfs::system::write(ULONGLONG id, LPCVOID data, DWORD size)
{
	if (!is_opened())
		throw std::exception("Database not open");//return end();
	LARGE_INTEGER old_size;
	if (!GetFileSizeEx(hFile, &old_size))
		return end();

	sFile_integral_ID file;
	file.type = file_identifier_types::integral;
	file.bDeleted = false;
	file.file_size = size;
	file.id = id;
	DWORD written;
	OVERLAPPED ovl = { };
	*PLONGLONG(&ovl.Offset) = 0xFFFFFFFFFFFFFFFF; //ovl.Offset = ovl.OffsetHigh = 0xFFFFFFFF;

	if (!::WriteFile(hFile, &file, sizeof(file), &written, &ovl))
		throw std::exception("Unable to write to database.");
	if (size != NULL)
		if (!::WriteFile(hFile, data, size, &written, &ovl)) {
			if (::SetFilePointerEx(hFile, old_size, nullptr, FILE_BEGIN))
				::SetEndOfFile(hFile);
			throw std::exception("Unable to write to database.");
		}
	::vfs::file f(vfs::id(id), ++fid_counter, size, old_size.QuadPart);
	return files.insert(files.end(), std::move(f));
}

std::list<::vfs::file>::iterator vfs::system::write(const std::wstring & id, LPCVOID data, DWORD size)
{
	if (!is_opened())
		throw std::exception("Database not open");//return end();
	LARGE_INTEGER old_size;
	if (!GetFileSizeEx(hFile, &old_size))
		return end();

	sFile_string_ID file;
	file.type = file_identifier_types::str;
	file.bDeleted = false;
	file.file_size = size;
	file.id_len = static_cast<WORD>(id.length());
	DWORD written;
	OVERLAPPED ovl = {};
	*PLONGLONG(&ovl.Offset) = 0xFFFFFFFFFFFFFFFF; //ovl.Offset = ovl.OffsetHigh = 0xFFFFFFFF;

	if (!::WriteFile(hFile, &file, sizeof(file), &written, &ovl))
		throw std::exception("Unable to write to database.");
	if (!::WriteFile(hFile, id.c_str(), id.length() * sizeof(wchar_t), &written, &ovl)) {
		if (::SetFilePointerEx(hFile, old_size, nullptr, FILE_BEGIN))
			::SetEndOfFile(hFile);
		throw std::exception("Unable to write to database.");
	}
	if (size != NULL)
		if (!::WriteFile(hFile, data, size, &written, &ovl)) {
			if (::SetFilePointerEx(hFile, old_size, nullptr, FILE_BEGIN))
				::SetEndOfFile(hFile);
			throw std::exception("Unable to write to database.");
		}
	::vfs::file f(vfs::id(id), ++fid_counter, size, old_size.QuadPart);
	return files.insert(files.end(), std::move(f));
}

bool vfs::system::update(const vfs::id& id, const std::vector<BYTE>& data)
{
	switch (id.type()) {
	case vfs::file_identifier_types::integral:
	{
		return this->update(id.get<ULONGLONG>(), data.data(), data.size());
	}
	break;
	case vfs::file_identifier_types::str:
	{
		return this->update(id.get<std::wstring>(), data.data(), data.size());
	}
	break;
	default:
		return false;
	}
}

bool vfs::system::update(ULONGLONG id, LPCVOID data, DWORD size)
{
	for (auto& file : files)
		if (file.type() == file_identifier_types::integral && file.get_id<ULONGLONG>() == id)
			return update(file, data, size);
	throw std::exception("Unable to find file with that id.");
}

bool vfs::system::update(const std::wstring & id, LPCVOID data, DWORD size)
{
	for (auto& file : files)
		if (file.type() == file_identifier_types::str && file.get_id<std::wstring>() == id)
			return update(file, data, size);
	throw std::exception("Unable to find file with that id.");
}

bool vfs::system::update(const file & file, LPCVOID data, DWORD size)
{
	if (file.file_size != size) {
		auto _id = file.identifier;
		this->remove(file);
		std::list<vfs::file>::iterator it;
		switch (_id.type()) {
		case vfs::file_identifier_types::integral:
			it = this->write(_id.get<ULONGLONG>(), data, size);
			break;
		case vfs::file_identifier_types::str:
		{
			it = this->write(_id.get<std::wstring>(), data, size);
		}
			break;
		default:
			it = files.end();
		}
		return it != files.end();
	}
	else {
		switch (file.type()) {
		case vfs::file_identifier_types::integral:
		{
			OVERLAPPED ovl = { };
			*PULONGLONG(&ovl.Offset) = file.offset + sizeof(sFile_integral_ID);
			DWORD written;
			return ::WriteFile(hFile, data, size, &written, &ovl) == TRUE;
		}
		break;
		case vfs::file_identifier_types::str:
		{
			OVERLAPPED ovl = {};
			*PULONGLONG(&ovl.Offset) = file.offset + sizeof(sFile_string_ID) + (file.get_id<std::wstring>().length() * sizeof(wchar_t));
			DWORD written;
			return ::WriteFile(hFile, data, size, &written, &ovl) == TRUE;
		}
		break;
		}
		
	}
	return false;
}

std::vector<BYTE> vfs::system::read(ULONGLONG id)
{
	for (const auto& file : files)
		if (file.type() == file_identifier_types::integral && file.get_id<ULONGLONG>() == id)
			return this->read(file);
	throw std::exception("Unable to find file with that id."); //throw std::runtime_error("Unable to find file with id: " + std::to_string(id));
}

std::vector<BYTE> vfs::system::read(const std::wstring & id)
{
	for (const auto& file : files)
		if (file.type() == file_identifier_types::str && file.get_id<std::wstring>() == id)
			return this->read(file);
	throw std::exception("Unable to find file with that id.");
}

std::vector<BYTE> vfs::system::read(const file & id)
{
	if (!is_opened())
		throw std::exception("Database not open"); //return std::vector<BYTE>();

	OVERLAPPED ovl = { };
	*PLONGLONG(&ovl.Offset) = id.offset;
	sFile_Base base;
	DWORD dwRead;
	if (!::ReadFile(hFile, &base, sizeof(base), &dwRead, &ovl))
		throw std::exception("vfs::system::read() - ReadFile() failed");
	if (base.bDeleted)
		throw std::exception("vfs::system::read() - attempted to read a deleted file.");
	std::vector<BYTE> result;
	switch (base.type) {
	case file_identifier_types::integral:
	{
		sFile_integral_ID file;
		if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl))
			throw std::exception("vfs::system::read() - ReadFile() failed");
		*PLONGLONG(&ovl.Offset) += sizeof(sFile_integral_ID);
		result.resize(file.file_size);
		if (!::ReadFile(hFile, result.data(), result.size(), &dwRead, &ovl))
			throw std::exception("vfs::system::read() - ReadFile() failed");
		return result;
	}
	break;
	case file_identifier_types::str:
	{
		sFile_string_ID file;
		LONGLONG offset = *PLONGLONG(&ovl.Offset);
		if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl))
			throw std::exception("vfs::system::read() - ReadFile() failed");
		*PLONGLONG(&ovl.Offset) += dwRead + file.id_len * sizeof(wchar_t);
		result.resize(file.file_size);
		if (!::ReadFile(hFile, result.data(), result.size(), &dwRead, &ovl))
			throw std::exception("vfs::system::read() - ReadFile() failed");
		return result;
	}
	break;
	default:
		throw std::exception("unknown file ID type.");
	}
}

void vfs::system::remove(const file & file)
{
	if (!is_opened())
		throw std::exception("Database not open");
	sFile_Base base;
	base.bDeleted = true;
	base.file_size = file.get_size();
	base.type = file.type();
	OVERLAPPED ovl = { };
	*PLONGLONG(&ovl.Offset) = file.offset;
	DWORD dwWritten;
	if (!::WriteFile(hFile, &base, sizeof(base), &dwWritten, &ovl))
		throw std::exception("Failed to write to database");
	files.remove(file);
}

void vfs::system::remove(const vfs::id& id)
{
	switch (id.type()) {
	case str:
	{
		auto strid = id.get<std::wstring>();
		for (auto& file : files)
			if (file.type() == str && file.get_id<std::wstring>() == strid)
				return remove(file);
		throw std::exception("file not found");
	}
	break;
	case integral:
	{
		for (auto& file : files)
			if (file.type() == integral && file.get_id<ULONGLONG>() == id.get<ULONGLONG>())
				return remove(file);
		throw std::exception("file not found");
	}
	break;
	default:
		throw std::exception("Invalid id");
	}
}

std::list<vfs::file>::iterator vfs::system::erase(std::list<file>::iterator file)
{
	if (!is_opened())
		throw std::exception("Database not open");
	sFile_Base base;
	base.bDeleted = true;
	base.file_size = file->get_size();
	base.type = file->type();
	OVERLAPPED ovl = {};
	*PLONGLONG(&ovl.Offset) = file->offset;
	DWORD dwWritten;
	if (!::WriteFile(hFile, &base, sizeof(base), &dwWritten, &ovl))
		throw std::exception("Failed to write to database");
	return files.erase(file);
}

std::list<vfs::file>::iterator vfs::system::find(const vfs::id & id)
{
	switch (id.type()) {
	case str:
	{
		for (auto it = files.begin(); it != files.end(); ++it)
			if (it->type() == str && it->get_id<std::wstring>() == id.get<std::wstring>())
				return it;
	}
	break;
	case integral:
	{
		for (auto it = files.begin(); it != files.end(); ++it)
			if (it->type() == integral && it->get_id<ULONGLONG>() == id.get<ULONGLONG>())
				return it;
	}
	break;
	}
	return end();
}

std::list<vfs::file>::iterator vfs::system::find_by_fid(const size_t & fid)
{
	for (auto it = files.begin(); it != files.end(); it++) {
		if (it->fid() == fid)
			return it;
	}
	return files.end();
}

void vfs::system::clear()
{
	if (hFile != INVALID_HANDLE_VALUE) {
		if (::SetFilePointerEx(hFile, LARGE_INTEGER(), nullptr, FILE_BEGIN)) {
			::SetEndOfFile(hFile);
			files.clear();
			fid_counter = NULL;
		}
	}
}

void vfs::system::close()
{
	if (hFile != INVALID_HANDLE_VALUE) {
		::CloseHandle(hFile);
		hFile = INVALID_HANDLE_VALUE;
	}
	fid_counter = NULL;
	files.clear();
	filename = L"";
}

LONGLONG vfs::system::size_on_hd() const
{
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hFile, &size))
		return -1;
	return size.QuadPart;
}

LONGLONG vfs::system::junksize() const
{
	size_t total_size_files_take_up = 0;
	for (const auto& file : files) {
		total_size_files_take_up += file.get_size();
		switch (file.type()) {
		case file_identifier_types::integral:
			total_size_files_take_up += sizeof sFile_integral_ID;
			break;
		case file_identifier_types::str:
			total_size_files_take_up += sizeof(sFile_string_ID) + (file.get_id<std::wstring>().length() * sizeof(wchar_t));
			break;
		}
	}
	return size_on_hd() - total_size_files_take_up;
}

void vfs::system::move_data(OVERLAPPED& ovl_old, OVERLAPPED& ovl_new, LONGLONG chunk_size)
{
	/*std::for_each(files.begin(), files.end(), [&](file& f) {
		if (f.offset == *PLONGLONG(&ovl_old.Offset))
			f.offset = *PLONGLONG(&ovl_new.Offset);
	});*/
	
	for (auto& file : files) {
		if (file.offset == *PLONGLONG(&ovl_old.Offset)) {
			file.offset = *PLONGLONG(&ovl_new.Offset);
			break;
		}
	}

	char buf[4096];
	while (chunk_size) {
		DWORD read_size = chunk_size > sizeof(buf) ? sizeof(buf) : static_cast<DWORD>(chunk_size);
		if (!::ReadFile(hFile, buf, read_size, &read_size, &ovl_old))
			throw std::exception("vfs::system::move_data() - ReadFile() failed");
		if (!::WriteFile(hFile, buf, read_size, &read_size, &ovl_new))
			throw std::exception("vfs::system::move_data() - WriteFile() failed");
		*PLONGLONG(&ovl_new.Offset) += read_size;
		*PLONGLONG(&ovl_old.Offset) += read_size;
		chunk_size -= read_size;
	}
}

void vfs::system::cleanup()
{
	if (!is_opened())
		return;
	//removes files with deleted flag and adjusts file offsets.
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hFile, &size))
		return;
	OVERLAPPED ovl_old = { }, ovl_new = { };
	while (*PLONGLONG(&ovl_old.Offset) < size.QuadPart) {
		sFile_Base base;
		DWORD dwRead;
		if (!::ReadFile(hFile, &base, sizeof(base), &dwRead, &ovl_old))
			throw std::exception("vfs::system::cleanup() - ReadFile() failed");
		LONGLONG chunk_size;
		switch (base.type) {
		case file_identifier_types::integral:
		{
			sFile_integral_ID file;
			if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl_old))
				throw std::exception("vfs::system::cleanup() - ReadFile() failed");
			chunk_size = sizeof(file) + file.file_size;
		}
		break;
		case file_identifier_types::str:
		{
			sFile_string_ID file;
			if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl_old))
				throw std::exception("vfs::system::cleanup() - ReadFile() failed");
			chunk_size = sizeof(file) + (file.id_len * sizeof(wchar_t)) + file.file_size;
		}
		break;
		default:
			throw std::exception("unknown file ID type.");
		}

		if (*PLONGLONG(&ovl_old.Offset) != *PLONGLONG(&ovl_new.Offset)) {
			if (!base.bDeleted)
				this->move_data(ovl_old, ovl_new, chunk_size);
			else
				*PLONGLONG(&ovl_old.Offset) += chunk_size;
		}
		else {
			*PLONGLONG(&ovl_old.Offset) += chunk_size;
			if (!base.bDeleted)
				*PLONGLONG(&ovl_new.Offset) += chunk_size;
		}
	}

	LARGE_INTEGER new_size;
	new_size.QuadPart = *PLONGLONG(&ovl_new.Offset);
	if (SetFilePointerEx(hFile, new_size, nullptr, FILE_BEGIN))
		::SetEndOfFile(hFile);
}

void vfs::system::parse_vfs()
{
	if (!is_opened())
		return;
	LARGE_INTEGER size;
	if (!GetFileSizeEx(hFile, &size))
		return;
	OVERLAPPED ovl = { };
	while (size.QuadPart) {
		sFile_Base base;
		DWORD dwRead;
		if (!::ReadFile(hFile, &base, sizeof(base), &dwRead, &ovl))
			throw std::exception("vfs::system::parse_vfs() - ReadFile() failed");
		switch (base.type) {
		case file_identifier_types::integral:
		{
			sFile_integral_ID file;
			if (size.QuadPart < sizeof(file))
				throw std::exception("corrupted");

			if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl))
				throw std::exception("vfs::system::parse_vfs() - ReadFile() failed");
			if (file.bDeleted == false)
				files.emplace_back(id(file.id), ++fid_counter, file.file_size, *PLONGLONG(&ovl.Offset));
			*PLONGLONG(&ovl.Offset) += dwRead + file.file_size;
			size.QuadPart -= dwRead + file.file_size;
		}
		break;
		case file_identifier_types::str:
		{
			sFile_string_ID file;
			if (size.QuadPart < sizeof(sFile_string_ID))
				throw std::exception("corrupted");
			LONGLONG offset = *PLONGLONG(&ovl.Offset);
			if (!::ReadFile(hFile, &file, sizeof(file), &dwRead, &ovl))
				throw std::exception("vfs::system::parse_vfs() - ReadFile() failed");
			*PLONGLONG(&ovl.Offset) += dwRead;
			if (static_cast<ULONGLONG>(size.QuadPart) < sizeof(sFile_string_ID) + file.file_size + (file.id_len * sizeof(wchar_t)))
				throw std::exception("corrupted");
			std::wstring ws;
			ws.resize(file.id_len);
			if (!::ReadFile(hFile, &ws[0], ws.length() * sizeof(wchar_t), &dwRead, &ovl))
				throw std::exception("vfs::system::parse_vfs() - ReadFile() failed");
			if (file.bDeleted == false)
				files.push_back(vfs::file(vfs::id(ws), ++fid_counter, file.file_size, offset));
			*PLONGLONG(&ovl.Offset) += dwRead + file.file_size;
			size.QuadPart -= sizeof(sFile_string_ID) + file.file_size + (file.id_len * sizeof(wchar_t));
		}
		break;
		default:
			throw std::exception("corrupted"); //unknown file ID type.
		}
	}

}


namespace vfs {
	void encrypted_system::set(Crypto::AES && encryption)
	{
		this->encryption = std::move(encryption);
	};

	std::list<file>::iterator encrypted_system::write(ULONGLONG id, LPCVOID data, DWORD size)
	{
		if (!encryption.available())
			throw std::exception("encryption not available");
		//auto enc = encryption.blockencrypt(data, size);
		std::vector<BYTE> enc;
		try {
			enc = encryption.encrypt(std::vector<BYTE>((PBYTE)data, (PBYTE)data + size));
		}
		catch (std::exception& e) {
			if (std::string(e.what()) == "Unable to encrypt data")
				throw std::exception("corrupted");//corrupted or incorrect password
		}
		return system::write(id, enc.data(), enc.size()); //we can't call system::write(DWORD, const std::vector<BYTE>&) because it will then call encrypted_system::write(DWORD, LPCVOID, DWORD) which will result in a stack overflow due to recursive calls to each other without the data being written in the end because they're passing it to each other infinitely(indefinitely).
	}

	std::list<file>::iterator encrypted_system::write(const std::wstring & id, LPCVOID data, DWORD size)
	{
		if (!encryption.available())
			throw std::exception("encryption not available");
		//auto enc = encryption.blockencrypt(data, size);
		std::vector<BYTE> enc;
		try {
			enc = encryption.encrypt(std::vector<BYTE>((PBYTE)data, (PBYTE)data + size));
		}
		catch (std::exception& e) {
			if (std::string(e.what()) == "Unable to encrypt data")
				throw std::exception("corrupted");//corrupted or incorrect password
		}
		return system::write(id, enc.data(), enc.size()); //we can't call system::write(const std::wstring&, const std::vector<BYTE>&) because it will then call encrypted_system::write(const std::wstring &, LPCVOID, DWORD) which will result in a stack overflow due to recursive calls to each other without the data being written in the end because they're passing it to each other infinitely(indefinitely).
	}

	std::vector<BYTE> encrypted_system::read(const file & id)
	{
		if (!encryption.available())
			throw std::exception("encryption not available");
		try {
			return encryption.decrypt(system::read(id));
		}
		catch (std::exception& e) {
			if (std::string(e.what()) == "Unable to decrypt")
				throw std::exception("corrupted");//corrupted or incorrect password
			else
				throw std::runtime_error(e.what());
		}
	}

/*	std::vector<BYTE> encrypted_system::read(ULONGLONG id)
	{
		return std::vector<BYTE>();
	}

	std::vector<BYTE> encrypted_system::read(const std::wstring & id)
	{
		return std::vector<BYTE>();
	}*/

	bool encrypted_system::update(const file & file, LPCVOID data, DWORD size)
	{
		if (!encryption.available())
			throw std::exception("encryption not available");
		if (file.file_size != encryption.get_plaintext_encrypted_len(size)) {
			auto _id = file.identifier;
			this->remove(file);
			std::list<vfs::file>::iterator it;
			switch (_id.type()) {
			case vfs::file_identifier_types::integral:
				it = this->write(_id.get<ULONGLONG>(), data, size); 
				break;
			case vfs::file_identifier_types::str:
			{
				it = this->write(_id.get<std::wstring>(), data, size);
			}
			break;
			default:
				throw std::exception("corrupted file type");
				//it = files.end();
			}
			return it != files.end();
		}
		else {
			OVERLAPPED ovl = {};
			auto enc = encryption.encrypt(std::vector<BYTE>((PBYTE)data, (PBYTE)data + size));
			switch (file.type()) {
			case vfs::file_identifier_types::integral:
			{
				*PULONGLONG(&ovl.Offset) = file.offset + sizeof(sFile_integral_ID);
			}
			break;
			case vfs::file_identifier_types::str:
			{
				*PULONGLONG(&ovl.Offset) = file.offset + sizeof(sFile_string_ID) + (file.get_id<std::wstring>().length() * sizeof(wchar_t));
			}
			break;
			default:
				throw std::exception("corrupted file type");
			}

			DWORD written;
			return ::WriteFile(hFile, enc.data(), enc.size(), &written, &ovl) == TRUE;
		}
	}

};
