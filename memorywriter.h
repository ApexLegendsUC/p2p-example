#pragma once

class MemoryWriter {
public:
	void write(LPCVOID data, size_t size);
	void reserve(size_t size) { data.reserve(size); };
	std::vector<BYTE>& get_data() { return data; };
	void clear() { data.clear(); };
private:
	std::vector<BYTE> data;
};