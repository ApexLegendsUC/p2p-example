#include <Windows.h>
#include <vector>
#include "memorywriter.h"

void MemoryWriter::write(LPCVOID lpcData, size_t size)
{
	if (lpcData == nullptr) {
		if (size)
			throw std::exception("Attempted to write nullptr with size.");
		return;
	}
	data.insert(data.end(), (PBYTE)lpcData, (PBYTE)lpcData + size);
	//auto o = data.size();
	//data.resize(o + size);
	//memcpy(&data[o], lpcData, size);
}