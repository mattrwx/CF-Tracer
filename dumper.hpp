#include <Windows.h>
#include <fstream>

namespace dumper
{
	void dump(std::string instruction, void* next_address, bool jmp_taken, const _EXCEPTION_POINTERS* exception_info);
}
