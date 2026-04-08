#include <Windows.h>
#include <iostream>
#include <fstream>

#define ZYDIS_STATIC_BUILD
#include "Zydis/Zydis.h"





namespace dumper
{
	void dump(std::string instruction, void* next_address, bool jmp_taken, const _EXCEPTION_POINTERS* exception_info);
}
