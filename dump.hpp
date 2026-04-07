#pragma once
#include <Windows.h>
#include <fstream>
#include <format>



namespace dumper
{
	void init();

	void add_line(std::string_view line);
	
	void dump_regs(EXCEPTION_POINTERS* exception_info);
}