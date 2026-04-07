#include "dump.hpp"


std::ofstream file;


void dumper::init()
{
	file.open("dump.txt");
}

void dumper::add_line(std::string_view line)
{
	file << reinterpret_cast<const char*>(line.data()) << std::endl;
}


void dumper::dump_regs(EXCEPTION_POINTERS* exception_info)
{
	dumper::add_line("<regs>");

	dumper::add_line(std::format("RAX: {:016X}", exception_info->ContextRecord->Rax));
	dumper::add_line(std::format("RBX: {:016X}", exception_info->ContextRecord->Rbx));
	dumper::add_line(std::format("RCX: {:016X}", exception_info->ContextRecord->Rcx));
	dumper::add_line(std::format("RDX: {:016X}", exception_info->ContextRecord->Rdx));
	dumper::add_line(std::format("RSI: {:016X}", exception_info->ContextRecord->Rsi));
	dumper::add_line(std::format("RDI: {:016X}", exception_info->ContextRecord->Rdi));
	dumper::add_line(std::format("RBP: {:016X}", exception_info->ContextRecord->Rbp));
	dumper::add_line(std::format("RSP: {:016X}", exception_info->ContextRecord->Rsp));

	dumper::add_line(std::format("R8 : {:016X}", exception_info->ContextRecord->R8));
	dumper::add_line(std::format("R9 : {:016X}", exception_info->ContextRecord->R9));
	dumper::add_line(std::format("R10: {:016X}", exception_info->ContextRecord->R10));
	dumper::add_line(std::format("R11: {:016X}", exception_info->ContextRecord->R11));
	dumper::add_line(std::format("R12: {:016X}", exception_info->ContextRecord->R12));
	dumper::add_line(std::format("R13: {:016X}", exception_info->ContextRecord->R13));
	dumper::add_line(std::format("R14: {:016X}", exception_info->ContextRecord->R14));
	dumper::add_line(std::format("R15: {:016X}", exception_info->ContextRecord->R15));

	dumper::add_line(std::format("RIP: {:016X}", exception_info->ContextRecord->Rip));
	dumper::add_line(std::format("EFLAGS: {:08X}", exception_info->ContextRecord->EFlags));

	dumper::add_line("</regs>");
}