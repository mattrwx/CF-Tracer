#include "dumper.hpp"



void dumper::dump(std::string instruction, void* next_address, bool jmp_taken, const _EXCEPTION_POINTERS* exception_info)
{
	static std::ofstream file("dump.cfd", std::ios::out);

    file << instruction << "|";
    file << reinterpret_cast<std::uintptr_t>(next_address) << "|";
    file << jmp_taken << "|";

    file << std::hex;
    file << exception_info->ContextRecord->Rax << "|";
    file << exception_info->ContextRecord->Rbx << "|";
    file << exception_info->ContextRecord->Rcx << "|";
    file << exception_info->ContextRecord->Rdx << "|";
    file << exception_info->ContextRecord->Rsi << "|";
    file << exception_info->ContextRecord->Rdi << "|";
    file << exception_info->ContextRecord->Rbp << "|";
    file << exception_info->ContextRecord->Rsp << "|";

    file << exception_info->ContextRecord->R8 << "|";
    file << exception_info->ContextRecord->R9 << "|";
    file << exception_info->ContextRecord->R10 << "|";
    file << exception_info->ContextRecord->R11 << "|";
    file << exception_info->ContextRecord->R12 << "|";
    file << exception_info->ContextRecord->R13 << "|";
    file << exception_info->ContextRecord->R14 << "|";
    file << exception_info->ContextRecord->R15 << "|";

    file << exception_info->ContextRecord->Rip << "|";
    file << exception_info->ContextRecord->EFlags << "|";

    file << exception_info->ContextRecord->SegCs << "|";
    file << exception_info->ContextRecord->SegDs << "|";
    file << exception_info->ContextRecord->SegEs << "|";
    file << exception_info->ContextRecord->SegFs << "|";
    file << exception_info->ContextRecord->SegGs << "|";
    file << exception_info->ContextRecord->SegSs << "|";

    file << exception_info->ContextRecord->Dr0 << "|";
    file << exception_info->ContextRecord->Dr1 << "|";
    file << exception_info->ContextRecord->Dr2 << "|";
    file << exception_info->ContextRecord->Dr3 << "|";
    file << exception_info->ContextRecord->Dr6 << "|";
    file << exception_info->ContextRecord->Dr7;

    file << std::endl;
}
