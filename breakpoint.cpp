#include "breakpoint.hpp"
#include <iostream>
#include <array>
#include <cstring>

constexpr std::uint8_t bp[] = { 0x0F, 0x22, 0xD8 };

std::unordered_map<std::uintptr_t, std::array<std::uint8_t, sizeof(bp)>> original_instructions;

ZydisDecoder decoder;
ZydisFormatter formatter;

template <std::size_t N>
void safe_write_bytes(LPVOID address, const std::uint8_t(&bytes)[N])
{
    DWORD old_protect;
    VirtualProtect(address, N, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(address, bytes, N);
    VirtualProtect(address, N, old_protect, &old_protect);
}

template <std::size_t N>
void safe_restore_bytes(LPVOID address, const std::array<std::uint8_t, N>& bytes)
{
    DWORD old_protect;
    VirtualProtect(address, N, PAGE_EXECUTE_READWRITE, &old_protect);
    std::memcpy(address, bytes.data(), N);
    VirtualProtect(address, N, old_protect, &old_protect);
}

std::optional<std::string> cft::identify_function(std::uintptr_t function_address)
{
    static std::unordered_map<std::uintptr_t, std::string> name_map;

    auto name_map_iterator = name_map.find(function_address);
    if (name_map_iterator != name_map.end())
        return name_map_iterator->second;

    std::string name{};

    PROCESS_BASIC_INFORMATION basic_information;
    NtQueryInformationProcess(GetCurrentProcess(), PROCESSINFOCLASS::ProcessBasicInformation, &basic_information, sizeof(PROCESS_BASIC_INFORMATION), 0);

    LIST_ENTRY* module_list_start = &basic_information.PebBaseAddress->Ldr->InMemoryOrderModuleList;

    for (LIST_ENTRY* current_entry = module_list_start->Flink; current_entry != module_list_start; current_entry = current_entry->Flink)
    {
        auto current_module = reinterpret_cast<std::uintptr_t>(CONTAINING_RECORD(current_entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks)->DllBase);

        const auto dos_header = reinterpret_cast<IMAGE_DOS_HEADER*>(current_module);
        const auto nt_headers = reinterpret_cast<IMAGE_NT_HEADERS64*>(current_module + dos_header->e_lfanew);

        const auto export_directory = nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!export_directory.VirtualAddress || !export_directory.Size)
            continue;

        const auto export_table = *reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(current_module + export_directory.VirtualAddress);
        if (!export_table.NumberOfNames || !export_table.AddressOfNames)
            continue;

        auto functions = reinterpret_cast<DWORD*>(current_module + export_table.AddressOfFunctions);
        auto ordinals = reinterpret_cast<WORD*> (current_module + export_table.AddressOfNameOrdinals);
        auto names = reinterpret_cast<DWORD*>(current_module + export_table.AddressOfNames);

        for (std::uint16_t i{}; i < export_table.NumberOfNames; i++)
        {
            auto test_address = current_module + functions[ordinals[i]];
            auto test_name = std::string(reinterpret_cast<char*>(current_module + names[i]));

            name_map[test_address] = test_name;

            if (name.empty() && test_address == function_address)
                name = test_name;
        }
    }

    if (name.empty())
        return std::nullopt;

    return name;
}

bool is_control_flow(const ZydisDisassembledInstruction& instruction)
{
    switch (instruction.info.mnemonic)
    {
    case ZYDIS_MNEMONIC_CALL:
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_JMP:
    case ZYDIS_MNEMONIC_JZ:
    case ZYDIS_MNEMONIC_JNZ:
    case ZYDIS_MNEMONIC_JB:
    case ZYDIS_MNEMONIC_JBE:
    case ZYDIS_MNEMONIC_JO:
    case ZYDIS_MNEMONIC_JNO:
    case ZYDIS_MNEMONIC_JS:
    case ZYDIS_MNEMONIC_JNS:
    case ZYDIS_MNEMONIC_JP:
    case ZYDIS_MNEMONIC_JNP:
    case ZYDIS_MNEMONIC_JL:
    case ZYDIS_MNEMONIC_JLE:
    case ZYDIS_MNEMONIC_LOOP:
    case ZYDIS_MNEMONIC_LOOPE:
    case ZYDIS_MNEMONIC_LOOPNE:
    case ZYDIS_MNEMONIC_JCXZ:
    case ZYDIS_MNEMONIC_JECXZ:
    case ZYDIS_MNEMONIC_JRCXZ:
        return true;
    default:
        return false;
    }
}

bool is_function_end(const ZydisDisassembledInstruction& instruction)
{
    return instruction.info.mnemonic == ZYDIS_MNEMONIC_RET;
}

bool jmp_condition_is_met(ZydisDisassembledInstruction& instruction, _EXCEPTION_POINTERS* exception_info)
{
    auto flags = exception_info->ContextRecord->EFlags;
    switch (instruction.info.mnemonic)
    {
    case ZYDIS_MNEMONIC_JZ:
        return flags & 0x40;
    case ZYDIS_MNEMONIC_JNZ:
        return !(flags & 0x40);
    case ZYDIS_MNEMONIC_JB:
        return flags & 0x1;
    case ZYDIS_MNEMONIC_JNB:
        return !(flags & 0x1);
    case ZYDIS_MNEMONIC_JBE:
        return (flags & 0x1) || (flags & 0x40);
    case ZYDIS_MNEMONIC_JNBE:
        return !(flags & 0x1) && !(flags & 0x40);
    case ZYDIS_MNEMONIC_JO:
        return flags & 0x800;
    case ZYDIS_MNEMONIC_JNO:
        return !(flags & 0x800);
    case ZYDIS_MNEMONIC_JS:
        return flags & 0x80;
    case ZYDIS_MNEMONIC_JNS:
        return !(flags & 0x80);
    case ZYDIS_MNEMONIC_JP:
        return flags & 0x4;
    case ZYDIS_MNEMONIC_JNP:
        return !(flags & 0x4);
    case ZYDIS_MNEMONIC_JL:
    {
        bool sf = flags & 0x80;
        bool of = flags & 0x800;
        return sf != of;
    }
    case ZYDIS_MNEMONIC_JNL:
    {
        bool sf = flags & 0x80;
        bool of = flags & 0x800;
        return sf == of;
    }
    case ZYDIS_MNEMONIC_JLE:
    {
        bool zf = flags & 0x40;
        bool sf = flags & 0x80;
        bool of = flags & 0x800;
        return zf || (sf != of);
    }
    case ZYDIS_MNEMONIC_JNLE:
    {
        bool zf = flags & 0x40;
        bool sf = flags & 0x80;
        bool of = flags & 0x800;
        return !zf && (sf == of);
    }
    case ZYDIS_MNEMONIC_LOOP:
        return --exception_info->ContextRecord->Rcx != 0;
    case ZYDIS_MNEMONIC_LOOPE:
        return (--exception_info->ContextRecord->Rcx != 0) && (flags & 0x40);
    case ZYDIS_MNEMONIC_LOOPNE:
        return (--exception_info->ContextRecord->Rcx != 0) && !(flags & 0x40);
    case ZYDIS_MNEMONIC_JCXZ:
        return (exception_info->ContextRecord->Rcx & 0xFFFF) == 0;
    case ZYDIS_MNEMONIC_JECXZ:
        return (exception_info->ContextRecord->Rcx & 0xFFFFFFFF) == 0;
    case ZYDIS_MNEMONIC_JRCXZ:
        return exception_info->ContextRecord->Rcx == 0;
    default:
        return true;
    }
}

std::uintptr_t get_call_address(ZydisDisassembledInstruction& instruction, _EXCEPTION_POINTERS* exception_info)
{
    const auto& op = instruction.operands[0];
    std::uintptr_t addr{};

    if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
    {
        ZydisCalcAbsoluteAddress(&instruction.info, &op, instruction.runtime_address, &addr);
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_MEMORY)
    {
        ZydisCalcAbsoluteAddress(&instruction.info, &op, instruction.runtime_address, &addr);
    }
    else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
    {
        switch (op.reg.value)
        {
        case ZYDIS_REGISTER_RAX: addr = exception_info->ContextRecord->Rax; break;
        case ZYDIS_REGISTER_RCX: addr = exception_info->ContextRecord->Rcx; break;
        case ZYDIS_REGISTER_RDX: addr = exception_info->ContextRecord->Rdx; break;
        case ZYDIS_REGISTER_RBX: addr = exception_info->ContextRecord->Rbx; break;
        case ZYDIS_REGISTER_RSP: addr = exception_info->ContextRecord->Rsp; break;
        case ZYDIS_REGISTER_RBP: addr = exception_info->ContextRecord->Rbp; break;
        case ZYDIS_REGISTER_RSI: addr = exception_info->ContextRecord->Rsi; break;
        case ZYDIS_REGISTER_RDI: addr = exception_info->ContextRecord->Rdi; break;
        case ZYDIS_REGISTER_R8:  addr = exception_info->ContextRecord->R8;  break;
        case ZYDIS_REGISTER_R9:  addr = exception_info->ContextRecord->R9;  break;
        case ZYDIS_REGISTER_R10: addr = exception_info->ContextRecord->R10; break;
        case ZYDIS_REGISTER_R11: addr = exception_info->ContextRecord->R11; break;
        case ZYDIS_REGISTER_R12: addr = exception_info->ContextRecord->R12; break;
        case ZYDIS_REGISTER_R13: addr = exception_info->ContextRecord->R13; break;
        case ZYDIS_REGISTER_R14: addr = exception_info->ContextRecord->R14; break;
        case ZYDIS_REGISTER_R15: addr = exception_info->ContextRecord->R15; break;
        }
    }

    return addr;
}

void handle_debugging(ZydisDisassembledInstruction& instruction, _EXCEPTION_POINTERS* exception_info)
{
    std::println("VK_UP step over / VK_DOWN step into");

    while (true)
    {
        if (GetAsyncKeyState(VK_UP))
        {
            while (GetAsyncKeyState(VK_UP))
                Sleep(10);
            break;
        }

        if (GetAsyncKeyState(VK_DOWN))
        {
            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
                cft::bp_function(get_call_address(instruction, exception_info));

            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
                cft::bp_function(*reinterpret_cast<std::uintptr_t*>(exception_info->ContextRecord->Rsp));

            while (GetAsyncKeyState(VK_DOWN))
                Sleep(10);
            break;
        }
    }
}

std::int32_t exception_handler(_EXCEPTION_POINTERS* exception_info)
{
    if (exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;

    auto current_instruction_address = exception_info->ExceptionRecord->ExceptionAddress;
    auto addr_key = reinterpret_cast<std::uintptr_t>(current_instruction_address);

    auto it = original_instructions.find(addr_key);
    if (it == original_instructions.end())
        return EXCEPTION_CONTINUE_SEARCH;

    static LPVOID previous_instruction_address = nullptr;

    if (previous_instruction_address && previous_instruction_address != current_instruction_address)
        safe_write_bytes(previous_instruction_address, bp);

    safe_restore_bytes(current_instruction_address, it->second);

    ZydisDisassembledInstruction current_instruction{};
    ZydisDisassembleIntel(
        ZYDIS_MACHINE_MODE_LONG_64,
        addr_key,
        reinterpret_cast<const void*>(current_instruction_address),
        ZYDIS_MAX_OPERAND_COUNT,
        &current_instruction);

    if (is_control_flow(current_instruction))
    {
        if (jmp_condition_is_met(current_instruction, exception_info))
        {
            std::println("\nBreakpoint Hit: 0x{:X}", addr_key);

            dumper::add_line("\n\n\n\n<dump>");

            dumper::dump_regs(exception_info);

            std::print("{}", current_instruction.text);
            dumper::add_line("<ins>");
            dumper::add_line(std::format("{}", current_instruction.text));
            dumper::add_line("</ins>");

            if (current_instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
            {
                auto call_target = get_call_address(current_instruction, exception_info);
                auto function_addr = *reinterpret_cast<std::uintptr_t*>(call_target);
                auto function_id = cft::identify_function(function_addr);

                if (function_id.has_value())
                {
                    std::print(" -> {}", function_id.value());
                    dumper::add_line("<func_name>");
                    dumper::add_line(std::format("{}", function_id.value()));
                    dumper::add_line("</func_name>");
                }

                cft::add_bp(current_instruction.runtime_address + current_instruction.info.length);
            }

            std::println("");
            dumper::add_line("</dump>");

            if (cft::is_debugging)
                handle_debugging(current_instruction, exception_info);
        }
        else
        {
            dumper::add_line("\n\n\n\n<path_not_taken>");
            dumper::dump_regs(exception_info);
            dumper::add_line("<ins>");
            dumper::add_line(std::format("{}", current_instruction.text));
            dumper::add_line("</ins>");
            dumper::add_line("</path_not_taken>");
        }
    }
    else
    {
        dumper::add_line("\n\n\n\n<returned>");
        dumper::dump_regs(exception_info);
        dumper::add_line("</returned>");
    }

    previous_instruction_address = current_instruction_address;

    return EXCEPTION_CONTINUE_EXECUTION;
}

void cft::init(bool debug)
{
    cft::is_debugging = debug;

    dumper::init();

    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(&exception_handler));
}

void cft::add_bp(std::uintptr_t instruction_address)
{
    if (original_instructions.contains(instruction_address))
        return;

    std::array<std::uint8_t, sizeof(bp)> saved{};
    std::memcpy(saved.data(), reinterpret_cast<const void*>(instruction_address), sizeof(bp));
    original_instructions.emplace(instruction_address, saved);

    safe_write_bytes(reinterpret_cast<LPVOID>(instruction_address), bp);
}

void cft::dump_function(std::uintptr_t function_address)
{
    ZydisDisassembledInstruction current_instruction{};
    std::size_t offset{};

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        ZYDIS_MACHINE_MODE_LONG_64,
        function_address + offset,
        reinterpret_cast<const void*>(function_address + offset),
        ZYDIS_MAX_OPERAND_COUNT,
        &current_instruction)))
    {
        std::println("{}", current_instruction.text);
        offset += current_instruction.info.length;

        if (is_function_end(current_instruction))
            return;
    }
}

void cft::bp_function(std::uintptr_t function_address)
{
    if (!function_address)
        return;

    ZydisDisassembledInstruction current_instruction{};
    std::size_t offset{};

    while (ZYAN_SUCCESS(ZydisDisassembleIntel(
        ZYDIS_MACHINE_MODE_LONG_64,
        function_address + offset,
        reinterpret_cast<const void*>(function_address + offset),
        ZYDIS_MAX_OPERAND_COUNT,
        &current_instruction)))
    {
        if (is_control_flow(current_instruction))
        {
            cft::add_bp(current_instruction.runtime_address);
            std::println("Breakpoint added at 0x{:X} {}", current_instruction.runtime_address, current_instruction.text);
        }

        offset += current_instruction.info.length;

        if (is_function_end(current_instruction))
            return;
    }
}