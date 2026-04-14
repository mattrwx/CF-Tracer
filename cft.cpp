#include "cft.hpp"

bool print_bp_function = false;

namespace cft
{
    // Zydis globals for disassembly
    ZydisDecoder decoder;
    ZydisFormatter formatter;

    // mov <control register> <- privledged instruction: will always cause exception in usermode
    // Why use this over int 3? Because anti-debugger routines will typically pick up on that
    constexpr std::array<std::uint8_t, 2> faulting_ins = { 0x0F, 0x22 };

    // Map containing address -> original bytes
    std::unordered_map<void*, std::array<std::uint8_t, sizeof(faulting_ins)>> orig_ins_map;

    namespace helper
    {
        // ZydisDisassembleIntel wrapper
        ZydisDisassembledInstruction get_ins(void* address)
        {
            ZydisDisassembledInstruction ins{};
            if (ZYAN_SUCCESS(ZydisDisassembleIntel(
                ZYDIS_MACHINE_MODE_LONG_64,
                reinterpret_cast<std::uintptr_t>(address),
                address,
                ZYDIS_MAX_OPERAND_COUNT,
                &ins)))
                return ins;

            return {};
        }

        // Searches for function name in every module's exports.
        std::optional<std::string> identify_function(void* function_address)
        {
            // This map will act as a export name cache. We don't want to walk every single module's exports
            // every time we want to identify a function
            static std::unordered_map<void*, std::string> name_map;

            // Query cache
            auto it = name_map.find(function_address);

            // Handle cache hit
            if (it != name_map.end())
                return it->second;

            // Handle cache miss

            // This will be filled in as the function name if it is found
            std::string name{};

            // Not going to comment this whole function, but we are manually fetching the module list from the
            // PEB and walking their export tables. Filling the cache on the way in case a new module has appeared etc
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
                    auto test_address = reinterpret_cast<void*>(current_module + functions[ordinals[i]]);
                    auto test_name = std::string(reinterpret_cast<char*>(current_module + names[i]));

                    name_map[test_address] = test_name;

                    if (name.empty() && test_address == function_address)
                        name = test_name;
                }
            }

            // If we don't find the function, return std::nullopt
            if (name.empty())
                return std::nullopt;

            // In the case that we find it :p
            return name;
        }

        // Will return call address, nullptr if unresolvable
        void* get_call_address(const ZydisDisassembledInstruction& instruction, const _CONTEXT* ctx = nullptr)
        {
            const auto& op = instruction.operands[0];
            std::uintptr_t addr{};

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE || op.type == ZYDIS_OPERAND_TYPE_MEMORY)
            {
                ZydisCalcAbsoluteAddress(&instruction.info, &op, instruction.runtime_address, &addr);

                if (op.type == ZYDIS_OPERAND_TYPE_MEMORY && op.mem.base == ZYDIS_REGISTER_RIP)
                    addr = *reinterpret_cast<uintptr_t*>(addr);
            }

            else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER && ctx)
                switch (op.reg.value)
                {
                case ZYDIS_REGISTER_RAX: addr = ctx->Rax; break;
                case ZYDIS_REGISTER_RCX: addr = ctx->Rcx; break;
                case ZYDIS_REGISTER_RDX: addr = ctx->Rdx; break;
                case ZYDIS_REGISTER_RBX: addr = ctx->Rbx; break;
                case ZYDIS_REGISTER_RSP: addr = ctx->Rsp; break;
                case ZYDIS_REGISTER_RBP: addr = ctx->Rbp; break;
                case ZYDIS_REGISTER_RSI: addr = ctx->Rsi; break;
                case ZYDIS_REGISTER_RDI: addr = ctx->Rdi; break;
                case ZYDIS_REGISTER_R8:  addr = ctx->R8;  break;
                case ZYDIS_REGISTER_R9:  addr = ctx->R9;  break;
                case ZYDIS_REGISTER_R10: addr = ctx->R10; break;
                case ZYDIS_REGISTER_R11: addr = ctx->R11; break;
                case ZYDIS_REGISTER_R12: addr = ctx->R12; break;
                case ZYDIS_REGISTER_R13: addr = ctx->R13; break;
                case ZYDIS_REGISTER_R14: addr = ctx->R14; break;
                case ZYDIS_REGISTER_R15: addr = ctx->R15; break;
                default: return nullptr;
                }

            else
                return nullptr;
            
            return reinterpret_cast<void*>(addr);
        }

        // Returns the target address of any jmp if taken, otherwise nullptr
        void* get_jmp_address(const ZydisDisassembledInstruction& instruction, const _EXCEPTION_POINTERS* exception_info)
        {
            const auto mnemonic = instruction.info.mnemonic;
            const auto flags = exception_info->ContextRecord->EFlags;
            const auto ctx = exception_info->ContextRecord;

            bool taken = false;
            switch (mnemonic)
            {
            case ZYDIS_MNEMONIC_JMP:    taken = true; break;
            case ZYDIS_MNEMONIC_JZ:     taken = flags & 0x40; break;
            case ZYDIS_MNEMONIC_JNZ:    taken = !(flags & 0x40); break;
            case ZYDIS_MNEMONIC_JB:     taken = flags & 0x1; break;
            case ZYDIS_MNEMONIC_JNB:    taken = !(flags & 0x1); break;
            case ZYDIS_MNEMONIC_JBE:    taken = (flags & 0x1) || (flags & 0x40); break;
            case ZYDIS_MNEMONIC_JNBE:   taken = !(flags & 0x1) && !(flags & 0x40); break;
            case ZYDIS_MNEMONIC_JO:     taken = flags & 0x800; break;
            case ZYDIS_MNEMONIC_JNO:    taken = !(flags & 0x800); break;
            case ZYDIS_MNEMONIC_JS:     taken = flags & 0x80; break;
            case ZYDIS_MNEMONIC_JNS:    taken = !(flags & 0x80); break;
            case ZYDIS_MNEMONIC_JP:     taken = flags & 0x4; break;
            case ZYDIS_MNEMONIC_JNP:    taken = !(flags & 0x4); break;
            case ZYDIS_MNEMONIC_JL:     taken = (bool)(flags & 0x80) != (bool)(flags & 0x800); break;
            case ZYDIS_MNEMONIC_JNL:    taken = (bool)(flags & 0x80) == (bool)(flags & 0x800); break;
            case ZYDIS_MNEMONIC_JLE:    taken = (flags & 0x40) || ((bool)(flags & 0x80) != (bool)(flags & 0x800)); break;
            case ZYDIS_MNEMONIC_JNLE:   taken = !(flags & 0x40) && ((bool)(flags & 0x80) == (bool)(flags & 0x800)); break;
            case ZYDIS_MNEMONIC_LOOP:   taken = --ctx->Rcx != 0; break;
            case ZYDIS_MNEMONIC_LOOPE:  taken = (--ctx->Rcx != 0) && (flags & 0x40); break;
            case ZYDIS_MNEMONIC_LOOPNE: taken = (--ctx->Rcx != 0) && !(flags & 0x40); break;
            case ZYDIS_MNEMONIC_JCXZ:   taken = (ctx->Rcx & 0xFFFF) == 0; break;
            case ZYDIS_MNEMONIC_JECXZ:  taken = (ctx->Rcx & 0xFFFFFFFF) == 0; break;
            case ZYDIS_MNEMONIC_JRCXZ:  taken = ctx->Rcx == 0; break;
            default: return nullptr;
            }

            if (!taken)
                return nullptr;

            const auto& op = instruction.operands[0];
            std::uintptr_t addr{};

            if (op.type == ZYDIS_OPERAND_TYPE_IMMEDIATE || op.type == ZYDIS_OPERAND_TYPE_MEMORY)
                ZydisCalcAbsoluteAddress(&instruction.info, &op, instruction.runtime_address, &addr);

            else if (op.type == ZYDIS_OPERAND_TYPE_REGISTER)
                switch (op.reg.value)
                {
                case ZYDIS_REGISTER_RAX: addr = ctx->Rax; break;
                case ZYDIS_REGISTER_RCX: addr = ctx->Rcx; break;
                case ZYDIS_REGISTER_RDX: addr = ctx->Rdx; break;
                case ZYDIS_REGISTER_RBX: addr = ctx->Rbx; break;
                case ZYDIS_REGISTER_RSP: addr = ctx->Rsp; break;
                case ZYDIS_REGISTER_RBP: addr = ctx->Rbp; break;
                case ZYDIS_REGISTER_RSI: addr = ctx->Rsi; break;
                case ZYDIS_REGISTER_RDI: addr = ctx->Rdi; break;
                case ZYDIS_REGISTER_R8:  addr = ctx->R8;  break;
                case ZYDIS_REGISTER_R9:  addr = ctx->R9;  break;
                case ZYDIS_REGISTER_R10: addr = ctx->R10; break;
                case ZYDIS_REGISTER_R11: addr = ctx->R11; break;
                case ZYDIS_REGISTER_R12: addr = ctx->R12; break;
                case ZYDIS_REGISTER_R13: addr = ctx->R13; break;
                case ZYDIS_REGISTER_R14: addr = ctx->R14; break;
                case ZYDIS_REGISTER_R15: addr = ctx->R15; break;
                default: return nullptr;
                }

            return reinterpret_cast<void*>(addr);
        }

        // Will return address that control flow will be at next
        void* get_next_address(const ZydisDisassembledInstruction& instruction, const _EXCEPTION_POINTERS* exception_info, std::string out_string)
        {
            // ret
            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_RET)
                return *reinterpret_cast<void**>(exception_info->ContextRecord->Rsp);

            // call
            if (instruction.info.mnemonic == ZYDIS_MNEMONIC_CALL)
            {
                auto call_addr = get_call_address(instruction, exception_info->ContextRecord);

                // If its a call instruction, we want to check if there is a name we can put instead of the address
                auto function_name = helper::identify_function(call_addr);

                if (function_name.has_value())
                {
                    out_string = std::format("call {}", function_name.value());

                    return reinterpret_cast<void*>(instruction.runtime_address + instruction.info.length);
                }

                return call_addr;
            }

            // jmp taken
            if (void* jmp = get_jmp_address(instruction, exception_info))
                return jmp;

            // jmp not taken
            return reinterpret_cast<void*>(instruction.runtime_address + instruction.info.length);
        }

        // std::memcpy wrapper that ensures writing permissions
        template <std::size_t size>
        void safe_copy(void* address, const std::array<std::uint8_t, size>& bytes)
        {
            DWORD old_protect;

            // We have to ensure that the page is writable, the chances of it being writable by default is close to zero since we are overwriting code.
            VirtualProtect(address, size, PAGE_EXECUTE_READWRITE, &old_protect);

            std::memcpy(reinterpret_cast<void*>(address), bytes.data(), size);

            // We don't want to leave it RWX because that would probably fail any base level anti-tamper checks.
            VirtualProtect(address, size, old_protect, &old_protect);
        }

        // Will return true if instruction is a control flow instruction
        // Any extra instructions that you want to BP should be put in this list
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

        // As of right now, I am just deciding that the ret is the function end.
        // Is this a good metric of identifying the end of a function? Of course not.
        bool is_function_end(const ZydisDisassembledInstruction& instruction)
        {
            return instruction.info.mnemonic == ZYDIS_MNEMONIC_RET;
        }
    
        // Fetch control flow changing instruction
        void* fetch_next_target(void* addr)
        {
            auto current_ins = get_ins(addr);

            while (true)
            {
                current_ins = get_ins(reinterpret_cast<void*>(current_ins.runtime_address + current_ins.info.length));

                if (is_control_flow(current_ins))
                    return reinterpret_cast<void*>(current_ins.runtime_address);
            }
        }
}

    // Not only add the bp code, but will also log it in the map.
    void place_bp(void* address)
    {
        std::array<std::uint8_t, sizeof(faulting_ins)> saved{};
        std::memcpy(saved.data(), address, sizeof(faulting_ins));

        if (!orig_ins_map.contains(address))
            orig_ins_map.insert({ address, saved });

        helper::safe_copy(address, faulting_ins);
    }

    // This is where the magic happens :p
    std::int32_t exception_handler(const _EXCEPTION_POINTERS* exception_info)
    {
        // Skipping unrelated exceptions.
        // Another benefit to using mov <control register> is that a privledged instruction exception is very rare.
        // If you make your exception something less unique, lets say a access violation, you will have
        // to rely on the fact that the faulting address is not in the orig_ins_map and will be skipped regardless.
        if (exception_info->ExceptionRecord->ExceptionCode != EXCEPTION_PRIV_INSTRUCTION)
            return EXCEPTION_CONTINUE_SEARCH;

        // We are constantly interacting with this so lets shorten the name.
        auto curr_ins_addr = exception_info->ExceptionRecord->ExceptionAddress;

        // Get the original bytes from our map
        auto it = orig_ins_map.find(curr_ins_addr);

        // If the iterator is at the end, it means we haven't found our faulting address in the orig_ins_map.
        // This either means some sort of bug has occured, or more likely that the exception was not ours.
        // In the case of mov <control register>, we can imagine this would be quite rare but still very important.
        if (it == orig_ins_map.end())
            return EXCEPTION_CONTINUE_SEARCH;

        // Copy original code into current instruction
        helper::safe_copy(curr_ins_addr, it->second);

        // Get ZydisDisassembledInstruction of current instruction (breakpoint)
        auto bp_ins = helper::get_ins(curr_ins_addr);

        // instruction string for dump
        std::string out_string = bp_ins.text;

        // next instruction after bp
        auto next_address = helper::get_next_address(bp_ins, exception_info, out_string);

        // next cf instruction 
        auto next_target = helper::fetch_next_target(next_address);

        if (out_string.empty())
            out_string = bp_ins.text;

        std::println("{}", out_string);
        dumper::dump(out_string, exception_info);

        // place bp at target
        place_bp(next_target);

        return EXCEPTION_CONTINUE_EXECUTION;
    }

    void init(void* start)
    {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
        ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

        AddVectoredExceptionHandler(TRUE, reinterpret_cast<PVECTORED_EXCEPTION_HANDLER>(&exception_handler));

        place_bp(start);
    }

    // Remove all breakpoints
    void cleanup()
    {
        for (auto it = orig_ins_map.begin(); it != orig_ins_map.end(); it++)
            helper::safe_copy(it->first, it->second);

        RemoveVectoredExceptionHandler(&exception_handler);
    }
}
