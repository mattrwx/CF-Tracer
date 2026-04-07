#pragma once
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <optional>
#include <print>
#include <unordered_map>

#define ZYDIS_STATIC_BUILD
#include "Zydis/Zydis.h"

#include "dump.hpp"




namespace cft
{
	inline bool is_debugging = false;

	void init(bool debug = false);

	void add_bp(std::uintptr_t instruction_address);

	std::optional<std::string> identify_function(std::uintptr_t function_address);

	void dump_function(std::uintptr_t function_address);

	void bp_function(std::uintptr_t function_address);
}