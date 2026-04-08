#pragma once
#include <Windows.h>
#include <iostream>
#include <psapi.h>
#include <winternl.h>
#include <vector>
#include <optional>
#include <print>
#include <unordered_map>
#include <array>
#include <stack>

#define ZYDIS_STATIC_BUILD
#include "Zydis/Zydis.h"

#include "dumper.hpp"

namespace cft
{
	void init(std::uint16_t max_recurse_depth);

	void bp_function(const void* address);

	void cleanup();
}
