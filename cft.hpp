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
#include <winternl.h>

#define ZYDIS_STATIC_BUILD
#include "Zydis/Zydis.h"

#include "dumper.hpp"

namespace cft
{
	enum hook_type
	{
		veh,
		wow64
	};

	void init(void* start, hook_type hooking_method);

	void cleanup();
}
