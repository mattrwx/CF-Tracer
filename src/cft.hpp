#pragma once
#include <Windows.h>
#include <array>
#include <iostream>
#include <optional>
#include <print>
#include <psapi.h>
#include <stack>
#include <unordered_map>
#include <vector>
#include <winternl.h>

#ifndef ZYDIS_STATIC_BUILD
#define ZYDIS_STATIC_BUILD
#endif

#include "Zydis/Zydis.h"

#include "dumper.hpp"
#include "eeh.hpp"

namespace cft
{
    void init(void* start);

    void cleanup();
} // namespace cft
