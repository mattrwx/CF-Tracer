#include <Windows.h>
#include <iostream>
#include "cft.hpp"

#pragma optimize("", off)
void c(int x)
{
    if (x > 10)
        volatile int y = x * 2;
    else
        volatile int y = x + 1;
    
    std::println("I am in C");
}

void b(int x)
{
    if (x % 2 == 0)
        c(x);
    else
        c(x + 1);
}

void a()
{
    for (int i = 0; i < 5; i++)
        b(i);
}
#pragma optimize("", on)

bool APIENTRY DllMain(HMODULE h_module, std::uint32_t reason_for_call, std::uintptr_t)
{
    if (reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(h_module);

        AllocConsole();

        FILE* f;
        freopen_s(&f, "CONOUT$", "w", stdout);


        cft::init();

        cft::bp_function(&b, 5);

        b(10);
    }

    return TRUE;
}