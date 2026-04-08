#include <Windows.h>
#include <iostream>
#include "cft.hpp"

#pragma optimize("", off)
bool messaged{};
void __declspec(noinline) c(int x)
{
    Beep(100, 100);

    if (x > 10)
        volatile int y = x * 2;
    else
        volatile int y = x + 1;
}

void __declspec(noinline) b(int x)
{
    Beep(100, 100);

    if (x % 2 == 0)
        c(x);
    else
        c(x + 1);
}

void __declspec(noinline) a()
{
    Beep(100, 100);

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


        cft::init(5);

        cft::bp_function(&a);

        a();

        MessageBoxA(0, "Complete!", 0, 0);
    }

    return TRUE;
}
