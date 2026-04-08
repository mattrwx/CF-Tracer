#include <Windows.h>
#include <iostream>
#include <thread>
#include "cft.hpp"

#pragma optimize("", off)
bool messaged{};
void __declspec(noinline) c(int x)
{
    if (!messaged)
    {
        messaged = true;
        MessageBoxA(0, "Boi", 0, 0);
    }
    if (x > 10)
        volatile int y = x * 2;
    else
        volatile int y = x + 1;
}

void __declspec(noinline) b(int x)
{
    if (x % 2 == 0)
        c(x);
    else
        c(x + 1);
}

void __declspec(noinline) a()
{
    for (int i = 0; i < 5; i++)
        b(i);
}
#pragma optimize("", on)


// Had to create a thread for the benchmark to make unloading straight forward
void benchmark(HMODULE h_module)
{
    AllocConsole();

    FILE* f;
    freopen_s(&f, "CONOUT$", "w", stdout);

    cft::init(20);
    cft::bp_function(&a);
    a();
    cft::cleanup();
    MessageBoxA(0, "Complete!", 0, 0);

    FreeConsole();
    FreeLibraryAndExitThread(h_module, 0);
}

bool APIENTRY DllMain(HMODULE h_module, std::uint32_t reason_for_call, std::uintptr_t)
{
    if (reason_for_call == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(h_module);
        std::thread(benchmark, h_module).detach();
    }

    return true;
}
