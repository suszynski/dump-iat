#pragma once
#include <Windows.h>
#include <TlHelp32.h>

namespace utils {

    void getModuleBaseAddressW(IN DWORD pid, IN const wchar_t* moduleName, OUT BYTE** moduleBase);
    void getProcessId(IN wchar_t* processExecutableName, OUT DWORD* pid);
}