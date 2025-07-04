#include "utils.h"

namespace utils {

    void getModuleBaseAddressW(IN DWORD pid, IN const wchar_t* moduleName, OUT BYTE** const moduleBase) {

        if (!moduleName || !pid || !moduleBase) return;
        *moduleBase = nullptr;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid); 

        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        MODULEENTRY32W modEntry;
        modEntry.dwSize = sizeof(MODULEENTRY32W);

        if (!Module32First(hSnapshot, &modEntry)) {
            CloseHandle(hSnapshot);
            return;
        }

        do
        {

            if (modEntry.modBaseAddr && _wcsicmp(modEntry.szModule, moduleName) == 0) {

                *moduleBase = modEntry.modBaseAddr;
                CloseHandle(hSnapshot);
                return;
            }

        } while (Module32NextW(hSnapshot, &modEntry));


        CloseHandle(hSnapshot);
    }

    void getProcessId(IN wchar_t* processExecutableName, OUT DWORD* const pid) {

        *pid = 0;
        if (!processExecutableName || !pid) return;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

        
        
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            return;
        }

        PROCESSENTRY32W modEntry;
        modEntry.dwSize = sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(hSnapshot, &modEntry)) {
            CloseHandle(hSnapshot);
            return;
        }

        do
        {

            if (_wcsicmp(modEntry.szExeFile, processExecutableName) == 0) {
                *pid = modEntry.th32ProcessID;
                CloseHandle(hSnapshot);
                return;
            }
                



        } while (Process32NextW(hSnapshot, &modEntry));


        CloseHandle(hSnapshot);
        return;

    }

}
