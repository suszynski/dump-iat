#include "IATDumper.h"

//
// IATSTATUS::UNSUPPORTED_ARCHITECTURE
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
// IATSTATUS::INVALID_PID
// IATSTATUS::INVALID_MODULE_BASE
// 
IATSTATUS IATDumper::configure() {

    // set the m_hProcess

    m_hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, m_ProcessId);

    

    if (!m_hProcess)
        return IATSTATUS::INVALID_PID;

    // set the m_isProcess64Bit flag

    IATSTATUS status1 = _isProcess64Bit();

    if (status1 != IATSTATUS::STATUS_TRUE && status1 != IATSTATUS::STATUS_FALSE)
        return status1;

    m_isProcess64Bit = (status1 == IATSTATUS::STATUS_TRUE);

    // select valid offsets for the modules bitness

    if (m_isProcess64Bit)
        m_offsets = PELayout::forPE64();
    else
        m_offsets = PELayout::forPE32();


    // set the m_moduleBase

    if (!m_moduleBase) {

        IATSTATUS status2;

        if (m_moduleName.has_value())
            status2 = _setModuleBaseByName();
        
        else // defaults to executable if no module name specified in a constructor
            status2 = _setExecutableModuleBase();

        if (status2 != IATSTATUS::SUCCESS)
            return status2;

    }
    else { // check if the manual passed moduleBase points to a valid PE file. (only checks for ms-dos signature cause im lazy)

        constexpr std::uint16_t DOS_e_magic = 0x5A4D;

        std::uint16_t possible_e_magic;

        if (!_readMemory(m_moduleBase, &possible_e_magic))
            return IATSTATUS::FAILURE;

        if (possible_e_magic != DOS_e_magic)
            return IATSTATUS::INVALID_MODULE_BASE;
    }

    // set m_IDT
    status1 = _setImportDescriptorTableBase();

    if (status1 != IATSTATUS::SUCCESS)
        return status1;

    return IATSTATUS::SUCCESS;

}


//
// IATSTATUS_UNSUPPORTED_ARCHITECTURE
// IATSTATUS_FALSE
// IATSTATUS_TRUE
// IAT_STATUS_FAILURE
// 
IATSTATUS IATDumper::_isProcess64Bit() {

    USHORT ProcessMachine;
    USHORT NativeMachine;

    if (!IsWow64Process2(m_hProcess, &ProcessMachine, &NativeMachine)) // TODO: Add IsWow64Process() check as well for older machines
        return IATSTATUS::FAILURE;

    if ((NativeMachine != IMAGE_FILE_MACHINE_I386 && NativeMachine != IMAGE_FILE_MACHINE_AMD64) ||
        (ProcessMachine != IMAGE_FILE_MACHINE_I386 && ProcessMachine != IMAGE_FILE_MACHINE_AMD64 && ProcessMachine != IMAGE_FILE_MACHINE_UNKNOWN)) // Only x86 and x86-64 is supported. No ARM -> can be changed later
        return IATSTATUS::UNSUPPORTED_ARCHITECTURE;


    BOOL isMachine64Bit = (NativeMachine == IMAGE_FILE_MACHINE_AMD64);

    if (!isMachine64Bit)
        return IATSTATUS::STATUS_FALSE;

    return IATSTATUS::STATUS_TRUE;
}
//
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
// IATSTATUS::MODULE_NOT_FOUND
//
IATSTATUS IATDumper::_getModuleBaseByName(std::wstring_view moduleName, uintptr_t& OUTmoduleBase) {


    if (moduleName.empty()) return IATSTATUS::FAILURE;


    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_ProcessId);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return IATSTATUS::FAILURE;


    MODULEENTRY32W modEntry;
    modEntry.dwSize = sizeof(MODULEENTRY32W);

    if (!Module32First(hSnapshot, &modEntry)) {
        CloseHandle(hSnapshot);
        return IATSTATUS::FAILURE;
    }

    do
    {

        if (modEntry.modBaseAddr && _wcsicmp(modEntry.szModule, moduleName.data()) == 0) {

            OUTmoduleBase = (uintptr_t)modEntry.modBaseAddr;
            CloseHandle(hSnapshot);
            return IATSTATUS::SUCCESS;
        }

    } while (Module32NextW(hSnapshot, &modEntry));


    CloseHandle(hSnapshot);
    
    return IATSTATUS::MODULE_NAME_NOT_FOUND;
    
}


//
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
// IATSTATUS::MODULE_NOT_FOUND
//
IATSTATUS IATDumper::_setModuleBaseByName() {

    return _getModuleBaseByName(m_moduleName.value(), m_moduleBase);
}


//
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
//
IATSTATUS IATDumper::_setExecutableModuleBase() {

    DWORD bytesNeeded;

    if (!EnumProcessModulesEx(m_hProcess, nullptr, NULL, &bytesNeeded, LIST_MODULES_ALL))
        return IATSTATUS::FAILURE;

    HMODULE* moduleAddresses = (HMODULE*)malloc(bytesNeeded);

    if (!moduleAddresses)
        return IATSTATUS::FAILURE;


    DWORD dummylpcbNeeded; // needed for enumprocessmodulesex to not fail

    if (!EnumProcessModulesEx(m_hProcess, moduleAddresses, bytesNeeded, &dummylpcbNeeded, LIST_MODULES_ALL)) {
        free(moduleAddresses);
        return IATSTATUS::FAILURE;    
    }

    m_moduleBase = (uintptr_t)moduleAddresses[0];

    free(moduleAddresses);
        
    return IATSTATUS::SUCCESS;

}


// requires m_moduleBase to be valid before use
//
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
//
IATSTATUS IATDumper::_setImportDescriptorTableBase() {

    std::uint32_t e_lfanew;


    if (!_readMemory(m_moduleBase + m_offsets.DOS_E_LFANEW, &e_lfanew))
        return IATSTATUS::FAILURE;

    uintptr_t ntHeaders = m_moduleBase + e_lfanew;
    uintptr_t optionalHeader = ntHeaders + m_offsets.OPTIONAL_HEADER_BASE;
    uintptr_t dataDirectory = optionalHeader + m_offsets.DATA_DIRECTORY_BASE;
    uintptr_t importDirectoryEntry = dataDirectory + m_offsets.DATA_DIRECTORY_IMPORT_TABLE;

    std::uint32_t IDTRva;

    if (!_readMemory(importDirectoryEntry, &IDTRva))
        return IATSTATUS::FAILURE;

    m_IDT = m_moduleBase + IDTRva;

    return IATSTATUS::SUCCESS;

}

//
// IATSTATUS::FAILURE
// IATSTATUS::SUCCESS
// IATSTATUS::NULL_ENTRY
//

IATSTATUS IATDumper::changeCurrentDLLImportsEntry(uintptr_t index) {

    m_currentImportDescriptorVA = m_IDT + sizeof(m_currentImportDescriptor) * index;

    if (!_readMemory(m_currentImportDescriptorVA, &m_currentImportDescriptor))
        return IATSTATUS::FAILURE;



    if (!m_currentImportDescriptor)
        return IATSTATUS::NULL_ENTRY;

    m_currentILT     = m_moduleBase + m_currentImportDescriptor.ILT_RVA;
    m_currentIAT     = m_moduleBase + m_currentImportDescriptor.IAT_RVA;
    uintptr_t currentDLLNameVA = m_moduleBase + m_currentImportDescriptor.DLL_NAME_RVA;

    char dllNameTemp[MAX_PATH] = {};
    

    SIZE_T bytesRead;
    //                                                                                                              4 bytes for ".dll" or ".exe", 1 byte for at least one character name and 1 byte for null terminator
    if (!ReadProcessMemory(m_hProcess, (LPCVOID)currentDLLNameVA, dllNameTemp, sizeof(dllNameTemp), &bytesRead) || bytesRead < 6 || memchr(dllNameTemp, '\0', bytesRead) == nullptr)
        return IATSTATUS::FAILURE;

    std::string dllNameAscii(dllNameTemp);

    std::wstring dllNameW(dllNameAscii.begin(), dllNameAscii.end());


    m_currentDLLNameW = std::move(dllNameW);

    return IATSTATUS::SUCCESS;

}

//
// IATSTATUS::FAILURE
// IATSTATUS::NULL_ENTRY
// IATSTATUS::SUCCESS
//
IATSTATUS IATDumper::setCurrentILTandIATentriesByIndex(uintptr_t index) {

    if (m_isProcess64Bit) {

        m_currentILTEntryVA = m_currentILT + sizeof(m_currentILTEntry.Bit64) * index;

        if (!_readMemory(m_currentILTEntryVA, &m_currentILTEntry.Bit64))
            return IATSTATUS::FAILURE;

        if (!m_currentILTEntry.Bit64) return IATSTATUS::NULL_ENTRY;

        m_currentIATEntryVA = m_currentIAT + sizeof(m_currentIATEntry.Bit64) * index;

        if (!_readMemory(m_currentIATEntryVA, &m_currentIATEntry.Bit64))
            return IATSTATUS::FAILURE;

        if (!m_currentIATEntry.Bit64) return IATSTATUS::NULL_ENTRY;
    }
    else {

        m_currentILTEntryVA = m_currentILT + sizeof(m_currentILTEntry.Bit32) * index;

        if (!_readMemory(m_currentILTEntryVA, &m_currentILTEntry.Bit32))
            return IATSTATUS::FAILURE;

        if (!m_currentILTEntry.Bit32) return IATSTATUS::NULL_ENTRY;

        m_currentIATEntryVA = m_currentIAT + sizeof(m_currentIATEntry.Bit32) * index;

        if (!_readMemory(m_currentIATEntryVA, &m_currentIATEntry.Bit32))
            return IATSTATUS::FAILURE;

        if (!m_currentIATEntry.Bit32) return IATSTATUS::NULL_ENTRY;

    }

    return IATSTATUS::SUCCESS;

}


BOOL IATDumper::isCurrentFunctionByOrdinal() {
    if (m_isProcess64Bit)
        return (m_currentILTEntry.Bit64 & IMAGE_ORDINAL_FLAG64) != 0;
    else
        return (m_currentILTEntry.Bit32 & IMAGE_ORDINAL_FLAG32) != 0;
}


// read only
std::wstring_view IATDumper::readCurrentDLLNameW() {

    return m_currentDLLNameW;
}

// returns 0 if the current selected ILT entry does not import by ordinal
std::uint16_t IATDumper::getCurrentOrdinal() {

    if (!isCurrentFunctionByOrdinal())
        return 0;

    if (m_isProcess64Bit)
        return (std::uint16_t)(m_currentILTEntry.Bit64 & 0xFFFF);
    else
        return (std::uint16_t)(m_currentILTEntry.Bit32 & 0xFFFF);
}

uintptr_t IATDumper::getCurrentIATEntry() {

    if (m_isProcess64Bit) return m_currentIATEntry.Bit64;
    else return (uintptr_t)m_currentIATEntry.Bit32;
}

// returns nullptr if the current selected ILT entry does not import by name
std::optional<std::string> IATDumper::getCurrentILTEntryFunctionName() { // fix if wrong

    if (isCurrentFunctionByOrdinal())
        return std::nullopt;

    uintptr_t importByNameRVA;

    if (m_isProcess64Bit)
        importByNameRVA = m_currentILTEntry.Bit64 & ~IMAGE_ORDINAL_FLAG64;
    else
        importByNameRVA = (uintptr_t)(m_currentILTEntry.Bit32 & ~IMAGE_ORDINAL_FLAG32);

    uintptr_t importByNameVA = m_moduleBase + importByNameRVA;

    CHAR buffer[MAX_PATH + sizeof(WORD)];

    SIZE_T bytesRead;

    if (!ReadProcessMemory(m_hProcess, (LPCVOID)importByNameVA, buffer, sizeof(buffer), &bytesRead) || bytesRead != sizeof(buffer))
        return std::nullopt;

    buffer[sizeof(buffer) - 1] = '\0';


    IMG_IMPORT_BY_NAME* pImportByName = (IMG_IMPORT_BY_NAME*)buffer;

    return std::make_optional(std::string(pImportByName->Name, strlen(pImportByName->Name)));
}

// returns 0 if failed
std::optional<DWORD> IATDumper::getPidByName(std::wstring_view processName) {

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return std::nullopt;

    PROCESSENTRY32W procEntry;

    procEntry.dwSize = sizeof(procEntry);

    if (!Process32FirstW(hSnapshot, &procEntry)) {
        CloseHandle(hSnapshot);
        return std::nullopt;
    }

    do
    {
        if (_wcsicmp(processName.data(), procEntry.szExeFile) == 0) {

            CloseHandle(hSnapshot);
            return std::make_optional(procEntry.th32ProcessID);
        }




    } while (Process32NextW(hSnapshot, &procEntry));

    CloseHandle(hSnapshot);
    return std::nullopt;
}


template<typename T>
bool IATDumper::_readMemory(uintptr_t address, T* out) {
    SIZE_T bytesRead;
    return ReadProcessMemory(m_hProcess, (void*)address, out, sizeof(T), &bytesRead) &&
        bytesRead == sizeof(T);
}


uintptr_t IATDumper::getCurrentImportsEntryVA() {

    return m_currentImportDescriptorVA;
}

uintptr_t IATDumper::getCurrentIATEntryVA() {

    return m_currentIATEntryVA;
}

uintptr_t IATDumper::getCurrentILTEntryVA() {

    return m_currentILTEntryVA;
}








