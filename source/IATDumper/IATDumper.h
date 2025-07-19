#include <Windows.h>
#include <string>
#include <string_view>
#include <optional>
#include <TlHelp32.h>
#include <psapi.h>
#include "../PELayout.h"
#include <cstdint>

constexpr SIZE_T MAX_DLL_NAME_LENGTH = 256;

enum class IATSTATUS {
	SUCCESS,
	FAILURE,
	NULL_ENTRY,
	STATUS_TRUE,  // status prefix needed because of the shitty winapi macro
	STATUS_FALSE,
	INVALID_PID,
    INVALID_MODULE_BASE,
	UNSUPPORTED_ARCHITECTURE,
    MODULE_NAME_NOT_FOUND,
	MAX,
};


class IATDumper {

public:


    explicit IATDumper(DWORD ProcessId) 
        : m_ProcessId{ ProcessId } {}

    IATDumper(DWORD ProcessId, std::wstring_view moduleName)
        : m_ProcessId{ ProcessId }, m_moduleName{ moduleName } {}

    IATDumper(DWORD ProcessId, uintptr_t moduleBase)
        : m_ProcessId{ ProcessId }, m_moduleBase{ moduleBase } {}


    ~IATDumper() {

        if (m_hProcess)
            CloseHandle(m_hProcess);

    }

    //
    // IATSTATUS::UNSUPPORTED_ARCHITECTURE
    // IATSTATUS::FAILURE
    // IATSTATUS::SUCCESS
    // IATSTATUS::INVALID_PID
    //
    IATSTATUS configure();
    IATSTATUS changeCurrentDLLImportsEntry(uintptr_t index);
    BOOL getIsProcess64Bit() { return m_isProcess64Bit; }
    IATSTATUS setCurrentILTandIATentriesByIndex(uintptr_t index);
    std::wstring_view readCurrentDLLNameW();
    uintptr_t getCurrentImportsEntryVA();
    BOOL isCurrentFunctionByOrdinal();
    std::uint16_t getCurrentOrdinal();
    uintptr_t getCurrentIATEntry();
    uintptr_t getCurrentIATEntryVA();
    uintptr_t getCurrentILTEntryVA();
    std::optional<std::string> getCurrentILTEntryFunctionName();
    static std::optional<DWORD> getPidByName(std::wstring_view processName);


private:


    HANDLE m_hProcess = nullptr;
    DWORD m_ProcessId = 0;
    BOOL m_isProcess64Bit = FALSE;
    uintptr_t m_moduleBase = 0;
    std::optional<std::wstring> m_moduleName;
    uintptr_t m_IDT = 0; // Import Descriptor Array
    PELayout m_offsets{};
    IMG_IMPORT_DESCRIPTOR m_currentImportDescriptor{}; // Modules's currently selected DLL Import_Descriptor entry by index from changeCurrentDLLImportsEntry
    uintptr_t m_currentImportDescriptorVA = 0;
    std::wstring m_currentDLLNameW; // Name of currently selected DLL Import_Descriptor entry by index from changeCurrentDLLImportsEntry
    uintptr_t m_currentILT = 0;
    uintptr_t m_currentIAT = 0;

    union {
        std::uint64_t Bit64;
        std::uint32_t Bit32;
    } m_currentILTEntry{};

    uintptr_t m_currentILTEntryVA = 0;
   

    union {
        std::uint64_t Bit64;
        std::uint32_t Bit32;
    } m_currentIATEntry{};

    uintptr_t m_currentIATEntryVA = 0;

    //
    // IATSTATUS_UNSUPPORTED_ARCHITECTURE
    // IATSTATUS_FALSE
    // IATSTATUS_TRUE
    // IAT_STATUS_FAILURE
    // 
    IATSTATUS _isProcess64Bit();

public:

    IATSTATUS _getModuleBaseByName(std::wstring_view moduleName, uintptr_t& OUTmoduleBase);

private:

    IATSTATUS _setExecutableModuleBase();
    IATSTATUS _setImportDescriptorTableBase();
    IATSTATUS _setModuleBaseByName();


    template<typename T>
    bool _readMemory(uintptr_t address, T* out);




};
