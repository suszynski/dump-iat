#pragma once

#include <Windows.h>

#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000


struct PELayout {

	uintptr_t DOS_E_LFANEW = 0;                // relative to module base
	uintptr_t OPTIONAL_HEADER_BASE = 0;        // relative to file header
	uintptr_t DATA_DIRECTORY_BASE = 0;         // relative to optional header
	uintptr_t DATA_DIRECTORY_IMPORT_TABLE = 0; // relative to data_directory


	static constexpr PELayout forPE32() {

		return {
			0x3C, // DOS_E_LFANEW
			0x18, // OPTIONAL_HEADER_BASE
			0x60, // DATA_DIRECTORY_BASE
			0x8   // DATA_DIRECTORY_IMPORT
		};
	}

	static constexpr PELayout forPE64() {

		return {
			0x3C, // DOS_E_LFANEW
			0x18, // OPTIONAL_HEADER_BASE
			0x70, // DATA_DIRECTORY_BASE
			0x8   // DATA_DIRECTORY_IMPORT_TABLE
		};

	}

};

#pragma pack(push, 1)
struct IMG_IMPORT_DESCRIPTOR {
	 
	std::uint32_t ILT_RVA = 0;		  // OriginalFirstThunk/Characteristics union
	std::uint32_t TimeDateStamp = 0;
	std::uint32_t ForwarderChain = 0;
	std::uint32_t DLL_NAME_RVA = 0;
	std::uint32_t IAT_RVA = 0;		  // FirstThunk


	bool operator!() const {

		return ILT_RVA        == 0  &&
			   TimeDateStamp  == 0  &&
			   ForwarderChain == 0  &&
			   DLL_NAME_RVA   == 0  &&
			   IAT_RVA        == 0;
  
	}

};

#pragma pack(pop)


#pragma pack(push, 1)
struct IMG_IMPORT_BY_NAME {

	std::uint16_t Hint;
	CHAR Name[1];
	
};
#pragma pack(pop)
