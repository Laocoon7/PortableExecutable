#pragma once

#include <Windows.h>
#include <winternl.h>

#include "PEB.h"
#include "RPMWPM.h"

class PortableExecutable
{
private:
	HANDLE hProcess;

	BOOL isValidPE;
	BOOL is64Bit;

	VOID Init();

public:

	PortableExecutable();
	PortableExecutable(HANDLE hProcess);
	~PortableExecutable();


	
	
	PIMAGE_DOS_HEADER getDOSHeader();
	PIMAGE_NT_HEADERS getNTHeaders();
	PIMAGE_FILE_HEADER getFileHeader();
	PIMAGE_OPTIONAL_HEADER getOptionalHeader();
	PIMAGE_DATA_DIRECTORY getDataDir64();
	PIMAGE_DATA_DIRECTORY getDataDir32();
	PIMAGE_DATA_DIRECTORY getDataDir();
	PIMAGE_IMPORT_DESCRIPTOR getFirstImportDescriptor64();
	PIMAGE_IMPORT_DESCRIPTOR getFirstImportDescriptor32();
	PIMAGE_IMPORT_DESCRIPTOR getFirstImportDescriptor();
	PIMAGE_IMPORT_DESCRIPTOR getNextImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR pCurrentImportDescriptor);
	PIMAGE_THUNK_DATA getOriginalFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor);
	PIMAGE_THUNK_DATA getOriginalNextThunk(PIMAGE_THUNK_DATA pCurrentThunk);
	PIMAGE_THUNK_DATA getFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor);
	PIMAGE_THUNK_DATA getNextThunk(PIMAGE_THUNK_DATA pCurrentThunk);

	BOOL IsValidPE();
	BOOL Is64Bit();

	LPVOID RVAtoOffset(WORD RVA);
	LPVOID RVAtoOffset(LONG RVA);
	LPVOID RVAtoOffset(UNALIGNED DWORD RVA);
	LPVOID RVAtoOffset(ULONGLONG RVA);
};

