#include "stdafx.h"
#include "PE.h"
#include "PortableExecutable.h"

VOID PortableExecutable::Init()
{
	this->isValidPE = IsValidPE();
	this->is64Bit = Is64Bit();
}



//Public
////////
PortableExecutable::PortableExecutable()
{
	this->hProcess = GetCurrentProcess();
	Init();
}

PortableExecutable::PortableExecutable(HANDLE hProcess)
{
	this->hProcess = hProcess;
	Init();
}


PortableExecutable::~PortableExecutable()
{
}




PIMAGE_DOS_HEADER PortableExecutable::getDOSHeader()
{
	HMODULE hNTDLL = LoadLibrary(L"ntdll");
	if (!hNTDLL)
		return 0;

	myNtQueryInformationProcess NtQIP = (myNtQueryInformationProcess)GetProcAddress(hNTDLL, "NtQueryInformationProcess");
	if (!NtQIP)
		return 0;

	PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION;
	DWORD dwReturnLength = 0;

	NtQIP(this->hProcess, ProcessBasicInformation, pBasicInfo, sizeof PROCESS_BASIC_INFORMATION, &dwReturnLength);

#ifdef _M_AMD64
	PEB64* pPEB = new PEB64();
	if (!RPM(this->hProcess, pBasicInfo->PebBaseAddress, pPEB, sizeof PEB64))
		return 0;
#elif defined(_M_IX86)
	PEB32* pPEB = new PEB32();
	if (!RPM(this->hProcess, pBasicInfo->PebBaseAddress, pPEB, sizeof PEB62))
		return 0;
#endif // _M_AMD64

	return (PIMAGE_DOS_HEADER)pPEB->ImageBaseAddress;
}

PIMAGE_NT_HEADERS PortableExecutable::getNTHeaders()
{
	IMAGE_DOS_HEADER DOSHeader;
	if (!RPM(this->hProcess, (LPVOID)getDOSHeader(), &DOSHeader, sizeof IMAGE_DOS_HEADER))
		return 0;
	
	return (PIMAGE_NT_HEADERS)RVAtoOffset(DOSHeader.e_lfanew);
}

PIMAGE_FILE_HEADER PortableExecutable::getFileHeader()
{
	if (!this->isValidPE)
		return 0;

	IMAGE_NT_HEADERS NTHeaders;
	if (!RPM(this->hProcess, (LPVOID)getNTHeaders(), &NTHeaders, sizeof IMAGE_NT_HEADERS))
		return 0;
	return (PIMAGE_FILE_HEADER)&NTHeaders.FileHeader;
}

PIMAGE_OPTIONAL_HEADER PortableExecutable::getOptionalHeader()
{
	if (!this->isValidPE)
		return 0;
	IMAGE_NT_HEADERS NTHeaders;
	if (!RPM(this->hProcess, (LPVOID)getNTHeaders(), &NTHeaders, sizeof IMAGE_NT_HEADERS))
		return 0;
	return (PIMAGE_OPTIONAL_HEADER)&NTHeaders.OptionalHeader;
}

PIMAGE_DATA_DIRECTORY PortableExecutable::getDataDir64()
{
	IMAGE_OPTIONAL_HEADER64 OPTHeader;
	if (!RPM(this->hProcess, (LPVOID)getOptionalHeader(), &OPTHeader, sizeof IMAGE_OPTIONAL_HEADER64))
		return 0;
	return (PIMAGE_DATA_DIRECTORY)&OPTHeader.DataDirectory;
}

PIMAGE_DATA_DIRECTORY PortableExecutable::getDataDir32()
{
	IMAGE_OPTIONAL_HEADER32 OPTHeader;
	if (!RPM(this->hProcess, (LPVOID)getOptionalHeader(), &OPTHeader, sizeof IMAGE_OPTIONAL_HEADER32))
		return 0;
	return (PIMAGE_DATA_DIRECTORY)&OPTHeader.DataDirectory;
}

PIMAGE_DATA_DIRECTORY PortableExecutable::getDataDir()
{
	if (!this->isValidPE)
		return 0;
	if (this->is64Bit)
	{
		return getDataDir64();
	}
	else
	{
		return getDataDir32();
	}
}

PIMAGE_IMPORT_DESCRIPTOR PortableExecutable::getFirstImportDescriptor64()
{
	IMAGE_OPTIONAL_HEADER64 OPTHeader;
	if (!RPM(this->hProcess, (LPVOID)getOptionalHeader(), &OPTHeader, sizeof IMAGE_OPTIONAL_HEADER64))
		return 0;
	DWORD NumberOfDirectories = OPTHeader.NumberOfRvaAndSizes;

	IMAGE_DATA_DIRECTORY* DataDir;
	SIZE_T DataDirLen = ((sizeof IMAGE_DATA_DIRECTORY) * NumberOfDirectories);
	DataDir = new IMAGE_DATA_DIRECTORY[NumberOfDirectories];
	if (!RPM(this->hProcess, (LPVOID)getDataDir64(), DataDir, DataDirLen))
		return 0;

	return (PIMAGE_IMPORT_DESCRIPTOR)RVAtoOffset(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}

PIMAGE_IMPORT_DESCRIPTOR PortableExecutable::getFirstImportDescriptor32()
{
	IMAGE_OPTIONAL_HEADER32 OPTHeader;
	if (!RPM(this->hProcess, (LPVOID)getOptionalHeader(), &OPTHeader, sizeof IMAGE_OPTIONAL_HEADER32))
		return 0;
	DWORD NumberOfDirectories = OPTHeader.NumberOfRvaAndSizes;

	IMAGE_DATA_DIRECTORY* DataDir;
	SIZE_T DataDirLen = ((sizeof IMAGE_DATA_DIRECTORY) * NumberOfDirectories);
	DataDir = new IMAGE_DATA_DIRECTORY [NumberOfDirectories];
	if (!RPM(this->hProcess, (LPVOID)getDataDir32(), DataDir, DataDirLen))
		return 0;

	return (PIMAGE_IMPORT_DESCRIPTOR)RVAtoOffset(DataDir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
}

PIMAGE_IMPORT_DESCRIPTOR PortableExecutable::getFirstImportDescriptor()
{
	if (!this->isValidPE)
		return 0;
	if (this->is64Bit)
	{
		return getFirstImportDescriptor64();
	}
	else
	{
		return getFirstImportDescriptor32();
	}
}

PIMAGE_IMPORT_DESCRIPTOR PortableExecutable::getNextImportDescriptor(PIMAGE_IMPORT_DESCRIPTOR pCurrentImportDescriptor)
{
	return (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)pCurrentImportDescriptor + sizeof IMAGE_IMPORT_DESCRIPTOR);
}

PIMAGE_THUNK_DATA PortableExecutable::getOriginalFirstThunk(PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor)
{
	if (!this->isValidPE)
		return 0;
	IMAGE_IMPORT_DESCRIPTOR IMPDesc;
	if (!RPM(this->hProcess, (LPVOID)pImportDescriptor, &IMPDesc, sizeof IMAGE_IMPORT_DESCRIPTOR))
		return 0;
	return (PIMAGE_THUNK_DATA)RVAtoOffset(IMPDesc.OriginalFirstThunk);
}

PIMAGE_THUNK_DATA PortableExecutable::getOriginalNextThunk(PIMAGE_THUNK_DATA pCurrentThunk)
{
	return (PIMAGE_THUNK_DATA)((BYTE*)pCurrentThunk + sizeof IMAGE_THUNK_DATA);
}

PIMAGE_THUNK_DATA PortableExecutable::getFirstThunk( PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor)
{
	if (!this->isValidPE)
		return 0;
	IMAGE_IMPORT_DESCRIPTOR IMPDesc;
	if (!RPM(this->hProcess, (LPVOID)pImportDescriptor, &IMPDesc, sizeof IMAGE_IMPORT_DESCRIPTOR))
		return 0;
	return (PIMAGE_THUNK_DATA)RVAtoOffset(IMPDesc.FirstThunk);
}

PIMAGE_THUNK_DATA PortableExecutable::getNextThunk(PIMAGE_THUNK_DATA pCurrentThunk)
{
	return (PIMAGE_THUNK_DATA)((BYTE*)pCurrentThunk + sizeof IMAGE_THUNK_DATA);
}



BOOL PortableExecutable::IsValidPE()
{
	IMAGE_DOS_HEADER DOSHeader;
	if (!RPM(this->hProcess, (LPVOID)getDOSHeader(), &DOSHeader, sizeof IMAGE_DOS_HEADER))
		return 0;

	if (DOSHeader.e_magic == IMAGE_DOS_SIGNATURE)
	{
		IMAGE_NT_HEADERS NTHeaders;
		if (!RPM(this->hProcess, (LPVOID)getNTHeaders(), &NTHeaders, sizeof IMAGE_NT_HEADERS))
			return 0;
		if (NTHeaders.Signature == IMAGE_NT_SIGNATURE)
			return TRUE;
	}
	return FALSE;
}

BOOL PortableExecutable::Is64Bit()
{
	if (this->isValidPE)
	{
		IMAGE_NT_HEADERS NTHeaders;
		if (!RPM(this->hProcess, (LPVOID)getNTHeaders(), &NTHeaders, sizeof IMAGE_NT_HEADERS))
			return 0;
		if (NTHeaders.FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64)
			return TRUE;
	}
	return FALSE;
}

LPVOID PortableExecutable::RVAtoOffset(WORD RVA)
{
	LPVOID RetVal = (LPVOID)getDOSHeader();
	if (!RetVal)
		return 0;
	return (LPVOID)((BYTE*)RetVal + RVA);
}
LPVOID PortableExecutable::RVAtoOffset(LONG RVA)
{
	LPVOID RetVal = (LPVOID)getDOSHeader();
	if (!RetVal)
		return 0;
	return (LPVOID)((BYTE*)RetVal + RVA);
}
LPVOID PortableExecutable::RVAtoOffset(UNALIGNED DWORD RVA)
{
	LPVOID RetVal = (LPVOID)getDOSHeader();
	if (!RetVal)
		return 0;
	return (LPVOID)((BYTE*)RetVal + RVA);
}
LPVOID PortableExecutable::RVAtoOffset(ULONGLONG RVA)
{
	LPVOID RetVal = (LPVOID)getDOSHeader();
	if (!RetVal)
		return 0;
	return (LPVOID)((BYTE*)RetVal + RVA);
}