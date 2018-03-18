#include "stdafx.h"

#include "RPMWPM.h"

BOOL RPM(HANDLE hProcess, LPVOID from, LPVOID to, SIZE_T len)
{
	BOOL RetVal;
	DWORD OldProtect;
	VirtualProtectEx(hProcess, from, len, PAGE_READONLY, &OldProtect);

	RetVal = ReadProcessMemory(hProcess, from, to, len, 0);

	VirtualProtectEx(hProcess, from, len, OldProtect, &OldProtect);
	return RetVal;
}

BOOL WPM(HANDLE hProcess, LPVOID from, LPVOID to, SIZE_T len)
{
	BOOL RetVal;
	DWORD OldProtect;
	VirtualProtectEx(hProcess, to, len, PAGE_WRITECOPY, &OldProtect);

	RetVal = WriteProcessMemory(hProcess, to, from, len, 0);

	VirtualProtectEx(hProcess, to, len, OldProtect, &OldProtect);
	return RetVal;
}
