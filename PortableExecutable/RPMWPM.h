#pragma once

#include <Windows.h>

BOOL RPM(HANDLE hProcess, LPVOID from, LPVOID to, SIZE_T len);
BOOL WPM(HANDLE hProcess, LPVOID from, LPVOID to, SIZE_T len);
