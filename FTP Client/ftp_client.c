#include <Windows.h>
#include <WinSock2.h>
#include <tchar.h>
#include <stdio.h>


BOOL ValidateParams(int argc, PTCHAR * argv)
{
	HANDLE dummyFile;
	IN_ADDR addr = { 0 };

	if (argc != 5)
	{
		_tprintf(TEXT("Usage: \"ftp client.exe <server_ip> <server_port> <listen_port> <file_path>\"\n"));
		return FALSE;
	}

	if (InetPton(AF_INET, argv[1], &addr) <= 0)
	{
		_tprintf(TEXT("Error: the server IP address is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[2]) <= 0 || atoi(argv[2]) > 65535)
	{
		_tprintf(TEXT("Error: the server port is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[3]) <= 0 || atoi(argv[3]) > 65535)
	{
		_tprintf(TEXT("Error: the listen port is invalid!\n"));
		return FALSE;
	}

	dummyFile = CreateFile(
		argv[4], // lpFileName
		GENERIC_READ, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		CREATE_NEW, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (dummyFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_EXISTS)
		{
			_tprintf(TEXT("Error: the given file already exists!\n"));
			return FALSE;
		}
		
		_tprintf(TEXT("Error: the file given is invalid!\n"));
		return FALSE;
	}

	CloseHandle(dummyFile);

	return TRUE;
}

int _tmain(DWORD argc, LPTSTR * argv)
{
	
}