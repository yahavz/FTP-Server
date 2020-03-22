#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "file_handler.h"
#include "../Protocol/protocol.h"

BOOL ReadPhaseAndWriteChunks(HANDLE inFile, USHORT chunkMaxSize)
{
	int i;
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE chunkFile;
	TCHAR chunkFileName[MAX_PATH] = { 0 };
	PBYTE chunkToWrite = (PBYTE)malloc(chunkMaxSize);
	if (!chunkToWrite)
	{
		return FALSE;
	}
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunkToWrite, 0, chunkMaxSize);
		memset(&chunkFileName, 0, MAX_PATH * sizeof(TCHAR));
		if (!ReadFile(
			inFile, // hFile
			chunkToWrite, // lpBuffer
			chunkMaxSize, // nNumberOfBytesToRead
			&bytesRead, // lpNumberOfBytesRead
			NULL // lpOverlapped
		))
		{
			memset(chunkToWrite, 0, chunkMaxSize);
			free(chunkToWrite);
			return FALSE;
		}

		if (bytesRead == 0)
		{
			memset(chunkToWrite, 0, chunkMaxSize);
			free(chunkToWrite);
			return TRUE;
		}

		_stprintf_s(chunkFileName, MAX_PATH, TEXT("%u.tmp"), i);

		chunkFile = CreateFile(
			chunkFileName, // lpFileName
			GENERIC_WRITE, // dwDesiredAccess
			0, // dwShareMode
			NULL, // lpSecurityAttributes
			CREATE_ALWAYS, // dwCreationDisposition
			0, // dwFlagsAndAttributes
			NULL // hTemplateFile
		);

		if (chunkFile == INVALID_HANDLE_VALUE)
		{
			memset(chunkToWrite, 0, chunkMaxSize);
			free(chunkToWrite);
			return FALSE;
		}

		if (!WriteFile(
			chunkFile, // hFile
			chunkToWrite, // lpBuffer
			bytesRead, // nNumberOfBytesToWrite
			&bytesWritten, // lpNumberOfBytesWritten
			NULL // lpOverlapped
		) || bytesWritten != bytesRead)
		{
			CloseHandle(chunkFile);
			memset(chunkToWrite, 0, chunkMaxSize);
			free(chunkToWrite);
			return FALSE;
		}

		CloseHandle(chunkFile);

	}

	memset(chunkToWrite, 0, chunkMaxSize);
	free(chunkToWrite);
	return TRUE;
}

BOOL DeleteChunksTempFiles()
{
	int i;
	TCHAR chunkFileName[MAX_PATH] = { 0 };
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunkFileName, 0, sizeof(TCHAR) * MAX_PATH);
		_stprintf_s(chunkFileName, MAX_PATH, TEXT("%u.tmp"), i);
		if (!DeleteFile(chunkFileName))
		{
			if (GetLastError() != ERROR_FILE_NOT_FOUND)
			{
				return FALSE;
			}
		}
	}

	return TRUE;
}

BOOL GatherChunks(HANDLE outFile, USHORT chunkMaxSize)
{
	int i;
	DWORD bytesRead;
	DWORD bytesWritten;
	HANDLE chunkFile;
	TCHAR chunkFileName[MAX_PATH] = { 0 };
	PBYTE chunkToRead = (PBYTE)malloc(chunkMaxSize);
	if (!chunkToRead)
	{
		return FALSE;
	}

	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunkToRead, 0, chunkMaxSize);
		memset(&chunkFileName, 0, MAX_PATH * sizeof(TCHAR));

		_stprintf_s(chunkFileName, MAX_PATH, TEXT("%u.tmp"), i);
		
		chunkFile = CreateFile(
			chunkFileName, // lpFileName
			GENERIC_READ, // dwDesiredAccess
			0, // dwShareMode
			NULL, // lpSecurityAttributes
			OPEN_ALWAYS, // dwCreationDisposition
			0, // dwFlagsAndAttributes
			NULL // hTemplateFile
		);

		if (chunkFile == INVALID_HANDLE_VALUE)
		{
			memset(chunkToRead, 0, chunkMaxSize);
			free(chunkToRead);
			return FALSE;
		}

		if (!ReadFile(
			chunkFile, // hFile
			chunkToRead, // lpBuffer
			chunkMaxSize, // nNumberOfBytesToRead
			&bytesRead, // lpNumberOfBytesRead
			NULL // lpOverlapped
		))
		{
			CloseHandle(chunkFile);
			memset(chunkToRead, 0, chunkMaxSize);
			free(chunkToRead);
			return FALSE;
		}

		if (bytesRead == 0)
		{
			CloseHandle(chunkFile);
			memset(chunkToRead, 0, chunkMaxSize);
			free(chunkToRead);
			return TRUE;
		}

		
		if (!WriteFile(
			outFile, // hFile
			chunkToRead, // lpBuffer
			bytesRead, // nNumberOfBytesToWrite
			&bytesWritten, // lpNumberOfBytesWritten
			NULL // lpOverlapped
		) || bytesWritten != bytesRead)
		{
			CloseHandle(chunkFile);
			memset(chunkToRead, 0, chunkMaxSize);
			free(chunkToRead);
			return FALSE;
		}

		CloseHandle(chunkFile);

	}

	memset(chunkToRead, 0, chunkMaxSize);
	free(chunkToRead);
	return TRUE;
}