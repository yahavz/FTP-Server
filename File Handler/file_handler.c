#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "file_handler.h"
#include "../Protocol/protocol.h"

BOOL AllocateChunks(BYTE ** chunksArray)
{
	DWORD i, j;
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		chunksArray[i] = (BYTE *)malloc(MAX_PSH_DATA);
		if (!chunksArray[i])
		{
			for (j = 0; j < i; j++)
			{
				free(chunksArray[j]);
			}
			return FALSE;
		}
	}
	return TRUE;
}

BOOL ReadPhase(HANDLE inFile, BYTE ** chunksArray)
{
	DWORD i;
	DWORD bytesRead;
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunksArray[i], 0, MAX_PSH_DATA);
		if (!ReadFile(
			inFile, // hFile
			chunksArray[i], // lpBuffer
			MAX_PSH_DATA, // nNumberOfBytesToRead
			&bytesRead, // lpNumberOfBytesRead
			NULL // lpOverlapped
		))
		{
			memset(chunksArray[i], 0, MAX_PSH_DATA);
			return FALSE;
		}

		if (bytesRead == 0)
		{
			memset(chunksArray[i], 0, MAX_PSH_DATA);
			return TRUE;
		}
		
	}
	return TRUE;
}

BOOL FreeChunks(BYTE ** chunksArray)
{
	DWORD i;
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunksArray[i], 0, MAX_PSH_DATA);
		free(chunksArray[i]);
	}

	return TRUE;
}

BOOL GatherChunks(HANDLE outFile, DWORD phaseSize, BYTE ** chunksArray)
{
	DWORD i;
	DWORD bytesToWrite;
	DWORD bytesWritten;
	BYTE chunksCount = (phaseSize / MAX_PSH_DATA) + (phaseSize % MAX_PSH_DATA != 0);

	for (i = 0; i < chunksCount; i++)
	{
		bytesToWrite = min(phaseSize, MAX_PSH_DATA);
		if (!WriteFile(
			outFile, // hFile
			chunksArray[i], // lpBuffer
			bytesToWrite, // nNumberOfBytesToWrite
			&bytesWritten, // lpNumberOfBytesWritten
			NULL // lpOverlapped
		) || bytesWritten != bytesToWrite)
		{
			return FALSE;
		}

		phaseSize -= bytesToWrite;
	}

	return TRUE;
}