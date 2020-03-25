#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include "file_handler.h"

BOOL AllocateChunks(chunk_t ** chunksArray)
{
	DWORD i, j;
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		chunksArray[i] = (p_chunk_t)malloc(sizeof(chunk_t));
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

BOOL ReadPhase(HANDLE inFile, chunk_t ** chunksArray)
{
	DWORD i;
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunksArray[i], 0, sizeof(chunk_t));
		if (!ReadFile(
			inFile, // hFile
			chunksArray[i]->data, // lpBuffer
			MAX_PSH_DATA, // nNumberOfBytesToRead
			&(chunksArray[i]->chunkSize), // lpNumberOfBytesRead
			NULL // lpOverlapped
		))
		{
			memset(chunksArray[i], 0, sizeof(chunk_t));
			return FALSE;
		}

		if (chunksArray[i]->chunkSize == 0)
		{
			memset(chunksArray[i], 0, sizeof(chunk_t));
			return TRUE;
		}
		
	}
	return TRUE;
}

BOOL FreeChunks(chunk_t ** chunksArray)
{
	DWORD i;
	
	for (i = 0; i < MAX_CHUNKS; i++)
	{
		memset(chunksArray[i], 0, sizeof(chunk_t));
		free(chunksArray[i]);
	}

	return TRUE;
}

BOOL GatherChunks(HANDLE outFile, BYTE chunksCount, chunk_t ** chunksArray)
{
	DWORD i;
	DWORD bytesWritten;

	for (i = 0; i < chunksCount; i++)
	{
		if (!WriteFile(
			outFile, // hFile
			chunksArray[i]->data, // lpBuffer
			chunksArray[i]->chunkSize, // nNumberOfBytesToWrite
			&bytesWritten, // lpNumberOfBytesWritten
			NULL // lpOverlapped
		) || bytesWritten != chunksArray[i]->chunkSize)
		{
			return FALSE;
		}
	}

	return TRUE;
}