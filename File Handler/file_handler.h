#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include "../Protocol/protocol.h"
#include <Windows.h>

typedef struct {
	USHORT chunkSize;
	BYTE data[MAX_PSH_DATA];
}chunk_t, *p_chunk_t;

BOOL AllocateChunks(chunk_t ** chunksArray);

BOOL ReadPhase(HANDLE inFile, chunk_t ** chunksArray);

BOOL FreeChunks(chunk_t ** chunksArray);

BOOL GatherChunks(HANDLE outFile, chunk_t ** chunksArray);

#endif // !FILE_HANDLER_H_