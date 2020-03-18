#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include <Windows.h>

BOOL ReadPhaseAndWriteChunks(HANDLE inFile, USHORT chunkMaxSize);

BOOL DeleteChunksTempFiles();

BOOL GatherChunks(HANDLE outFile, USHORT chunkMaxSize);

#endif // !FILE_HANDLER_H_