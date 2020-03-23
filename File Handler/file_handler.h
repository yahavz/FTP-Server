#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include <Windows.h>

BOOL ReadPhaseAndWriteChunks(HANDLE inFile, PTCHAR dir, USHORT chunkMaxSize);

BOOL DeleteChunksTempFiles(PTCHAR dir);

BOOL GatherChunks(HANDLE outFile, PTCHAR dir, USHORT chunkMaxSize);

#endif // !FILE_HANDLER_H_