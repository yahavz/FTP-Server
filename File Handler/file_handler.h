#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include <Windows.h>

BOOL AllocateChunks(BYTE ** chunksArray);

BOOL ReadPhase(HANDLE inFile, BYTE ** chunksArray);

BOOL FreeChunks(BYTE ** chunksArray);

BOOL GatherChunks(HANDLE outFile, DWORD phaseSize, BYTE ** chunksArray);

#endif // !FILE_HANDLER_H_