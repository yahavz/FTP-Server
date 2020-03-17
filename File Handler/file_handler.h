#ifndef FILE_HANDLER_H_
#define FILE_HANDLER_H_

#include <Windows.h>

BOOL NextPhaseToChunks(HANDLE file);

BOOL GatherChunks(USHORT phaseNumber);

#endif // !FILE_HANDLER_H_