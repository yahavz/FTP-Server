#ifndef CLAYWORM_H_
#define CLAYWORM_H_

#include <Windows.h>
#include <WinSock2.h>
#include <tchar.h>

BOOL ClayWorm_Initialize();

BOOL ClayWorm_Cleanup();

BOOL ClayWorm_Bind(PTCHAR ip, unsigned short port);

BOOL ClayWorm_Available();

SIZE_T ClayWorm_Send(PBYTE data, SIZE_T dataLength, PADDRINFOA destination);

SIZE_T ClayWorm_Receive(PBYTE data, SIZE_T dataLength, PADDRINFOA source);

#endif // !CLAYWORM_H_