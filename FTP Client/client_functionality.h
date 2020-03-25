#ifndef CLIENT_H_
#define CLIENT_H_

#include "../ClayWorm/clayworm.h"
#include "../Protocol/protocol.h"
#include <Windows.h>
#include <tchar.h>

typedef struct {
	LPTSTR serverIP;
	USHORT serverPort;
	USHORT listenPort;
	LPTSTR filePath;
} PARAMS, *PPARAMS;

DWORD ListenForSYN(ClayWormAddress *serverAddress);

BOOL GetFileAndFinish(ClayWormAddress *serverAddress, HANDLE fileToWrite, DWORD numberOfChunks);

BOOL HandleClient(PPARAMS params);

#endif // !CLIENT_H_