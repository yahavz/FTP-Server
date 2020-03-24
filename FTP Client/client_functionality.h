#ifndef CLIENT_H_
#define CLIENT_H_

#include "../ClayWorm/clayworm.h"
#include <Windows.h>
#include <tchar.h>
#include "../Protocol/protocol.h"

#define MAX_PSH_DATA (MAX_PACKET - PSH_PACKET_SIZE)

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