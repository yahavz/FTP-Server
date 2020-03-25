#ifndef SERVER_H_
#define SERVER_H_

#include "../ClayWorm/clayworm.h"

typedef struct {
	LPTSTR clientIP;
	USHORT clientPort;
	USHORT listenPort;
	LPTSTR filePath;
} PARAMS, *PPARAMS;

BOOL ServerHandshake(ClayWormAddress *clientAddress, DWORD numberOfChunks);

BOOL SendFile(ClayWormAddress *clientAddress, DWORD numberOfPhases, DWORD numberOfChunks, HANDLE file);

BOOL Finish(ClayWormAddress *clientAddress);

BOOL HandleServer(PPARAMS params);

#endif // !SERVER_H_