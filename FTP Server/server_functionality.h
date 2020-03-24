#include "../ClayWorm/clayworm.h"
#include "../Protocol/protocol.h"

#define MAX_PSH_DATA (MAX_PACKET - PSH_PACKET_SIZE)

typedef struct {
	LPTSTR clientIP;
	USHORT clientPort;
	USHORT listenPort;
	LPTSTR filePath;
} PARAMS, *PPARAMS;

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file);

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file);

BOOL Finish(ClayWormAddress *clientAddress);

BOOL HandleServer(PPARAMS params);