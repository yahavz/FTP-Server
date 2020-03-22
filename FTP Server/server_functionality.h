#include "../ClayWorm/clayworm.h"
#include "../Protocol/protocol.h"

#define MAX_PSH_DATA (MAX_PACKET - PSH_PACKET_SIZE)

typedef struct {
	DWORD argc;
	LPTSTR * argv;
} PARAMS, *PPARAMS;

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file);

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file);

BOOL Finish(ClayWormAddress *clientAddress);

BOOL HandleServer(PPARAMS params);