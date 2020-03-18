#include "../ClayWorm/clayworm.h"
#include "../Protocol/protocol.h"

#define MAX_PSH_DATA (MAX_PACKET - PSH_PACKET_SIZE)

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file);

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file, DWORD numberOfPhases);

BOOL Finish(ClayWormAddress *clientAddress);