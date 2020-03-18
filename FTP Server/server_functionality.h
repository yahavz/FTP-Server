#include "../ClayWorm/clayworm.h"

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file);

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file, DWORD numberOfPhases);

BOOL Finish(ClayWormAddress *clientAddress);