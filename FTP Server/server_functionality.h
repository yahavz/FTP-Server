#include "../ClayWorm/clayworm.h"

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file);

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file);

BOOL Finish(ClayWormAddress *clientAddress);