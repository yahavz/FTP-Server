#include "../ClayWorm/clayworm.h"

BOOL ServerHandshake(struct ClayWormAddress *clientAddress);

BOOL SendFile(struct ClayWormAddress *clientAddress, PTCHAR filePath);

BOOL Finish(struct ClayWormAddress *clientAddress);