#ifndef CLAYWORM_H_
#define CLAYWORM_H_

#include <WinSock2.h>
#include <Windows.h>
#include <tchar.h>
#include <stdint.h>

#define MAX_PACKET (10*1024)
#define ADDRESS_MAX_LENGTH	(16)


typedef struct {
	TCHAR address[16];
	uint16_t port;
} ClayWormAddress;

BOOL ClayWorm_Initialize(uint16_t port_to_listen);

void ClayWorm_Cleanup();

BOOL ClayWorm_Available();

BOOL ClayWorm_Send(uint8_t* data, uint32_t dataLength, ClayWormAddress* destination);

int ClayWorm_Receive(uint8_t* data, uint32_t dataLength, TCHAR source_address[ADDRESS_MAX_LENGTH]);

#endif // !CLAYWORM_H_