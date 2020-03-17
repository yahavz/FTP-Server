#include <WinSock2.h>
#include <WS2tcpip.h>
#include <stdio.h>
#include "clayworm.h"

static SOCKET receiving_socket;
static BOOL is_initialized = FALSE;
static BOOL is_peeked = FALSE;
static int msg_peek_size = 0;
static uint8_t msg_peek[MAX_PACKET] = { 0 };
static uint8_t addr_peek[ADDRESS_MAX_LENGTH] = { 0 };

BOOL ClayWorm_Initialize(uint16_t port_to_listen)
{
	WSADATA wsaData;
	SOCKADDR_IN receive_address;
	uint32_t timeout = 10;
	
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("Server: WSAStartup failed with error %ld\n", WSAGetLastError());

		return FALSE;
	}

	receiving_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (receiving_socket == INVALID_SOCKET)
	{
		WSACleanup();

		return FALSE;
	}

	receive_address.sin_family = AF_INET;
	receive_address.sin_port = htons(port_to_listen);
	receive_address.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	
	if (bind(receiving_socket, (SOCKADDR *)&receive_address, sizeof(receive_address)) == SOCKET_ERROR)
	{
		printf("Server: bind() failed!Error : %ld.\n", WSAGetLastError());
		closesocket(receiving_socket);
		WSACleanup();

		return FALSE;
	}

	setsockopt(receiving_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout));

	is_initialized = TRUE;

	return TRUE;
}

void ClayWorm_Cleanup()
{
	if (is_initialized)
	{
		closesocket(receiving_socket);
		WSACleanup();
	}
}

BOOL ClayWorm_Send(uint8_t* data, uint32_t dataLength, ClayWormAddress* destination)
{
	BOOL return_value = TRUE;
	SOCKET sending_socket;
	SOCKADDR_IN sending_address;
	int sending_address_len = sizeof(sending_address);

	if ((!is_initialized) || (data == NULL) || (dataLength > MAX_PACKET) || (destination == NULL))
	{
		return 0;
	}

	sending_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (sending_socket == INVALID_SOCKET)
	{
		return FALSE;
	}

	sending_address.sin_family = AF_INET;
	sending_address.sin_port = htons(destination->port);
	InetPton(AF_INET, destination->address, &(sending_address.sin_addr.S_un.S_addr));

	if (sendto(sending_socket, data, dataLength, 0, (SOCKADDR *)&sending_address, sending_address_len) != dataLength)
	{
		return_value = FALSE;
	}

	closesocket(sending_socket);

	return return_value;
}

BOOL ClayWorm_Available()
{
	SOCKADDR_IN sender_address;
	int sender_address_size = sizeof(sender_address);

	if (!is_initialized)
	{
		return FALSE;
	}

	if (is_peeked)
	{
		return TRUE;
	}

	if ((msg_peek_size = recvfrom(receiving_socket, msg_peek, MAX_PACKET, 0, (SOCKADDR *)&sender_address, &sender_address_size)) > 0)
	{
		is_peeked = TRUE;
		InetNtop(AF_INET, &(sender_address.sin_addr.S_un.S_addr), addr_peek, 16);
	
		return TRUE;
	}
	else
	{
		return FALSE;
	}
}

int ClayWorm_Receive(uint8_t* data, uint32_t dataLength, TCHAR source_address[ADDRESS_MAX_LENGTH])
{
	SOCKADDR_IN sender_address;
	int sender_address_size = sizeof(sender_address);
	int bytes_received;

	if ((!is_initialized) || (data == NULL) || (dataLength > MAX_PACKET) || (source_address == NULL))
	{
		return 0;
	}

	memset(source_address, 0, ADDRESS_MAX_LENGTH);

	if (!is_peeked)
	{
		bytes_received = recvfrom(receiving_socket, data, dataLength, 0, (SOCKADDR *)&sender_address, &sender_address_size);
		if (bytes_received > 0)
		{
			InetNtop(AF_INET, &(sender_address.sin_addr.S_un.S_addr), source_address, ADDRESS_MAX_LENGTH);
		}

		return bytes_received;
	}
	else
	{
		is_peeked = FALSE;
		memcpy(data, msg_peek, msg_peek_size);
		memcpy(source_address, addr_peek, ADDRESS_MAX_LENGTH);
		memset(addr_peek, 0, ADDRESS_MAX_LENGTH);
		memset(msg_peek, 0, MAX_PACKET);

		return msg_peek_size;
	}
}
