#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <tchar.h>
#include "server_functionality.h"
#include "../ClayWorm/clayworm.h"
#include "../Protocol/protocol.h"
#include "../File Handler/file_handler.h"

#define MAX_PSH_DATA (MAX_PACKET - PSH_PACKET_SIZE)

BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file)
{
	DWORD64 fileSize = 0;
	BYTE synPacket[SYN_PACKET_SIZE] = { 0 };
	BYTE synackPacket[SYNACK_PACKET_SIZE] = { 0 };
	ClayWormAddress sourceAddr = { 0 };
	BY_HANDLE_FILE_INFORMATION fileInfo = { 0 };

	if (!GetFileInformationByHandle(
		file, // hFile
		&fileInfo // lpFileInformation
	))
	{
		CloseHandle(file);
		return FALSE;
	}
	
	CloseHandle(file);

	fileSize += fileInfo.nFileSizeHigh;
	fileSize << 32;
	fileSize += fileInfo.nFileSizeLow;

	((p_packet_headers)(&synPacket))->type = TYPE_SYN;
	((p_syn_packet)(&synPacket + PACKET_HEADERS_SIZE))->numberOfChunks =
		((fileSize / MAX_PSH_DATA) + (fileSize % MAX_PSH_DATA != 0));

	((p_packet_headers)(&synPacket))->crc = crc16(
		&synPacket + CRC_SIZE, // data 
		sizeof(synPacket) - CRC_SIZE // size
	);
	while (TRUE) 
	{
		if (!ClayWorm_Send(
			&synPacket, // data
			SYN_PACKET_SIZE, // dataLength
			clientAddress // destination
		))
		{
			_tprintf(TEXT("Error: could not send the SYN packet!\n"));
			return FALSE;
		}

		Sleep(1000);

		while (ClayWorm_Available())
		{
			memset(&synackPacket, 0, SYNACK_PACKET_SIZE);
			if (ClayWorm_Receive(
				&synackPacket, // data
				SYNACK_PACKET_SIZE, // dataLength
				&sourceAddr // source_address
			) != SYNACK_PACKET_SIZE)
			{
				continue;
			}

			if (memcmp(&sourceAddr, clientAddress, sizeof(ClayWormAddress)) != 0)
			{
				continue;
			}

			if (crc16(
				&synackPacket + CRC_SIZE,
				SYNACK_PACKET_SIZE - CRC_SIZE) != ((p_packet_headers)(&synackPacket))->crc)
			{
				continue;
			}

			if (((p_packet_headers)(&synackPacket))->type != (TYPE_SYN | TYPE_ACK))
			{
				continue;
			}

			return TRUE;
		}
	}
}

BOOL _SendFrag(ClayWormAddress *clientAddress, DWORD phaseIndex, BYTE fragIndex)
{
	HANDLE fragFile;
	DWORD bytesRead;
	TCHAR fragFileName[MAX_PATH] = { 0 };
	BYTE fragData[MAX_PSH_DATA] = { 0 };
	BYTE pshPacket[MAX_PACKET] = { 0 };
	_stprintf_s(fragFileName, MAX_PATH, TEXT("%u.tmp"), fragIndex);
	
	fragFile = CreateFile(
		fragFileName, // lpFileName
		GENERIC_READ, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		OPEN_EXISTING, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (fragFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_NOT_FOUND)
		{
			return TRUE;
		}

		return FALSE;
	}

	if (!ReadFile(
		fragFile, // hFile
		fragData, // lpBuffer
		MAX_PSH_DATA, // nNumberOfBytesToRead
		&bytesRead, // nNumberOfBytesRead
		NULL // lpOverlapped
	))
	{
		return FALSE;
	}

	((p_packet_headers)(&pshPacket))->type = TYPE_PSH;
	((p_psh_packet)(&pshPacket + PACKET_HEADERS_SIZE))->fragIndex = fragIndex;
	((p_psh_packet)(&pshPacket + PACKET_HEADERS_SIZE))->fragPhase = phaseIndex;
	((p_psh_packet)(&pshPacket + PACKET_HEADERS_SIZE))->fragSize = bytesRead;
	memcpy(&pshPacket + PSH_PACKET_SIZE, fragData, bytesRead);

	((p_packet_headers)(&pshPacket))->crc = crc16(
		&pshPacket + CRC_SIZE, // data
		PSH_PACKET_SIZE + bytesRead - CRC_SIZE // size
	);

	if (!ClayWorm_Send(&pshPacket, PSH_PACKET_SIZE + bytesRead, clientAddress))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL _SendEOP(ClayWormAddress *clientAddress, DWORD phaseIndex)
{
	BYTE eopPacket[EOP_PACKET_SIZE] = { 0 };

	((p_packet_headers)(&eopPacket))->type = TYPE_EOP;
	((p_eop_packet)(&eopPacket + PACKET_HEADERS_SIZE))->fragPhase = phaseIndex;
	((p_packet_headers)(&eopPacket))->crc = crc16(
		&eopPacket + CRC_SIZE, // data
		EOP_PACKET_SIZE - CRC_SIZE // size
	);

	if (!ClayWorm_Send(&eopPacket, EOP_PACKET_SIZE, clientAddress))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL _IsPhaseCompleted(BYTE ackField[ACK_BITFIELD_SIZE])
{
	int i;
	for (i = 0; i < (ACK_BITFIELD_SIZE / sizeof(DWORD)); i++)
	{
		if (((DWORD *)&ackField)[i] != MAXDWORD)
		{
			return FALSE;
		}

	}

	return TRUE;
}

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file, DWORD numberOfPhases)
{
	DWORD currentPhase;
	BYTE currentFrag;
	HANDLE currentFragFile;

	BOOL packetFound = FALSE;
	ClayWormAddress source = { 0 };
	BYTE eopackPacket[EOPACK_PACKET_SIZE] = { 0 };
	BYTE ackArray[ACK_BITFIELD_SIZE] = { 0 };
	BYTE currentFragData[MAX_PSH_DATA] = { 0 };
	
	for (currentPhase = 0; currentPhase < numberOfPhases; currentPhase++)
	{
		memset(&ackArray, 0, sizeof(ackArray));
		if (!ReadPhaseAndWriteChunks(file, MAX_PSH_DATA))
		{
			return FALSE;
		}

		while (!_IsPhaseCompleted(&ackArray))
		{
			for (currentFrag = 0; currentFrag < MAX_FRAGMENT_AT_ONCE; currentFrag++)
			{
				if (!_SendFrag(clientAddress, currentPhase, currentFrag))
				{
					DeleteChunksTempFiles();
					return FALSE;
				}
			}

			while (TRUE)
			{
				if (!_SendEOP(clientAddress, currentPhase))
				{
					DeleteChunksTempFiles();
					return FALSE;
				}

				Sleep(1000);

				while (ClayWorm_Available())
				{
					if (!ClayWorm_Receive(&eopackPacket, EOPACK_PACKET_SIZE, &source))
					{
						DeleteChunksTempFiles();
						return FALSE;
					}

					if (memcmp(&source, clientAddress, sizeof(ClayWormAddress)) != 0)
					{
						continue;
					}

					if (crc16(
						&eopackPacket + CRC_SIZE, // data 
						EOPACK_PACKET_SIZE - CRC_SIZE // size
					) != ((p_packet_headers)(&eopackPacket))->crc)
					{
						continue;
					}

					if (((p_packet_headers)(&eopackPacket))->type != (TYPE_EOP | TYPE_ACK))
					{
						continue;
					}

					if (((p_eopack_packet)(&eopackPacket + PACKET_HEADERS_SIZE))->ackPhase == currentPhase)
					{
						packetFound = TRUE;
						break;
					}
				}

				if (packetFound)
				{
					packetFound = FALSE;
					break;
				}

			}

			memcpy(
				ackArray,
				((p_eopack_packet)(&eopackPacket + PACKET_HEADERS_SIZE))->ackField,
				sizeof(ackArray)
			);
		}
	}
	
	return TRUE;
}

BOOL Finish(ClayWormAddress *clientAddress)
{
	BYTE finPacket[FIN_PACKET_SIZE] = { 0 };
	BYTE receivedPacket[MAX_PACKET] = { 0 };
	ClayWormAddress receivedAddr = { 0 };
	BOOL clientStillUp = FALSE;
	
	((p_packet_headers)(&finPacket))->type = TYPE_EOP;
	((p_packet_headers)(&finPacket))->crc = crc16(
		&finPacket + CRC_SIZE, // data
		FIN_PACKET_SIZE - CRC_SIZE // size
	);

	do
	{
		clientStillUp = FALSE;
		if (!ClayWorm_Send(&finPacket, FIN_PACKET_SIZE, clientAddress))
		{
			return FALSE;
		}

		Sleep(5000);

		while (ClayWorm_Available())
		{
			memset(&receivedPacket, 0, MAX_PACKET);

			if (!ClayWorm_Receive(&receivedPacket, MAX_PACKET, &receivedAddr))
			{
				return FALSE;
			}

			if (memcmp(&receivedAddr, clientAddress, sizeof(ClayWormAddress)) == 0)
			{
				clientStillUp = TRUE;
			}
		}
	} while (clientStillUp);
	
	return TRUE;
}