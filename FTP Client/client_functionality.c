#include "client_functionality.h"
#include "../File Handler/file_handler.h"
#include <stdio.h>

#define CHECK_ACK(a, i) ((a[(i) / 8] & (1 << (7 - ((i) % 8)))) != 0)
#define ACK_CHUNK(a, i) a[(i) / 8] |= (1 << (7 - ((i) % 8)))


DWORD ListenForSYN(ClayWormAddress *serverAddress)
{
	syn_packet receivedPacket = { 0 };
	ClayWormAddress sourceAddr = { 0 };

	while (TRUE)
	{
		while (ClayWorm_Available())
		{
			memset(&receivedPacket, 0, SYN_PACKET_SIZE);
			memset(&sourceAddr, 0, sizeof(ClayWormAddress));

			if (ClayWorm_Receive(
				(uint8_t *)&receivedPacket, 
				SYN_PACKET_SIZE, 
				&sourceAddr
			) != SYN_PACKET_SIZE)
			{
				continue;
			}

			if (_tcsncmp(sourceAddr.address, serverAddress->address, 16) != 0)
			{
				continue;
			}

			if (crc16(
				&(receivedPacket.headers.type), // data
				SYN_PACKET_SIZE - CRC_SIZE // size
			) != receivedPacket.headers.crc)
			{
				continue;
			}

			if (receivedPacket.headers.type != (TYPE_SYN))
			{
				continue;
			}
			
			return receivedPacket.numberOfChunks;
		
		}
	}
	
}


static BOOL SendSynAck(ClayWormAddress *serverAddress)
{
	synack_packet synackPacket = { 0 };

	synackPacket.headers.type = TYPE_SYNACK;

	synackPacket.headers.crc = crc16(
		&(synackPacket.headers.type), // data
		SYNACK_PACKET_SIZE - CRC_SIZE // size
	);

	if (!ClayWorm_Send(
		(uint8_t *)&synackPacket, // data
		SYNACK_PACKET_SIZE, // dataLength
		serverAddress // destination
	))
	{
		_tprintf(TEXT("Error: could not send the SYN/ACK packet!\n"));
		return FALSE;
	}

	return TRUE;
}

static BOOL SendEopAck(ClayWormAddress *serverAddress, DWORD phaseIndex, BYTE * ackArray)
{
	eopack_packet eopackPacket = { 0 };

	eopackPacket.headers.type = TYPE_EOPACK;

	eopackPacket.ackPhase = phaseIndex;
	memcpy(eopackPacket.ackField, ackArray, ACK_BITFIELD_SIZE);
	
	eopackPacket.headers.crc = crc16(
		&(eopackPacket.headers.type), // data
		EOPACK_PACKET_SIZE - CRC_SIZE // size
	);

	if (!ClayWorm_Send(
		(uint8_t *)&eopackPacket, // data
		EOPACK_PACKET_SIZE, // dataLength
		serverAddress // destination
	))
	{
		_tprintf(TEXT("Error: could not send the SYN packet!\n"));
		return FALSE;
	}

	return TRUE;
}

static BOOL GetFirstPacketOfPhase(ClayWormAddress *serverAddress, DWORD phaseIndex, p_dynamic_packet pReceivedPacket)
{
	USHORT receivedBytes = 0;
	DWORD lastGoodPacketTime = GetTickCount();
	ClayWormAddress sourceAddr = { 0 };
	BYTE finalAckArray[ACK_BITFIELD_SIZE] = { 0 };
	memset(finalAckArray, 0xff, ACK_BITFIELD_SIZE);

	while (TRUE)
	{
		
		if (!phaseIndex)
		{
			if (!SendSynAck(serverAddress))
			{
				return FALSE;
			}
		}

		else
		{
			if (!SendEopAck(serverAddress, phaseIndex - 1, finalAckArray))
			{
				return FALSE;
			}
		}

		while (ClayWorm_Available())
		{
			memset(pReceivedPacket, 0, MAX_PACKET);
			memset(&sourceAddr, 0, sizeof(ClayWormAddress));
			if ((receivedBytes = (USHORT)ClayWorm_Receive(
				(uint8_t *)pReceivedPacket, // data
				MAX_PACKET, // dataLength
				&sourceAddr // source_address
			)) < PACKET_HEADERS_SIZE)
			{
				continue;
			}

			if (_tcsncmp(sourceAddr.address, serverAddress->address, 16) != 0)
			{
				if (GetTickCount() - lastGoodPacketTime >= PROTOCOL_TIMEOUT)
				{
					_tprintf(TEXT("Error: timeout exceeded!\n"));
					return FALSE;
				}
				continue;
			}

			lastGoodPacketTime = GetTickCount();

			if (crc16(
				&(pReceivedPacket->asPSH.pshHeaders.headers.type), // data
				receivedBytes - CRC_SIZE // size
			) != pReceivedPacket->asPSH.pshHeaders.headers.crc)
			{
				continue;
			}


			if (pReceivedPacket->asEOP.headers.type == TYPE_EOP)
			{
				if (pReceivedPacket->asEOP.fragPhase == phaseIndex)
				{
					return TRUE;
				}
			}

			if (pReceivedPacket->asPSH.pshHeaders.headers.type == TYPE_PSH)
			{
				if ((pReceivedPacket->asPSH.pshHeaders.fragPhase == phaseIndex) &&
					(pReceivedPacket->asPSH.pshHeaders.fragIndex < MAX_CHUNKS) &&
					(pReceivedPacket->asPSH.pshHeaders.fragSize <= MAX_PSH_DATA))
				{
					return TRUE;
				}
			}

			if (pReceivedPacket->asFIN.headers.type == TYPE_FIN)
			{
				return TRUE;
			}
		}
	}
}

static BOOL IsPhaseCompleted(BYTE ackField[ACK_BITFIELD_SIZE], DWORD chunksInPhase)
{
	DWORD i;
	for (i = 0; i < chunksInPhase; i++)
	{
		if (!CHECK_ACK(ackField, i))
		{
			return FALSE;
		}

	}

	return TRUE;
}

BOOL GetFileAndFinish(ClayWormAddress *serverAddress, HANDLE fileToWrite, DWORD numberOfChunks)
{
	BYTE chunksInPhase;
	DWORD currentPhase;
	DWORD lastGoodPacketTime;
	
	BOOL isEOP = FALSE;
	USHORT bytesReceived = 0;
	DWORD numberOfPhases = ((numberOfChunks / MAX_CHUNKS) + (numberOfChunks % MAX_CHUNKS != 0));
	BYTE ackArray[16] = { 0 };
	p_chunk_t chunksArray[MAX_CHUNKS] = { 0 };
	dynamic_packet receivedPacket = { 0 };
	ClayWormAddress sourceAddr = { 0 };

	if (!AllocateChunks(chunksArray))
	{
		return FALSE;
	}

	for (currentPhase = 0; currentPhase < numberOfPhases; currentPhase++)
	{
		chunksInPhase = (BYTE)min(numberOfChunks, MAX_CHUNKS);
		if (!GetFirstPacketOfPhase(serverAddress, currentPhase, &receivedPacket))
		{
			return FALSE;
		}

		lastGoodPacketTime = GetTickCount();

		goto l_after_first_phase_packet_received;
		
		while (!IsPhaseCompleted(ackArray, chunksInPhase))
		{
			while (ClayWorm_Available())
			{
				memset(&receivedPacket, 0, sizeof(dynamic_packet));
				memset(&sourceAddr, 0, sizeof(ClayWormAddress));
				if ((bytesReceived = (USHORT)ClayWorm_Receive(
					(uint8_t *)&receivedPacket, 
					MAX_PACKET, 
					&sourceAddr
				)) < PACKET_HEADERS_SIZE)
				{
					continue;
				}

				if (_tcsncmp(sourceAddr.address, serverAddress->address, 16) != 0)
				{
					if (GetTickCount() - lastGoodPacketTime >= PROTOCOL_TIMEOUT)
					{
						_tprintf(TEXT("Error: timeout exceeded!\n"));
						FreeChunks(chunksArray);
						return FALSE;
					}
					continue;
				}

				lastGoodPacketTime = GetTickCount();

				if (crc16(
					&(receivedPacket.asPSH.pshHeaders.headers.type), // data
					bytesReceived - CRC_SIZE // size
				) != receivedPacket.asPSH.pshHeaders.headers.crc)
				{
					continue;
				}

			l_after_first_phase_packet_received:

				if ((receivedPacket.asEOP.headers.type == TYPE_EOP) &&
					(receivedPacket.asEOP.fragPhase == currentPhase))
				{
					isEOP = TRUE;
					continue;
				}

				if ((receivedPacket.asPSH.pshHeaders.headers.type == TYPE_PSH) &&
					(receivedPacket.asPSH.pshHeaders.fragPhase == currentPhase) &&
					!(CHECK_ACK(ackArray, receivedPacket.asPSH.pshHeaders.fragIndex)))
				{
					chunksArray[receivedPacket.asPSH.pshHeaders.fragIndex]->chunkSize =
						receivedPacket.asPSH.pshHeaders.fragSize;

					memcpy(
						chunksArray[receivedPacket.asPSH.pshHeaders.fragIndex]->data,
						receivedPacket.asPSH.data,
						receivedPacket.asPSH.pshHeaders.fragSize
					);

					ACK_CHUNK(ackArray, receivedPacket.asPSH.pshHeaders.fragIndex);
				}
			}

			if (isEOP)
			{
				if (!SendEopAck(serverAddress, currentPhase, ackArray))
				{
					FreeChunks(chunksArray);
					return FALSE;
				}
			}
		}
		
		numberOfChunks -= chunksInPhase;
		memset(ackArray, 0, ACK_BITFIELD_SIZE);
		if (!GatherChunks(fileToWrite, chunksInPhase, chunksArray))
		{
			FreeChunks(chunksArray);
			return FALSE;
		}

	}

	if (!FreeChunks(chunksArray))
	{
		return FALSE;
	}

	while (TRUE)
	{
		if (!GetFirstPacketOfPhase(serverAddress, currentPhase, &receivedPacket))
		{
			return FALSE;
		}

		if (receivedPacket.asFIN.headers.type == TYPE_FIN)
		{
			return TRUE;
		}
	}
}

BOOL HandleClient(PPARAMS params)
{
	HANDLE fileToSave;
	DWORD numberOfChunks;
	ClayWormAddress serverAddress = { 0 };
	USHORT portToListen = params->listenPort;
	if (!ClayWorm_Initialize(portToListen))
	{
		return FALSE;
	}

	_tcsncpy_s(
		(TCHAR *)&(serverAddress.address), // _Dst
		16,
		(TCHAR*)params->serverIP, // _Source
		15 // _Count
	);

	serverAddress.port = params->serverPort;

	fileToSave = CreateFile(
		params->filePath, // lpFileName
		GENERIC_WRITE, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		CREATE_ALWAYS, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (fileToSave == INVALID_HANDLE_VALUE)
	{
		ClayWorm_Cleanup();
		return FALSE;
	}

	numberOfChunks = ListenForSYN(&serverAddress);

	if (!GetFileAndFinish(&serverAddress, fileToSave, numberOfChunks))
	{
		CloseHandle(fileToSave);
		ClayWorm_Cleanup();
		return FALSE;
	}

	CloseHandle(fileToSave);
	ClayWorm_Cleanup();
	return TRUE;
}