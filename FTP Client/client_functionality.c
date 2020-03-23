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

			if (!ClayWorm_Receive((uint8_t *)&receivedPacket, SYN_PACKET_SIZE, &sourceAddr))
			{
				_tprintf(TEXT("Error in receiving SYN packet!\n"));
				SetLastError(ERROR_UNIDENTIFIED_ERROR);
				return 0;
			}

			if (memcmp(&sourceAddr, serverAddress, sizeof(ClayWormAddress)) != 0)
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
			
			SetLastError(0);
			return receivedPacket.numberOfChunks;
		
		}
	}
	
}

BOOL _SaveFrag(USHORT fragSize, BYTE * fragData, BYTE fragIndex)
{
	HANDLE fragFile;
	DWORD bytesWritten;
	TCHAR fragFileName[MAX_PATH] = { 0 };
	_stprintf_s(fragFileName, MAX_PATH, TEXT("%u.tmp"), fragIndex);

	fragFile = CreateFile(
		fragFileName, // lpFileName
		GENERIC_WRITE, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		CREATE_NEW, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (fragFile == INVALID_HANDLE_VALUE)
	{
		if (GetLastError() == ERROR_FILE_EXISTS)
		{
			return TRUE;
		}

		return FALSE;
	}

	if (!WriteFile(
		fragFile, // hFile
		fragData, // lpBuffer
		fragSize, // nNumberOfBytesToWrite
		&bytesWritten, // lpNumberOfBytesWritten
		NULL // lpOverlapped
	))
	{
		CloseHandle(fragFile);
		return FALSE;
	}

	CloseHandle(fragFile);
	return TRUE;
}

BOOL _SendSynAck(ClayWormAddress *serverAddress)
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

BOOL _SendEopAck(ClayWormAddress *serverAddress, DWORD phaseIndex, BYTE * ackArray)
{
	eopack_packet eopackPacket = { 0 };

	eopackPacket.headers.type = TYPE_EOPACK;

	eopackPacket.headers.crc = crc16(
		&(eopackPacket.headers.type), // data
		EOPACK_PACKET_SIZE - CRC_SIZE // size
	);

	eopackPacket.ackPhase = phaseIndex;
	memcpy(eopackPacket.ackField, ackArray, ACK_BITFIELD_SIZE);

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

BOOL _GetFirstPacketOfPhase(ClayWormAddress *serverAddress, DWORD phaseIndex, BYTE * pReceivedPacket)
{
	USHORT receivedBytes = 0;
	DWORD lastGoodPacketTime = GetTickCount();
	ClayWormAddress sourceAddr = { 0 };
	dynamic_packet receivedPacketDynamic = { (p_syn_packet)pReceivedPacket };
	BYTE finalAckArray[ACK_BITFIELD_SIZE] = { 0 };
	memset(finalAckArray, 0xff, ACK_BITFIELD_SIZE);

	while (TRUE)
	{
		
		if (!phaseIndex)
		{
			if (!_SendSynAck(serverAddress))
			{
				return FALSE;
			}
		}

		else
		{
			if (!_SendEopAck(serverAddress, phaseIndex - 1, finalAckArray))
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
			)) < 2)
			{
				continue;
			}

			if (memcmp(&sourceAddr, serverAddress, sizeof(ClayWormAddress)) != 0)
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
				&(receivedPacketDynamic.asPSH->headers.type), // data
				receivedBytes - CRC_SIZE // size
			) != receivedPacketDynamic.asPSH->headers.crc)
			{
				continue;
			}


			if (receivedPacketDynamic.asPSH->headers.type == TYPE_EOP)
			{
				if (receivedPacketDynamic.asEOP->fragPhase == phaseIndex)
				{
					return TRUE;
				}
			}

			if (receivedPacketDynamic.asPSH->headers.type == TYPE_PSH)
			{
				if ((receivedPacketDynamic.asPSH->fragPhase == phaseIndex) &&
					(receivedPacketDynamic.asPSH->fragIndex < MAX_CHUNKS))
				{
					return TRUE;
				}
			}

			if (receivedPacketDynamic.asFIN->headers.type == TYPE_FIN)
			{
				return TRUE;
			}
		}
	}
}

BOOL _IsPhaseCompleted(BYTE ackField[ACK_BITFIELD_SIZE], DWORD chunksInPhase)
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
	DWORD chunksInPhase;
	DWORD currentPhase;
	DWORD lastGoodPacketTime;
	
	BOOL isEOP = FALSE;
	USHORT bytesReceived = 0;
	DWORD numberOfPhases = ((numberOfChunks / MAX_CHUNKS) + (numberOfChunks % MAX_CHUNKS != 0));
	BYTE ackArray[16] = { 0 };
	BYTE * receivedPacketAsBytes[MAX_PACKET] = { 0 };
	dynamic_packet receivedPacket = {(p_syn_packet)receivedPacketAsBytes};
	ClayWormAddress sourceAddr = { 0 };

	for (currentPhase = 0; currentPhase < numberOfPhases; currentPhase++)
	{
		chunksInPhase = min(numberOfChunks, MAX_CHUNKS);
		if (!_GetFirstPacketOfPhase(serverAddress, currentPhase, (BYTE *)receivedPacketAsBytes))
		{
			return FALSE;
		}

		lastGoodPacketTime = GetTickCount();

		goto l_after_first_phase_packet_received;
		
		while (!_IsPhaseCompleted(ackArray, chunksInPhase))
		{
			while (!ClayWorm_Available())
			{
				memset(receivedPacketAsBytes, 0, MAX_PACKET);
				memset(&sourceAddr, 0, sizeof(ClayWormAddress));
				if ((bytesReceived = (USHORT)ClayWorm_Receive(
					(uint8_t *)receivedPacketAsBytes, 
					MAX_PACKET, 
					&sourceAddr
				)) < 2)
				{
					return FALSE;
				}

				if (memcmp(&sourceAddr, serverAddress, sizeof(ClayWormAddress)) != 0)
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
					&(receivedPacket.asPSH->headers.type), // data
					bytesReceived - CRC_SIZE // size
				) != receivedPacket.asPSH->headers.crc)
				{
					continue;
				}

			l_after_first_phase_packet_received:

				if ((receivedPacket.asEOP->headers.type == TYPE_EOP) &&
					(receivedPacket.asEOP->fragPhase == currentPhase))
				{
					isEOP = TRUE;
					continue;
				}

				if ((receivedPacket.asPSH->headers.type == TYPE_PSH) &&
					(receivedPacket.asPSH->fragPhase == currentPhase) &&
					!(CHECK_ACK(ackArray, receivedPacket.asPSH->fragIndex)))
				{
					if (!_SaveFrag(
						receivedPacket.asPSH->fragSize, // fragSize
						(BYTE *)(receivedPacket.asPSH + 1), // fragData
						receivedPacket.asPSH->fragIndex // fragIndex
					))
					{
						return FALSE;
					}

					ACK_CHUNK(ackArray, receivedPacket.asPSH->fragIndex);
				}
			}
		}
		
		numberOfChunks -= chunksInPhase;
		memset(ackArray, 0, ACK_BITFIELD_SIZE);
		if (!GatherChunks(fileToWrite, MAX_PSH_DATA))
		{
			return FALSE;
		}
	}

	while (TRUE)
	{
		if (!_GetFirstPacketOfPhase(serverAddress, currentPhase, (BYTE *)receivedPacketAsBytes))
		{
			return FALSE;
		}

		if (receivedPacket.asFIN->headers.type == TYPE_FIN)
		{
			return TRUE;
		}
	}
}

BOOL HandleClient(PPARAMS params)
{
	HANDLE fileToSave;
	DWORD numberOfChunks;
	BOOL returnValue = FALSE;
	ClayWormAddress serverAddress = { 0 };
	USHORT portToListen = atoi(params->argv[3]);
	if (!ClayWorm_Initialize(portToListen))
	{
		goto l_return;
	}

	_tcsncpy_s(
		(TCHAR *)&(serverAddress.address), // _Dst
		16,
		(TCHAR*)params->argv[1], // _Source
		15 // _Count
	);

	serverAddress.port = atoi(params->argv[2]);

	fileToSave = CreateFile(
		params->argv[4], // lpFileName
		GENERIC_WRITE, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		CREATE_ALWAYS, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (fileToSave == INVALID_HANDLE_VALUE)
	{
		goto l_clayworm_cleanup;
	}

	numberOfChunks = ListenForSYN(&serverAddress);

	if (GetLastError())
	{
		goto l_close_file;
	}

	if (!GetFileAndFinish(&serverAddress, fileToSave, numberOfChunks))
	{
		goto l_close_file;
	}

	returnValue = TRUE;

l_close_file:
	CloseHandle(fileToSave);
l_clayworm_cleanup:
	ClayWorm_Cleanup();
l_return:
	return returnValue;
}