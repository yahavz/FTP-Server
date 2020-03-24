#include "../ClayWorm/clayworm.h"
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <stdlib.h>
#include "../Protocol/protocol.h"
#include "server_functionality.h"
#include "../File Handler/file_handler.h"

#define CHECK_ACK(a, i) ((a[(i) / 8] & (1 << (7 - ((i) % 8)))) != 0)

#define TEMP_DIR TEXT("server_tmp")

BOOL _ValidateParams(PPARAMS params)
{
	HANDLE dummyFile;
	IN_ADDR addr = { 0 };

	if (InetPton(AF_INET, params->clientIP, &addr) <= 0)
	{
		_tprintf(TEXT("Error: the client IP address is invalid!\n"));
		return FALSE;
	}

	if (params->clientPort < 1)
	{
		_tprintf(TEXT("Error: the client port is invalid!\n"));
		return FALSE;
	}

	if (params->listenPort < 1)
	{
		_tprintf(TEXT("Error: the listen port is invalid!\n"));
		return FALSE;
	}

	dummyFile = CreateFile(
		params->filePath, // lpFileName
		GENERIC_READ, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		OPEN_EXISTING, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (dummyFile == INVALID_HANDLE_VALUE)
	{
		_tprintf(TEXT("Error: the file given is invalid!\n"));
		return FALSE;
	}

	CloseHandle(dummyFile);

	return TRUE;

}

DWORD _ChunksCountOfFile(HANDLE file)
{
	unsigned long long fileSize = 0;
	unsigned long long numberOfChunks = 0;
	BY_HANDLE_FILE_INFORMATION fileInfo = { 0 };
	
	if (!GetFileInformationByHandle(
		file, // hFile
		&fileInfo // lpFileInformation
	))
	{
		_tprintf(TEXT("Error in getting file information for calculation of number of chunks!"));
		return 0;
	}

	fileSize += fileInfo.nFileSizeHigh;
	fileSize <<= 32;
	fileSize += fileInfo.nFileSizeLow;

	SetLastError(0);

	numberOfChunks = ((fileSize / MAX_PSH_DATA) + (fileSize % MAX_PSH_DATA != 0));

	if (numberOfChunks > MAXDWORD)
	{
		_tprintf(TEXT("file is to big!"));
		SetLastError(ERROR_FILE_TOO_LARGE);
		return 0;
	}

	return (DWORD)numberOfChunks;
}

DWORD _PhaseCountOfFile(HANDLE file)
{
	DWORD numberOfChunks = _ChunksCountOfFile(file);
	if ((numberOfChunks == 0) && (GetLastError != 0))
	{
		_tprintf(TEXT("Error in getting number of chunks for calculation of number of phases!"));
		SetLastError(GetLastError());
	}

	return ((numberOfChunks / MAX_CHUNKS) + (numberOfChunks % MAX_CHUNKS != 0));
}


BOOL ServerHandshake(ClayWormAddress *clientAddress, HANDLE file)
{
	syn_packet synPacket = { 0 };
	synack_packet receivedPacket = { 0 };
	ClayWormAddress sourceAddr = { 0 };
	synPacket.headers.type = TYPE_SYN;
	synPacket.numberOfChunks = _ChunksCountOfFile(file);
	if ((synPacket.numberOfChunks == 0) && (GetLastError() != 0))
	{
		return FALSE;
	}

	synPacket.headers.crc = crc16(
		&(synPacket.headers.type), // data
		SYN_PACKET_SIZE - CRC_SIZE // size
	);


	while (TRUE)
	{
		if (!ClayWorm_Send(
			(uint8_t *)&synPacket, // data
			SYN_PACKET_SIZE, // dataLength
			clientAddress // destination
		))
		{
			_tprintf(TEXT("Error: could not send the SYN packet!\n"));
			return FALSE;
		}

		while (ClayWorm_Available())
		{
			memset(&receivedPacket, 0, SYNACK_PACKET_SIZE);
			memset(&sourceAddr, 0, sizeof(ClayWormAddress));
			if (ClayWorm_Receive(
				(uint8_t *)&receivedPacket, // data
				SYNACK_PACKET_SIZE, // dataLength
				&sourceAddr // source_address
			) != SYNACK_PACKET_SIZE)
			{
				continue;
			}

			if (_tcsncmp(sourceAddr.address, clientAddress->address, 16) != 0)
			{
				continue;
			}

			if (crc16(
				&(receivedPacket.headers.type), // data
				SYNACK_PACKET_SIZE - CRC_SIZE // size
			) != receivedPacket.headers.crc)
			{
				continue;
			}

			if (receivedPacket.headers.type != (TYPE_SYNACK))
			{
				continue;
			}

			return TRUE;
		}
	}

	return FALSE;
}

BOOL _SendFrag(ClayWormAddress *clientAddress, DWORD phaseIndex, BYTE fragIndex)
{
	HANDLE fragFile;
	USHORT bytesRead;
	TCHAR fragFileName[MAX_PATH] = { 0 };
	BYTE fragData[MAX_PSH_DATA] = { 0 };
	BYTE packetAsBytes[MAX_PACKET] = { 0 };
	p_psh_packet pshPacket = (p_psh_packet)packetAsBytes;
	_stprintf_s(fragFileName, MAX_PATH, TEXT("%s\\%u.tmp"), TEMP_DIR, fragIndex);
	
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
		(DWORD *)&bytesRead, // nNumberOfBytesRead
		NULL // lpOverlapped
	))
	{
		CloseHandle(fragFile);
		return FALSE;
	}

	pshPacket->headers.type = TYPE_PSH;
	pshPacket->fragIndex = fragIndex;
	pshPacket->fragPhase = phaseIndex;
	pshPacket->fragSize = bytesRead;
	memcpy(packetAsBytes + PSH_PACKET_SIZE, fragData, bytesRead);

	pshPacket->headers.crc = crc16(
		&(pshPacket->headers.type), // data
		PSH_PACKET_SIZE + bytesRead - CRC_SIZE // size
	);

	if (!ClayWorm_Send((uint8_t *)pshPacket, PSH_PACKET_SIZE + bytesRead, clientAddress))
	{
		CloseHandle(fragFile);
		return FALSE;
	}
	
	CloseHandle(fragFile);
	return TRUE;
}

BOOL _SendEOP(ClayWormAddress *clientAddress, DWORD phaseIndex)
{
	eop_packet eopPacket = { 0 };

	eopPacket.headers.type = TYPE_EOP;
	eopPacket.fragPhase = phaseIndex;
	eopPacket.headers.crc = crc16(
		&(eopPacket.headers.type), // data
		EOP_PACKET_SIZE - CRC_SIZE // size
	);

	if (!ClayWorm_Send((uint8_t *)&eopPacket, EOP_PACKET_SIZE, clientAddress))
	{
		return FALSE;
	}
	return TRUE;
}

BOOL _IsPhaseCompleted(BYTE ackField[ACK_BITFIELD_SIZE])
{
	int i;
	for (i = 0; i < ACK_BITFIELD_SIZE ; i++)
	{
		if (ackField[i] != 0xff)
		{
			return FALSE;
		}

	}

	return TRUE;
}

BOOL SendFile(ClayWormAddress *clientAddress, HANDLE file)
{
	DWORD currentPhase;
	BYTE currentFrag;
	DWORD numberOfPhases;
	DWORD firstPhaseEOPTime;
	DWORD numberOfChunks;
	
	
	BOOL packetFound = FALSE;
	ClayWormAddress sourceAddr = { 0 };
	eopack_packet eopackPacket = { 0 };
	BYTE ackArray[ACK_BITFIELD_SIZE] = { 0 };

	numberOfPhases = _PhaseCountOfFile(file);
	if ((numberOfPhases == 0) && (GetLastError() != 0))
	{
		return FALSE;
	}

	numberOfChunks = _ChunksCountOfFile(file);
	if ((numberOfChunks == 0) && (GetLastError() != 0))
	{
		return FALSE;
	}

	for (currentPhase = 0; currentPhase < numberOfPhases; currentPhase++)
	{
		
		memset(&ackArray, 0, sizeof(ackArray));
		
		if (!CreateDirectory(
			TEMP_DIR, // lpPathName
			NULL // lpSecurityAttributes
		))
		{
			if (GetLastError() != ERROR_ALREADY_EXISTS)
			{
				return FALSE;
			}
		}

		if (!ReadPhaseAndWriteChunks(file, TEMP_DIR, MAX_PSH_DATA))
		{
			return FALSE;
		}

		while (!_IsPhaseCompleted((BYTE *)&ackArray))
		{
			for (currentFrag = 0; currentFrag < min(numberOfChunks, MAX_CHUNKS); currentFrag++)
			{
				// check if the frag was ACKed before
				
				if (CHECK_ACK(ackArray, currentFrag))
				{
					continue;
				}
				
				if (!_SendFrag(clientAddress, currentPhase, currentFrag))
				{
					DeleteChunksTempFiles(TEMP_DIR);
					return FALSE;
				}
				
			}

			firstPhaseEOPTime = GetTickCount();

			while (TRUE)
			{
				if (GetTickCount() - firstPhaseEOPTime >= PROTOCOL_TIMEOUT)
				{
					_tprintf(TEXT("Timeout exceeded! The client is not up probably."));
					DeleteChunksTempFiles(TEMP_DIR);
					return FALSE;
				}

				if (!_SendEOP(clientAddress, currentPhase))
				{
					DeleteChunksTempFiles(TEMP_DIR);
					return FALSE;
				}

				while (ClayWorm_Available())
				{
					memset(&eopackPacket, 0, EOPACK_PACKET_SIZE);
					memset(&sourceAddr, 0, sizeof(ClayWormAddress));
					if (ClayWorm_Receive(
						(uint8_t *)&eopackPacket, 
						EOPACK_PACKET_SIZE, 
						&sourceAddr
					) != EOPACK_PACKET_SIZE)
					{
						continue;
					}

					if (_tcsncmp(sourceAddr.address, clientAddress->address, 16) != 0)
					{
						continue;
					}

					firstPhaseEOPTime = GetTickCount();

					if (crc16(
						&(eopackPacket.headers.type), // data 
						EOPACK_PACKET_SIZE - CRC_SIZE // size
					) != eopackPacket.headers.crc)
					
					{
						continue;
					}

					if (eopackPacket.headers.type != (TYPE_EOPACK))
					{
						continue;
					}


					if (eopackPacket.ackPhase == currentPhase)
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
				&(eopackPacket.ackField),
				sizeof(ackArray)
			);
		}

		numberOfChunks -= currentFrag;
		DeleteChunksTempFiles(TEMP_DIR);
	}
	
	return TRUE;
}

BOOL Finish(ClayWormAddress *clientAddress)
{
	fin_packet finPacket = { 0 };
	eopack_packet receivedPacket = { 0 };
	ClayWormAddress sourceAddr = { 0 };
	BOOL clientStillUp = FALSE;
	
	finPacket.headers.type = TYPE_FIN;
	finPacket.headers.crc = crc16(
		&(finPacket.headers.type), // data
		FIN_PACKET_SIZE - CRC_SIZE // size
	);

	do
	{		
		clientStillUp = FALSE;
		if (!ClayWorm_Send((uint8_t *)&finPacket, FIN_PACKET_SIZE, clientAddress))
		{
			return FALSE;
		}

		Sleep(5000);

		while (ClayWorm_Available())
		{
			memset(&receivedPacket, 0, MAX_PACKET);
			memset(&sourceAddr, 0, sizeof(ClayWormAddress));

			if (!ClayWorm_Receive((uint8_t *)&receivedPacket, MAX_PACKET, &sourceAddr))
			{
				return FALSE;
			}

			if (_tcsncmp(sourceAddr.address, clientAddress->address, 16) == 0)
			{
				clientStillUp = TRUE;
			}
		}
	} while (clientStillUp);
	
	return TRUE;
}


BOOL HandleServer(PPARAMS params)
{
	HANDLE fileToSend;
	USHORT portToListen;
	BOOL returnValue = FALSE;
	ClayWormAddress clientAddress = { 0 };
	
	if (!_ValidateParams(params))
	{
		return FALSE;
	}

	if (!ClayWorm_Initialize(portToListen))
	{
		return FALSE;
	}

	_tcsncpy_s(
		(TCHAR *)&(clientAddress.address), // _Dst
		16,
		(TCHAR*)params->clientIP, // _Source
		15 // _Count
	);

	clientAddress.port = params->clientPort;

	fileToSend = CreateFile(
		params->filePath, // lpFileName
		GENERIC_READ, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		OPEN_EXISTING, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (fileToSend == INVALID_HANDLE_VALUE)
	{
		ClayWorm_Cleanup();
		return FALSE;
	}

	if (!ServerHandshake(&clientAddress, fileToSend))
	{
		CloseHandle(fileToSend);
		ClayWorm_Cleanup();
		return FALSE;
	}

	if (!SendFile(&clientAddress, fileToSend))
	{
		CloseHandle(fileToSend);
		ClayWorm_Cleanup();
		return FALSE;
	}

	if (!Finish(&clientAddress))
	{
		CloseHandle(fileToSend);
		ClayWorm_Cleanup();
		return FALSE;
	}

	CloseHandle(fileToSend);
	ClayWorm_Cleanup();
	return TRUE;
}