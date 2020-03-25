#include <WS2tcpip.h>
#include <Windows.h>
#include <stdio.h>
#include <winsvc.h>
#include <tchar.h>
#include "../ClayWorm/clayworm.h"
#include "server_functionality.h"

#define SERVICE_NAME  _T("FTPServer")

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL; // "The service status handle does not have to be closed."
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;
DWORD dwCheckPoint = 1;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

BOOL ValidateParams(DWORD argc, LPTSTR * argv)
{
	HANDLE dummyFile;
	IN_ADDR addr = { 0 };

	if (argc != 5)
	{
		OutputDebugString(TEXT("Usage: \"handler.exe <client_ip> <client_port> <listen_port> <file_path>\"\n"));
		return FALSE;
	}

	if (InetPton(AF_INET, argv[1], &addr) <= 0)
	{
		OutputDebugString(TEXT("Error: the client IP address is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[2]) < 50000 || atoi(argv[2]) > 65535)
	{
		OutputDebugString(TEXT("Error: the client port is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[3]) < 50000 || atoi(argv[3]) > 65535)
	{
		OutputDebugString(TEXT("Error: the listen port is invalid!\n"));
		return FALSE;
	}

	dummyFile = CreateFile(
		argv[4], // lpFileName
		GENERIC_READ, // dwDesiredAccess
		0, // dwShareMode
		NULL, // lpSecurityAttributes
		OPEN_EXISTING, // dwCreationDisposition
		0, // dwFlagsAndAttributes
		NULL // hTemplateFile
	);

	if (dummyFile == INVALID_HANDLE_VALUE)
	{
		OutputDebugString(TEXT("Error: the file given is invalid!\n"));
		return FALSE;
	}

	CloseHandle(dummyFile);

	return TRUE;
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{	
	DWORD waitStatus;
	BOOL exitCode;
	HANDLE serverThread;
	HANDLE handleArray[2] = { 0 };
	
	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
		if ((serverThread = CreateThread(
			NULL, // lpSecurityAttributes
			0, // dwStackSize
			(LPTHREAD_START_ROUTINE)HandleServer, // lpStartAddress
			lpParam, // lpParameter
			0, //dwCreationFlags
			NULL // lpThreadId
		)) == NULL)
		{
			SetEvent(g_ServiceStopEvent);
			return GetLastError();
		};


		handleArray[0] = serverThread;
		handleArray[1] = g_ServiceStopEvent;

		waitStatus = WaitForMultipleObjects(
			2, // nCount
			handleArray, // lpHandles
			FALSE, // bWaitAll
			INFINITE // dwMilliseconds
		);

		switch (waitStatus)
		{
		case 0: // serverThread (and optionaly g_ServiceStopEvent) is signaled
			if (WaitForSingleObject(g_ServiceStopEvent, 0) == WAIT_OBJECT_0)
			{
				return ERROR_SUCCESS;
			}

			if (!GetExitCodeThread(serverThread, (DWORD *)&exitCode))
			{
				return GetLastError();
			}

			if (!exitCode)
			{
				return ERROR_UNIDENTIFIED_ERROR;
			}
			
			break;
		
		case 1: // g_ServiceStopEvent is signaled
			TerminateThread(serverThread, ERROR_SERVICE_DISABLED);
			ClayWorm_Cleanup();
			return 0;

		default:
			TerminateThread(serverThread, ERROR_WAIT_1);
			ClayWorm_Cleanup();
			SetEvent(g_ServiceStopEvent);
			return 1;
		}


	}

	
	return 0;
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode)
{
	switch (CtrlCode)
	{
	case SERVICE_CONTROL_STOP:

		if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
			break;

		/*
		* Perform tasks necessary to stop the service here
		*/

		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
		g_ServiceStatus.dwWin32ExitCode = 0;
		g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			OutputDebugString(_T(
				"My Sample Service: ServiceCtrlHandler: SetServiceStatus returned error"));
		}

		// This will signal the worker thread to start shutting down
		SetEvent(g_ServiceStopEvent);

		break;

	default:
		break;
	}
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv)
{	
	
	PARAMS params;
	// Register our service control handler with the SCM
	g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

	if (g_StatusHandle == NULL)
	{
		return;
	}

	if (!ValidateParams(argc, argv))
	{
		return;
	}


	// Tell the service controller we are starting
	ZeroMemory(&g_ServiceStatus, sizeof(g_ServiceStatus));
	g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwServiceSpecificExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		return;
	}

	/*
	* Perform tasks necessary to start the service here
	*/

	// Create a service stop event to wait on later
	g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	if (g_ServiceStopEvent == NULL)
	{
		// Error creating event
		// Tell service controller we are stopped and exit
		g_ServiceStatus.dwControlsAccepted = 0;
		g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
		g_ServiceStatus.dwWin32ExitCode = GetLastError();
		g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

		SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
		return;

	}

	// Tell the service controller we are started
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		CloseHandle(g_ServiceStopEvent);
		return;
	}

	// Start a thread that will perform the main task of the service

	params.clientIP = argv[1];
	params.clientPort = (USHORT)atoi(argv[2]);
	params.listenPort = (USHORT)atoi(argv[3]);
	params.filePath = argv[4];

	HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, &params, 0, NULL);

	if (hThread == NULL)
	{
		CloseHandle(g_ServiceStopEvent);
		return;
	}

	

	// Wait until our worker thread exits signaling that the service needs to stop
	WaitForSingleObject(hThread, INFINITE);

	/*
	* Perform any cleanup tasks
	*/

	CloseHandle(g_ServiceStopEvent);

	// Tell the service controller we are stopped
	g_ServiceStatus.dwControlsAccepted = 0;
	g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = dwCheckPoint++;

	SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

	return;
}


int _tmain(int argc, PTCHAR *argv)
{	
	SERVICE_TABLE_ENTRY ServiceTable[] =
	{
		{ SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain },
		{ NULL, NULL }
	};

	if (StartServiceCtrlDispatcher(ServiceTable) == FALSE)
	{
		return GetLastError();
	}

	return 0;
}