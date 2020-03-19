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

BOOL ValidateParams(int argc, PTCHAR * argv)
{
	HANDLE dummyFile;
	IN_ADDR addr = { 0 };

	if (argc != 5)
	{
		_tprintf(TEXT("Usage: \"handler.exe <client_ip> <client_port> <listen_port> <file_path>\"\n"));
		return FALSE;
	}

	if (InetPton(AF_INET, argv[1], &addr) <= 0)
	{
		_tprintf(TEXT("Error: the client IP address is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[2]) <= 0 || atoi(argv[2]) > 65535)
	{
		_tprintf(TEXT("Error: the client port is invalid!\n"));
		return FALSE;
	}

	if (atoi(argv[3]) <= 0 || atoi(argv[3]) > 65535)
	{
		_tprintf(TEXT("Error: the listen port is invalid!\n"));
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
		_tprintf(TEXT("Error: the file given is invalid!\n"));
		return FALSE;
	}

	CloseHandle(dummyFile);

	return TRUE;
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{	
	HANDLE handlesArray[2] = { 0 };
	HANDLE hThread = CreateThread(
		NULL, // lpThreadAttributes - NULL means default
		0, // dwStackSize - 0 means default
		HandleServer, // lpStartAddress
		lpParam, // lpParameter
		0, // dwCreationFlags
		NULL // lpThreadId
	);


	if (hThread == NULL)
	{
		return GetLastError();
	}
	
	handlesArray[0] = g_ServiceStopEvent;
	handlesArray[1] = hThread;

	WaitForMultipleObjects(
		2, // nCount
		handlesArray, // lpHandles
		FALSE, // bWaitAll
		INFINITE // dwMilliseconds
	);
	
	TerminateThread(
		hThread, // hThread 
		0 // dwExitCode
	);
	
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
	
	PARAMS params = { argc, argv };
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
		return;
	}

	// Start a thread that will perform the main task of the service
	HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, &params, 0, NULL);

	if (hThread == NULL)
	{
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