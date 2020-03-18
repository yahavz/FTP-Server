#include <Windows.h>
#include <winsvc.h>
#include <tchar.h>
#include "../ClayWorm/clayworm.h"
#include "server_functionality.h"

#define SERVICE_NAME  _T("FTPServer")

typedef struct {
	int argc;
	PTCHAR * argv;
} PARAMS, *PPARAMS;

SERVICE_STATUS        g_ServiceStatus = { 0 };
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE                g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);


DWORD WINAPI ServiceWorkerThread(LPVOID lpParam)
{
	HANDLE file;
	PPARAMS params = (PPARAMS)lpParam;
	ClayWormAddress clientAddress = {0};
	BY_HANDLE_FILE_INFORMATION fileInfo = { 0 };
	DWORD64 fileSize = 0;
	DWORD numberOfChunks = 0;
	DWORD numberOfPhases = 0;

	//  Periodically check if the service has been requested to stop
	while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0)
	{
		
		if (!ClayWorm_Initialize(_ttoi(params->argv[3])))
		{
			return ERROR_UNKNOWN_FEATURE;
		}

		file = CreateFile(
			params->argv[4], // lpFileName
			GENERIC_READ, // dwDesiredAccess
			0, // dwShareMode
			NULL, // lpSecurityAttributes
			OPEN_EXISTING, // dwCreationDisposition
			0, // dwFlagsAndAttributes
			NULL //hTemplateFile
		);

		if (file == INVALID_HANDLE_VALUE)
		{
			return ERROR_INVALID_PARAMETER;
		}

		memcpy(&(clientAddress.address), params->argv[1], ADDRESS_MAX_LENGTH);
		clientAddress.port = atoi(params->argv[2]);

		if (!ServerHandshake(&clientAddress, file))
		{
			return ERROR_UNIDENTIFIED_ERROR;
		}

		if (!GetFileInformationByHandle(file, &fileInfo))
		{
			return ERROR_UNIDENTIFIED_ERROR;
		}

		fileSize += fileInfo.nFileSizeHigh;
		fileSize << 32;
		fileSize += fileInfo.nFileSizeLow;

		numberOfChunks = (fileSize / MAX_PSH_DATA) + (fileSize % MAX_PSH_DATA != 0);
		numberOfPhases = (numberOfChunks / MAX_FRAGMENT_AT_ONCE) +
			(numberOfChunks % MAX_FRAGMENT_AT_ONCE != 0);

		if (!SendFile(
			&clientAddress, // clientAddress
			file, // file
			numberOfPhases // numberOfPhases
		))
		{
			return ERROR_UNIDENTIFIED_ERROR;
		}

		if (!Finish(&clientAddress))
		{
			return ERROR_UNIDENTIFIED_ERROR;
		}
		break;
	}
	
	ClayWorm_Cleanup();
	return ERROR_SUCCESS;
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
		g_ServiceStatus.dwCheckPoint = 4;

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
		goto EXIT;
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
		OutputDebugString(_T(
			"My Sample Service: ServiceMain: SetServiceStatus returned error"));
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
		g_ServiceStatus.dwCheckPoint = 1;

		if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
		{
			OutputDebugString(_T(
				"My Sample Service: ServiceMain: SetServiceStatus returned error"));
		}
		goto EXIT;
	}

	// Tell the service controller we are started
	g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
	g_ServiceStatus.dwWin32ExitCode = 0;
	g_ServiceStatus.dwCheckPoint = 0;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		OutputDebugString(_T(
			"My Sample Service: ServiceMain: SetServiceStatus returned error"));
	}



	// Start a thread that will perform the main task of the service
	HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, &params, 0, NULL);

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
	g_ServiceStatus.dwCheckPoint = 3;

	if (SetServiceStatus(g_StatusHandle, &g_ServiceStatus) == FALSE)
	{
		OutputDebugString(_T(
			"My Sample Service: ServiceMain: SetServiceStatus returned error"));
	}

EXIT:
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