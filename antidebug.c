#define WIN32_LEAN_AND_MEAN
#include <windows.h>

/* Set this to the installed service name for driver.c. */
#define DRIVER_SERVICE_NAME "driver"

static void unload_driver(void)
{
	SC_HANDLE manager = OpenSCManagerA(NULL, NULL, SC_MANAGER_CONNECT);
	if (manager == NULL)
		return;

	SC_HANDLE service = OpenServiceA(manager, DRIVER_SERVICE_NAME,
		SERVICE_STOP | SERVICE_QUERY_STATUS);
	if (service != NULL) {
		SERVICE_STATUS status;
		ControlService(service, SERVICE_CONTROL_STOP, &status);
		CloseServiceHandle(service);
	}

	CloseServiceHandle(manager);
}

/* Returns nonzero if a debugger is attached to this process. */
int antidebugger_detected(void)
{
	BOOL remote_debugger = FALSE;

	if (IsDebuggerPresent())
		goto debugger_detected;

	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &remote_debugger) &&
		remote_debugger)
		goto debugger_detected;

	return 0;

debugger_detected:
	MessageBoxA(NULL, "This program protected by anti-debugging", "Warning",
		MB_OK | MB_ICONWARNING);
	unload_driver();
	TerminateProcess(GetCurrentProcess(), 1);
	return 1;
}
