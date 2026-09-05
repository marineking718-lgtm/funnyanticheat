// Windows module-count integrity monitor.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>

static DWORD module_count(DWORD pid)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
								FALSE, pid);
	HMODULE modules[1024];
	DWORD needed = 0;
	DWORD count = 0;
	HANDLE snapshot;
	MODULEENTRY32W entry = { .dwSize = sizeof(entry) };

	if (!process)
		return 0;

	if (EnumProcessModulesEx(process, modules, sizeof(modules), &needed,
							LIST_MODULES_ALL)) {
		count = needed / sizeof(HMODULE);
		CloseHandle(process);
		return count;
	}

	CloseHandle(process);

	snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE |
											TH32CS_SNAPMODULE32, pid);
	if (Module32FirstW(snapshot, &entry)) {
		do {
			++count;
		} while (Module32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return count;
}

static void trigger_anticheat(void)
{
	STARTUPINFOW si = { .cb = sizeof(si) };
	PROCESS_INFORMATION pi = { 0 };
	wchar_t command[] = L"anticheat.exe";

	if (CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_NO_WINDOW,
					   NULL, NULL, &si, &pi)) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
	}
}

int wmain(int argc, wchar_t **argv)
{
	DWORD pid;
	DWORD expected;
	HANDLE process;

	if (argc != 2) {
		fwprintf(stderr, L"Usage: %s <main-process-id>\n", argv[0]);
		return 2;
	}

	pid = wcstoul(argv[1], NULL, 10);
	if (!pid || pid == GetCurrentProcessId())
		return 2;

	process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION |
						  PROCESS_TERMINATE, FALSE, pid);
	if (!process)
		return 1;

	expected = module_count(pid);       // Baseline taken at launch.
	if (!expected) {
		CloseHandle(process);
		return 1;
	}

	for (;;) {
		DWORD current;
		DWORD exit_code;

		if (!GetExitCodeProcess(process, &exit_code) ||
			exit_code != STILL_ACTIVE)
			break;

		current = module_count(pid);
		if (!current || current != expected) {
			TerminateProcess(process, 0xC0000428u);
			trigger_anticheat();
			break;
		}
		Sleep(1000);
	}

	CloseHandle(process);
	return 0;
}
