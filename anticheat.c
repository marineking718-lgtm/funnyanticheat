// Build with: cl /W4 anticheat.c user32.lib advapi32.lib psapi.lib
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <wchar.h>

#define REG_PATH L"Software\\anticheat"

static BOOL suspicious_text(const wchar_t *text)
{
	static const wchar_t *names[] = {
		L"cheat", L"hack", L"inject", L"trainer", L"x64dbg", L"ollydbg", L"ida"
	};
	wchar_t lower[MAX_PATH];
	size_t i;

	wcsncpy_s(lower, MAX_PATH, text, _TRUNCATE);
	CharLowerBuffW(lower, (DWORD)wcslen(lower));
	for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i)
		if (wcsstr(lower, names[i]) != NULL) return TRUE;
	return FALSE;
}

static DWORD get_remaining(void)
{
	HKEY key;
	DWORD value = 9, type = 0, size = sizeof(value);
	if (RegOpenKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
		RegQueryValueExW(key, L"remaining", NULL, &type, (BYTE *)&value, &size);
		RegCloseKey(key);
	}
	return value > 9 ? 9 : value;
}

static void save_state(DWORD remaining)
{
	HKEY key;
	DWORD ban = remaining == 0 ? 1 : 0;
	if (RegCreateKeyExW(HKEY_CURRENT_USER, REG_PATH, 0, NULL, 0, KEY_SET_VALUE,
						NULL, &key, NULL) == ERROR_SUCCESS) {
		RegSetValueExW(key, L"remaining", 0, REG_DWORD,
					   (const BYTE *)&remaining, sizeof(remaining));
		RegSetValueExW(key, L"ban", 0, REG_DWORD,
					   (const BYTE *)&ban, sizeof(ban));
		RegCloseKey(key);
	}
}

static BOOL suspicious_process_running(void)
{
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W entry = { sizeof(entry) };
	BOOL found = FALSE;
	if (snapshot == INVALID_HANDLE_VALUE) return FALSE;
	if (Process32FirstW(snapshot, &entry)) {
		do {
			if (suspicious_text(entry.szExeFile)) { found = TRUE; break; }
		} while (Process32NextW(snapshot, &entry));
	}
	CloseHandle(snapshot);
	return found;
}

static BOOL suspicious_module_loaded(DWORD pid)
{
	HANDLE process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
	HMODULE modules[1024];
	DWORD bytes = 0, i, count;
	BOOL found = FALSE;
	if (!process) return FALSE;
	if (EnumProcessModules(process, modules, sizeof(modules), &bytes)) {
		count = bytes / sizeof(HMODULE);
		for (i = 0; i < count; ++i) {
			wchar_t path[MAX_PATH];
			if (GetModuleFileNameExW(process, modules[i], path, MAX_PATH) &&
				suspicious_text(path)) { found = TRUE; break; }
		}
	}
	CloseHandle(process);
	return found;
}

static void detect_and_terminate(void)
{
	DWORD remaining = get_remaining();
	if (remaining > 0) --remaining;
	save_state(remaining);

	if (remaining == 0)
		MessageBoxW(NULL, L"You are banned", L"Anti-cheat", MB_OK | MB_ICONWARNING);
	else {
		wchar_t message[128];
		_snwprintf_s(message, 128, _TRUNCATE,
					 L"Remaining:%lu ,if it ran to 0 you will get banned", remaining);
		MessageBoxW(NULL, message, L"Anti-cheat", MB_OK | MB_ICONWARNING);
	}
	TerminateProcess(GetCurrentProcess(), 1);
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show)
{
	(void)instance; (void)previous; (void)command_line; (void)show;
	if (suspicious_process_running() || suspicious_module_loaded(GetCurrentProcessId()))
		detect_and_terminate();
	return 0;
}
