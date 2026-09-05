#define UNICODE
#define _UNICODE
#include <windows.h>

#define GAME_EXE_PATH L"game.exe"

// Declaration các hàm kiểm tra từ module khác
extern BOOL suspicious_process_running(void);
extern int antidebugger_detected(void);
extern int environment_is_virtualized(wchar_t *evidence, DWORD evidence_count);

// Khóa game.exe vào Job Object để Windows tự diệt Game nếu Launcher bị kill
static HANDLE attach_game_to_job_object(HANDLE hProcess) {
    HANDLE hJob = CreateJobObjectW(NULL, NULL);
    if (hJob == NULL) return NULL;

    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jeli = { 0 };
    jeli.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if (SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &jeli, sizeof(jeli))) {
        if (AssignProcessToJobObject(hJob, hProcess)) {
            return hJob;
        }
    }

    CloseHandle(hJob);
    return NULL;
}

static BOOL start_game_process(PROCESS_INFORMATION *pi) {
    STARTUPINFOW si = { sizeof(si) };
    wchar_t command[] = GAME_EXE_PATH;

    return CreateProcessW(
        NULL, command, NULL, NULL, FALSE,
        0, NULL, NULL, &si, pi
    );
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show) {
    (void)instance; (void)previous; (void)command_line; (void)show;
    wchar_t vm_evidence[256] = {0};
    PROCESS_INFORMATION game_pi = {0};

    // 1. Quét bảo mật ban đầu - Phát hiện bất thường là thoát im lặng ngay
    if (suspicious_process_running() ||
        antidebugger_detected() ||
        environment_is_virtualized(vm_evidence, 256)) {
        return 1;
    }

    // 2. Mở game.exe
    if (!start_game_process(&game_pi)) {
        return 1;
    }

    // 3. Liên kết vòng đời Game với Launcher qua Kernel Job Object
    HANDLE hJob = attach_game_to_job_object(game_pi.hProcess);

    // 4. Vòng lặp giám sát liên tục
    while (1) {
        DWORD exit_code;
        if (!GetExitCodeProcess(game_pi.hProcess, &exit_code) || exit_code != STILL_ACTIVE) {
            break; // Game tự tắt bình thường
        }

        // Phát hiện gian lận -> Cưỡng chế ngắt tiến trình Game âm thầm
        if (suspicious_process_running() || antidebugger_detected()) {
            TerminateProcess(game_pi.hProcess, 1);
            break;
        }

        Sleep(1000);
    }

    if (hJob) CloseHandle(hJob);
    CloseHandle(game_pi.hProcess);
    CloseHandle(game_pi.hThread);
    return 0;
}