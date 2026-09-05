#include <windows.h>
#include <commctrl.h>
#include <intrin.h>
#include <stdio.h>
#include <wchar.h>

static int contains_virtualization_name(const wchar_t *text)
{
    static const wchar_t *names[] = {
        L"virtual", L"vmware", L"vbox", L"virtualbox", L"qemu",
        L"xen", L"kvm", L"parallels", L"hyper-v", L"hyperv"
    };
    size_t name_count = sizeof names / sizeof names[0];
    size_t index;

    if (text == NULL) {
        return 0;
    }

    for (index = 0; index < name_count; ++index) {
        if (wcsstr(text, names[index]) != NULL) {
            return 1;
        }
    }
    return 0;
}

static int read_firmware_value(const wchar_t *value_name, wchar_t *value, DWORD value_count)
{
    HKEY key = NULL;
    DWORD value_type = 0;
    DWORD value_bytes = value_count * sizeof value[0];
    LONG result;

    if (value == NULL || value_count == 0) {
        return 0;
    }
    value[0] = L'\0';

    result = RegOpenKeyExW(
        HKEY_LOCAL_MACHINE,
        L"HARDWARE\\DESCRIPTION\\System\\BIOS",
        0,
        KEY_READ,
        &key);
    if (result != ERROR_SUCCESS) {
        return 0;
    }

    result = RegQueryValueExW(
        key,
        value_name,
        NULL,
        &value_type,
        (LPBYTE)value,
        &value_bytes);
    RegCloseKey(key);

    if (result != ERROR_SUCCESS ||
        (value_type != REG_SZ && value_type != REG_EXPAND_SZ)) {
        value[0] = L'\0';
        return 0;
    }

    value[value_count - 1] = L'\0';
    return 1;
}

static int cpuid_reports_hypervisor(wchar_t *vendor, DWORD vendor_count)
{
    int basic_leaf[4];
    int feature_leaf[4];
    int hypervisor_leaf[4];

    if (vendor != NULL && vendor_count != 0) {
        vendor[0] = L'\0';
    }

    __cpuid(basic_leaf, 0);
    if (basic_leaf[0] < 1) {
        return 0;
    }

    __cpuid(feature_leaf, 1);
    if ((feature_leaf[2] & (1 << 31)) == 0) {
        return 0;
    }

    __cpuid(hypervisor_leaf, 0x40000000);
    if (vendor != NULL && vendor_count >= 13) {
        char raw_vendor[13];
        memcpy(raw_vendor + 0, &hypervisor_leaf[1], 4);
        memcpy(raw_vendor + 4, &hypervisor_leaf[2], 4);
        memcpy(raw_vendor + 8, &hypervisor_leaf[3], 4);
        raw_vendor[12] = '\0';
        MultiByteToWideChar(CP_ACP, 0, raw_vendor, -1, vendor, vendor_count);
    }
    return 1;
}

static int environment_is_virtualized(wchar_t *evidence, DWORD evidence_count)
{
    wchar_t manufacturer[256];
    wchar_t product_name[256];
    wchar_t hypervisor_vendor[64];
    int cpuid_detected;

    if (evidence != NULL && evidence_count != 0) {
        evidence[0] = L'\0';
    }

    cpuid_detected = cpuid_reports_hypervisor(hypervisor_vendor, ARRAYSIZE(hypervisor_vendor));
    if (cpuid_detected && evidence != NULL && evidence_count != 0) {
        _snwprintf_s(evidence, evidence_count, _TRUNCATE,
            L"CPUID hypervisor flag (%s)",
            hypervisor_vendor[0] != L'\0' ? hypervisor_vendor : L"vendor unavailable");
        return 1;
    }

    read_firmware_value(L"SystemManufacturer", manufacturer, ARRAYSIZE(manufacturer));
    read_firmware_value(L"SystemProductName", product_name, ARRAYSIZE(product_name));

    if (contains_virtualization_name(manufacturer) ||
        contains_virtualization_name(product_name)) {
        if (evidence != NULL && evidence_count != 0) {
            _snwprintf_s(evidence, evidence_count, _TRUNCATE,
                L"Firmware identity (%s / %s)", manufacturer, product_name);
        }
        return 1;
    }

    return 0;
}

static int show_trust_prompt(int virtualized, const wchar_t *evidence)
{
    wchar_t message[512];
    TASKDIALOG_BUTTON buttons[2] = {
        { 100, L"Exit" },
        { IDOK, L"OK" }
    };
    TASKDIALOGCONFIG config = {0};
    int selected_button = 100;

    if (virtualized) {
        _snwprintf_s(message, ARRAYSIZE(message), _TRUNCATE,
            L"The run environment is not trusted.\n\nEvidence: %s",
            evidence[0] != L'\0' ? evidence : L"virtualization indicator detected");
        MessageBoxW(NULL, message, L"Environment warning", MB_OK | MB_ICONWARNING);
        return 0;
    }

    config.cbSize = sizeof config;
    config.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION;
    config.pszWindowTitle = L"Environment warning";
    config.pszMainInstruction = L"The run environment is trusted, do you want to continue?";
    config.pszMainIcon = TD_WARNING_ICON;
    config.cButtons = ARRAYSIZE(buttons);
    config.pButtons = buttons;

    if (TaskDialogIndirect(&config, &selected_button, NULL, NULL) != S_OK) {
        return 0;
    }
    return selected_button == IDOK;
}

int WINAPI wWinMain(HINSTANCE instance, HINSTANCE previous, PWSTR command_line, int show_command)
{
    wchar_t evidence[256];
    int virtualized;

    (void)instance;
    (void)previous;
    (void)command_line;
    (void)show_command;

    virtualized = environment_is_virtualized(evidence, ARRAYSIZE(evidence));
    if (!show_trust_prompt(virtualized, evidence)) {
        return 0;
    }

    MessageBoxW(NULL, L"Continuing normal application execution.",
        L"Environment check", MB_OK | MB_ICONINFORMATION);
    return 0;
}
