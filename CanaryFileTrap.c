/*
  CanaryFileTrap.c - Windows canary file access monitor.

  Creates a dummy/canary file, adds a read-audit SACL, subscribes to
  Windows Security Event ID 4663, reports which process accessed the file,
  and optionally suspends and/or dumps that process.

  Build:
    cl /nologo /W4 /O2 CanaryFileTrap.c /link Advapi32.lib Wevtapi.lib Dbghelp.lib Bcrypt.lib
*/

#define WIN32_LEAN_AND_MEAN
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0601
#endif

#include <windows.h>
#include <sddl.h>
#include <aclapi.h>
#include <winevt.h>
#include <tlhelp32.h>
#include <dbghelp.h>
#include <ntsecapi.h>
#include <bcrypt.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <wchar.h>

#pragma comment(lib, "Advapi32.lib")
#pragma comment(lib, "Wevtapi.lib")
#pragma comment(lib, "Dbghelp.lib")
#pragma comment(lib, "Bcrypt.lib")

#define MAX_EXCLUDES 128
#define MAX_CANARY_FILES 256
#define MAX_PATH_CHARS 32768
#define DEFAULT_CANARY_SIZE 4096ULL
#define MAX_CANARY_SIZE (1024ULL * 1024ULL * 1024ULL)

static volatile LONG g_stop = 0;

typedef struct pid_set {
    DWORD *items;
    size_t count;
    size_t cap;
} pid_set_t;

typedef enum canary_data_mode {
    CANARY_DATA_TEXT = 0,
    CANARY_DATA_BINARY = 1,
    CANARY_DATA_FIXED = 2
} canary_data_mode_t;

typedef struct options {
    wchar_t *canary_paths[MAX_CANARY_FILES];
    int canary_path_count;

    wchar_t canary_dir[MAX_PATH_CHARS];
    wchar_t canary_prefix[128];
    wchar_t canary_extension[64];
    unsigned canary_count;
    unsigned long long canary_size;
    canary_data_mode_t data_mode;
    bool content_override;

    wchar_t dump_dir[MAX_PATH_CHARS];
    wchar_t content[1024];
    bool suspend_on_access;
    bool dump_on_access;
    bool full_dump;
    bool enable_audit_policy;
    bool check_audit_policy;
    bool verbose;
    bool quiet;
    bool no_default_excludes;
    bool repeat_actions;
    bool cleanup_on_exit;
    wchar_t *exclude_names[MAX_EXCLUDES];
    int exclude_count;
    DWORD self_pid;
    wchar_t self_name[MAX_PATH];
} options_t;

typedef struct app_context {
    options_t *opts;
    pid_set_t acted_pids;
    CRITICAL_SECTION acted_lock;
    CRITICAL_SECTION print_lock;
} app_context_t;

static BOOL WINAPI ctrl_handler(DWORD ctrl_type) {
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
        InterlockedExchange(&g_stop, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

static const wchar_t *base_name_w(const wchar_t *path) {
    const wchar_t *p1, *p2, *p;
    if (!path) return L"";
    p1 = wcsrchr(path, L'\\');
    p2 = wcsrchr(path, L'/');
    p = p1 > p2 ? p1 : p2;
    return p ? p + 1 : path;
}

static void usage(const wchar_t *argv0) {
    fwprintf(stderr,
        L"Usage:\n"
        L"  %s [options]\n\n"
        L"Audit options:\n"
        L"  --check-audit-policy      Check whether File System success auditing is enabled, then exit.\n"
        L"  --enable-audit-policy     Enable successful File System auditing if needed.\n"
        L"                            Uses AuditSetSystemPolicy first, auditpol fallback.\n\n"
        L"Canary file options:\n"
        L"  --path <file>             Canary file path. Repeatable.\n"
        L"                            Default: %%ProgramData%%\\CanaryTrap\\canary.txt\n"
        L"  --path-list <file>        Read canary paths from a text file, one path per line.\n"
        L"  --dir <directory>         Directory for generated canary files.\n"
        L"  --count <N>               Number of generated canary files. Default: 1.\n"
        L"  --prefix <name>           Generated file prefix. Default: canary\n"
        L"  --extension <ext>         Generated file extension. Default: .txt\n"
        L"  --size <N|NK|NM|NG>       Size of each canary file. Default: 4K. Max: 1G.\n"
        L"  --data-mode <mode>        File content mode: text, binary, or fixed. Default: text.\n"
        L"  --content <text>          Repeated/truncated to fill --size; implies fixed mode.\n"
        L"  --cleanup-on-exit       Delete canary files after a clean Ctrl-C shutdown.\n\n"
        L"Actions:\n"
        L"  --suspend                 Suspend the accessing process.\n"
        L"  --dump                    Write a minidump of the accessing process.\n"
        L"  --full-dump               With --dump, use MiniDumpWithFullMemory.\n"
        L"  --dump-dir <dir>          Dump directory. Default: .\\dumps\n"
        L"  --repeat-actions          Allow suspend/dump more than once per PID. Default: once per PID.\n\n"
        L"Exclusions:\n"
        L"  --exclude-name a,b        Add exact case-insensitive process basenames to exclude.\n"
        L"                            explorer.exe and this tool are excluded by default.\n"
        L"  --no-default-excludes     Do not add explorer.exe. This tool is still always excluded.\n\n"
        L"Other:\n"
        L"  -q, --quiet               Less output.\n"
        L"  -v, --verbose             More diagnostics.\n"
        L"  -h, --help                Show this help.\n\n"
        L"Examples:\n"
        L"  %s --check-audit-policy\n"
        L"  %s --enable-audit-policy\n"
        L"  %s --path C:\\Users\\Public\\Documents\\invoice_passwords.txt --suspend\n"
        L"  %s --dir C:\\Users\\Public\\Documents --count 10 --size 128K --data-mode text\n"
        L"  %s --path-list canaries.txt --dump --dump-dir C:\\Dumps\n",
        argv0, argv0, argv0, argv0, argv0, argv0);
}

static wchar_t *wcsdup_heap(const wchar_t *s) {
    size_t n;
    wchar_t *p;
    if (!s) return NULL;
    n = wcslen(s) + 1;
    p = (wchar_t *)malloc(n * sizeof(wchar_t));
    if (p) memcpy(p, s, n * sizeof(wchar_t));
    return p;
}

static wchar_t *trim_w_in_place(wchar_t *s) {
    wchar_t *e;
    while (*s == L' ' || *s == L'\t' || *s == L'\r' || *s == L'\n') s++;
    e = s + wcslen(s);
    while (e > s && (e[-1] == L' ' || e[-1] == L'\t' || e[-1] == L'\r' || e[-1] == L'\n')) *--e = L'\0';
    return s;
}

static bool add_exclude_name(options_t *opts, const wchar_t *name) {
    if (opts->exclude_count >= MAX_EXCLUDES) {
        fwprintf(stderr, L"Too many exclusions; max is %d\n", MAX_EXCLUDES);
        return false;
    }
    opts->exclude_names[opts->exclude_count] = wcsdup_heap(name);
    if (!opts->exclude_names[opts->exclude_count]) return false;
    opts->exclude_count++;
    return true;
}

static bool split_exclude_csv(options_t *opts, const wchar_t *csv) {
    wchar_t *copy = wcsdup_heap(csv);
    wchar_t *ctx = NULL, *tok;
    if (!copy) return false;
    tok = wcstok_s(copy, L",", &ctx);
    while (tok) {
        wchar_t *clean = trim_w_in_place(tok);
        if (*clean && !add_exclude_name(opts, clean)) { free(copy); return false; }
        tok = wcstok_s(NULL, L",", &ctx);
    }
    free(copy);
    return true;
}

static bool is_excluded_process(const options_t *opts, DWORD pid, const wchar_t *process_path_or_name) {
    const wchar_t *name = base_name_w(process_path_or_name);
    if (pid == opts->self_pid) return true;
    if (_wcsicmp(name, opts->self_name) == 0) return true;
    for (int i = 0; i < opts->exclude_count; i++) {
        if (_wcsicmp(name, opts->exclude_names[i]) == 0) return true;
    }
    return false;
}

static bool pid_set_contains(const pid_set_t *set, DWORD pid) {
    for (size_t i = 0; i < set->count; i++) if (set->items[i] == pid) return true;
    return false;
}

static bool pid_set_add(pid_set_t *set, DWORD pid) {
    DWORD *new_items;
    size_t new_cap;
    if (pid_set_contains(set, pid)) return true;
    if (set->count == set->cap) {
        new_cap = set->cap ? set->cap * 2 : 128;
        new_items = (DWORD *)realloc(set->items, new_cap * sizeof(DWORD));
        if (!new_items) return false;
        set->items = new_items;
        set->cap = new_cap;
    }
    set->items[set->count++] = pid;
    return true;
}

static void pid_set_free(pid_set_t *set) {
    free(set->items);
    set->items = NULL;
    set->count = 0;
    set->cap = 0;
}

static bool run_auditpol_enable(void);

static bool enable_privilege(const wchar_t *priv_name) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    BOOL ok;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    if (!LookupPrivilegeValueW(NULL, priv_name, &luid)) { CloseHandle(token); return false; }
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    ok = AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return ok && GetLastError() == ERROR_SUCCESS;
}


/*
  File System audit-policy subcategory GUID:
    {0CCE921D-69AE-11D9-BED3-505054503030}
*/
static const GUID FILE_SYSTEM_AUDIT_SUBCATEGORY_GUID =
    { 0x0CCE921D, 0x69AE, 0x11D9, { 0xBE, 0xD3, 0x50, 0x50, 0x54, 0x50, 0x30, 0x30 } };

static bool query_file_system_audit_policy(bool *success_enabled,
                                           bool *failure_enabled,
                                           DWORD *error_out) {
    GUID subcats[1];
    PAUDIT_POLICY_INFORMATION policy = NULL;

    if (success_enabled) *success_enabled = false;
    if (failure_enabled) *failure_enabled = false;
    if (error_out) *error_out = ERROR_SUCCESS;

    subcats[0] = FILE_SYSTEM_AUDIT_SUBCATEGORY_GUID;

    if (!AuditQuerySystemPolicy(subcats, 1, &policy)) {
        if (error_out) *error_out = GetLastError();
        return false;
    }

    if (policy) {
        if (success_enabled) *success_enabled = (policy[0].AuditingInformation & POLICY_AUDIT_EVENT_SUCCESS) != 0;
        if (failure_enabled) *failure_enabled = (policy[0].AuditingInformation & POLICY_AUDIT_EVENT_FAILURE) != 0;
        AuditFree(policy);
    }

    return true;
}

static bool enable_file_system_success_audit_policy(DWORD *error_out) {
    AUDIT_POLICY_INFORMATION new_policy;
    PAUDIT_POLICY_INFORMATION current_policy = NULL;
    GUID subcats[1];
    ULONG flags = POLICY_AUDIT_EVENT_SUCCESS;

    if (error_out) *error_out = ERROR_SUCCESS;

    subcats[0] = FILE_SYSTEM_AUDIT_SUBCATEGORY_GUID;

    /* Preserve existing failure auditing if present. */
    if (AuditQuerySystemPolicy(subcats, 1, &current_policy) && current_policy) {
        flags = current_policy[0].AuditingInformation;
        flags &= ~POLICY_AUDIT_EVENT_NONE;
        flags |= POLICY_AUDIT_EVENT_SUCCESS;
        AuditFree(current_policy);
    }

    ZeroMemory(&new_policy, sizeof(new_policy));
    new_policy.AuditSubCategoryGuid = FILE_SYSTEM_AUDIT_SUBCATEGORY_GUID;
    new_policy.AuditingInformation = flags;

    if (!AuditSetSystemPolicy(&new_policy, 1)) {
        if (error_out) *error_out = GetLastError();
        return false;
    }

    return true;
}

static int check_or_enable_file_system_auditing(const options_t *opts, bool *success_enabled_out) {
    bool success_enabled = false;
    bool failure_enabled = false;
    DWORD err = ERROR_SUCCESS;
    bool query_ok;

    if (success_enabled_out) *success_enabled_out = false;

    query_ok = query_file_system_audit_policy(&success_enabled, &failure_enabled, &err);
    if (query_ok) {
        if (!opts->quiet) {
            wprintf(L"File System audit policy: success=%s failure=%s\n",
                    success_enabled ? L"enabled" : L"disabled",
                    failure_enabled ? L"enabled" : L"disabled");
        }
    } else {
        fwprintf(stderr, L"Could not query File System audit policy with AuditQuerySystemPolicy: %lu\n", err);
        fwprintf(stderr, L"Run elevated. SeSecurityPrivilege is normally required for audit-policy queries.\n");
    }

    if (opts->enable_audit_policy && !success_enabled) {
        bool enabled = false;
        err = ERROR_SUCCESS;

        if (!opts->quiet) {
            wprintf(L"Attempting to enable File System success auditing...\n");
        }

        if (enable_file_system_success_audit_policy(&err)) {
            enabled = true;
        } else {
            fwprintf(stderr, L"AuditSetSystemPolicy failed: %lu; trying auditpol fallback.\n", err);
            enabled = run_auditpol_enable();
        }

        if (enabled) {
            query_ok = query_file_system_audit_policy(&success_enabled, &failure_enabled, &err);
            if (query_ok) {
                wprintf(L"File System audit policy after enable: success=%s failure=%s\n",
                        success_enabled ? L"enabled" : L"disabled",
                        failure_enabled ? L"enabled" : L"disabled");
            }
        }
    }

    if (!success_enabled) {
        fwprintf(stderr,
                 L"Warning: File System success auditing does not appear to be enabled. "
                 L"Canary read events may not appear until it is enabled.\n");
    }

    if (success_enabled_out) *success_enabled_out = success_enabled;
    return success_enabled ? 0 : 1;
}

static bool run_auditpol_enable(void) {
    wchar_t cmd[] = L"auditpol.exe /set /subcategory:\"File System\" /success:enable";
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 1;
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    wprintf(L"Enabling File System auditing with auditpol...\n");
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"CreateProcess(auditpol) failed: %lu\n", GetLastError());
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &exit_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != 0) {
        fwprintf(stderr, L"auditpol exited with code %lu\n", exit_code);
        return false;
    }
    return true;
}

static bool ensure_directory(const wchar_t *dir) {
    DWORD attrs;
    if (!dir || !*dir) return true;
    attrs = GetFileAttributesW(dir);
    if (attrs != INVALID_FILE_ATTRIBUTES && (attrs & FILE_ATTRIBUTE_DIRECTORY)) return true;
    if (CreateDirectoryW(dir, NULL)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool ensure_parent_directory(const wchar_t *path) {
    wchar_t tmp[MAX_PATH_CHARS];
    wchar_t *slash1, *slash2, *slash;
    wcsncpy_s(tmp, MAX_PATH_CHARS, path, _TRUNCATE);
    slash1 = wcsrchr(tmp, L'\\');
    slash2 = wcsrchr(tmp, L'/');
    slash = slash1 > slash2 ? slash1 : slash2;
    if (!slash) return true;
    *slash = L'\0';
    if (wcslen(tmp) <= 3 && tmp[1] == L':') return true;
    return ensure_directory(tmp);
}

static bool fill_random_bytes(uint8_t *buf, DWORD len) {
    if (len == 0) return true;
    return BCryptGenRandom(NULL, buf, len, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
}

static bool write_repeated_utf8_content(HANDLE h, const wchar_t *content, unsigned long long target_size) {
    char utf8[4096];
    int n;
    unsigned long long remaining = target_size;

    n = WideCharToMultiByte(CP_UTF8, 0, content, -1, utf8, sizeof(utf8), NULL, NULL);
    if (n <= 1) {
        strcpy_s(utf8, sizeof(utf8), "canary\r\n");
        n = (int)strlen(utf8) + 1;
    }

    while (remaining > 0) {
        DWORD written = 0;
        DWORD to_write = (DWORD)((remaining < (unsigned long long)(n - 1)) ? remaining : (unsigned long long)(n - 1));
        if (!WriteFile(h, utf8, to_write, &written, NULL)) return false;
        if (written == 0) return false;
        remaining -= written;
    }

    return true;
}

static bool write_random_text_content(HANDLE h, unsigned long long target_size) {
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        " .,:;_-+=/@#$%()[]{}<>!?\\r\\n";
    uint8_t rnd[8192];
    char out[8192];
    unsigned long long remaining = target_size;
    const size_t alpha_len = sizeof(alphabet) - 1;

    while (remaining > 0) {
        DWORD chunk = (DWORD)((remaining < sizeof(rnd)) ? remaining : sizeof(rnd));
        DWORD written = 0;
        if (!fill_random_bytes(rnd, chunk)) return false;
        for (DWORD i = 0; i < chunk; i++) out[i] = alphabet[rnd[i] % alpha_len];
        if (!WriteFile(h, out, chunk, &written, NULL)) return false;
        if (written == 0) return false;
        remaining -= written;
    }

    return true;
}

static bool write_random_binary_content(HANDLE h, unsigned long long target_size) {
    uint8_t buf[8192];
    unsigned long long remaining = target_size;

    while (remaining > 0) {
        DWORD chunk = (DWORD)((remaining < sizeof(buf)) ? remaining : sizeof(buf));
        DWORD written = 0;
        if (!fill_random_bytes(buf, chunk)) return false;
        if (!WriteFile(h, buf, chunk, &written, NULL)) return false;
        if (written == 0) return false;
        remaining -= written;
    }

    return true;
}

static bool write_canary_file(const options_t *opts, const wchar_t *path) {
    HANDLE h;
    bool ok;

    if (!ensure_parent_directory(path)) {
        fwprintf(stderr, L"Could not create parent directory for %s: %lu\n", path, GetLastError());
        return false;
    }

    h = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"CreateFile failed for %s: %lu\n", path, GetLastError());
        return false;
    }

    if (opts->data_mode == CANARY_DATA_BINARY) ok = write_random_binary_content(h, opts->canary_size);
    else if (opts->data_mode == CANARY_DATA_FIXED || opts->content_override) ok = write_repeated_utf8_content(h, opts->content, opts->canary_size);
    else ok = write_random_text_content(h, opts->canary_size);

    if (!ok) fwprintf(stderr, L"Writing canary content failed for %s: %lu\n", path, GetLastError());

    CloseHandle(h);
    return ok;
}

static bool set_canary_sacl(const wchar_t *path) {
    PSID everyone = NULL;
    PACL sacl = NULL;
    EXPLICIT_ACCESS_W ea;
    DWORD err;
    DWORD access_mask;
    if (!ConvertStringSidToSidW(L"S-1-1-0", &everyone)) {
        fwprintf(stderr, L"ConvertStringSidToSid(Everyone) failed: %lu\n", GetLastError());
        return false;
    }
    ZeroMemory(&ea, sizeof(ea));
    access_mask = FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL;
    ea.grfAccessPermissions = access_mask;
    ea.grfAccessMode = SET_AUDIT_SUCCESS;
    ea.grfInheritance = NO_INHERITANCE;
    ea.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea.Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea.Trustee.ptstrName = (LPWSTR)everyone;
    err = SetEntriesInAclW(1, &ea, NULL, &sacl);
    if (err != ERROR_SUCCESS) {
        fwprintf(stderr, L"SetEntriesInAcl failed: %lu\n", err);
        LocalFree(everyone);
        return false;
    }
    err = SetNamedSecurityInfoW((LPWSTR)path, SE_FILE_OBJECT, SACL_SECURITY_INFORMATION, NULL, NULL, NULL, sacl);
    if (err != ERROR_SUCCESS) {
        fwprintf(stderr, L"SetNamedSecurityInfo(SACL) failed: %lu\n", err);
        fwprintf(stderr, L"Run elevated and make sure SeSecurityPrivilege is available.\n");
        LocalFree(sacl);
        LocalFree(everyone);
        return false;
    }
    LocalFree(sacl);
    LocalFree(everyone);
    return true;
}

static bool get_default_canary_path(wchar_t *out, size_t out_count) {
    DWORD n;
    wchar_t program_data[MAX_PATH];
    n = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) wcsncpy_s(program_data, MAX_PATH, L"C:\\ProgramData", _TRUNCATE);
    return swprintf_s(out, out_count, L"%s\\CanaryTrap\\canary.txt", program_data) > 0;
}

static bool get_default_dump_dir(wchar_t *out, size_t out_count) {
    return GetFullPathNameW(L".\\dumps", (DWORD)out_count, out, NULL) != 0;
}

static bool get_default_canary_dir(wchar_t *out, size_t out_count) {
    DWORD n;
    wchar_t program_data[MAX_PATH];
    n = GetEnvironmentVariableW(L"ProgramData", program_data, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) wcsncpy_s(program_data, MAX_PATH, L"C:\\ProgramData", _TRUNCATE);
    return swprintf_s(out, out_count, L"%s\\CanaryTrap", program_data) > 0;
}

static bool add_canary_path(options_t *opts, const wchar_t *path) {
    wchar_t full[MAX_PATH_CHARS];
    DWORD n;

    if (opts->canary_path_count >= MAX_CANARY_FILES) {
        fwprintf(stderr, L"Too many canary files; max is %d\n", MAX_CANARY_FILES);
        return false;
    }

    n = GetFullPathNameW(path, MAX_PATH_CHARS, full, NULL);
    if (n == 0 || n >= MAX_PATH_CHARS) {
        fwprintf(stderr, L"Invalid canary path: %s\n", path);
        return false;
    }

    opts->canary_paths[opts->canary_path_count] = wcsdup_heap(full);
    if (!opts->canary_paths[opts->canary_path_count]) return false;
    opts->canary_path_count++;
    return true;
}

static bool add_canary_paths_from_list(options_t *opts, const wchar_t *list_path) {
    FILE *f = NULL;
    wchar_t line[MAX_PATH_CHARS];
    errno_t er;

    er = _wfopen_s(&f, list_path, L"rt, ccs=UTF-8");
    if (er != 0 || !f) {
        er = _wfopen_s(&f, list_path, L"rt");
    }
    if (er != 0 || !f) {
        fwprintf(stderr, L"Could not open --path-list file: %s\n", list_path);
        return false;
    }

    while (fgetws(line, MAX_PATH_CHARS, f)) {
        wchar_t *clean = trim_w_in_place(line);
        if (*clean == L'\0' || *clean == L'#') continue;
        if (!add_canary_path(opts, clean)) { fclose(f); return false; }
    }

    fclose(f);
    return true;
}

static bool parse_size_arg(const wchar_t *s, unsigned long long *out) {
    wchar_t *end = NULL;
    unsigned long long value;
    unsigned long long multiplier = 1;

    if (!s || !*s) return false;
    value = wcstoull(s, &end, 10);
    if (end == s) return false;

    if (*end == L'K' || *end == L'k') { multiplier = 1024ULL; end++; }
    else if (*end == L'M' || *end == L'm') { multiplier = 1024ULL * 1024ULL; end++; }
    else if (*end == L'G' || *end == L'g') { multiplier = 1024ULL * 1024ULL * 1024ULL; end++; }

    if (*end != L'\0') return false;
    if (value == 0 || value > MAX_CANARY_SIZE / multiplier) return false;
    value *= multiplier;
    if (value > MAX_CANARY_SIZE) return false;
    *out = value;
    return true;
}

static bool parse_data_mode(const wchar_t *s, canary_data_mode_t *mode) {
    if (_wcsicmp(s, L"text") == 0) { *mode = CANARY_DATA_TEXT; return true; }
    if (_wcsicmp(s, L"binary") == 0 || _wcsicmp(s, L"bin") == 0) { *mode = CANARY_DATA_BINARY; return true; }
    if (_wcsicmp(s, L"fixed") == 0 || _wcsicmp(s, L"content") == 0) { *mode = CANARY_DATA_FIXED; return true; }
    return false;
}

static bool build_generated_canary_paths(options_t *opts) {
    unsigned count = opts->canary_count ? opts->canary_count : 1;
    wchar_t path[MAX_PATH_CHARS];

    if (count > MAX_CANARY_FILES) {
        fwprintf(stderr, L"--count must be <= %d\n", MAX_CANARY_FILES);
        return false;
    }

    if (!ensure_directory(opts->canary_dir)) {
        fwprintf(stderr, L"Could not create canary directory %s: %lu\n", opts->canary_dir, GetLastError());
        return false;
    }

    for (unsigned i = 1; i <= count; i++) {
        if (count == 1) {
            if (swprintf_s(path, MAX_PATH_CHARS, L"%s\\%s%s", opts->canary_dir, opts->canary_prefix, opts->canary_extension) <= 0) return false;
        } else {
            if (swprintf_s(path, MAX_PATH_CHARS, L"%s\\%s_%04u%s", opts->canary_dir, opts->canary_prefix, i, opts->canary_extension) <= 0) return false;
        }
        if (!add_canary_path(opts, path)) return false;
    }

    return true;
}

static bool is_canary_object_path(const options_t *opts, const wchar_t *object_name) {
    for (int i = 0; i < opts->canary_path_count; i++) {
        if (_wcsicmp(object_name, opts->canary_paths[i]) == 0) return true;
    }
    return false;
}


static bool parse_args(int argc, wchar_t **argv, options_t *opts) {
    wchar_t self_path[MAX_PATH_CHARS];
    ZeroMemory(opts, sizeof(*opts));

    opts->self_pid = GetCurrentProcessId();
    GetModuleFileNameW(NULL, self_path, MAX_PATH_CHARS);
    wcsncpy_s(opts->self_name, MAX_PATH, base_name_w(self_path), _TRUNCATE);

    get_default_canary_dir(opts->canary_dir, MAX_PATH_CHARS);
    get_default_dump_dir(opts->dump_dir, MAX_PATH_CHARS);
    wcsncpy_s(opts->canary_prefix, 128, L"canary", _TRUNCATE);
    wcsncpy_s(opts->canary_extension, 64, L".txt", _TRUNCATE);
    opts->canary_count = 1;
    opts->canary_size = DEFAULT_CANARY_SIZE;
    opts->data_mode = CANARY_DATA_TEXT;
    wcsncpy_s(opts->content, 1024, L"Internal financial backup credentials - canary file.\r\n", _TRUNCATE);

    for (int i = 1; i < argc; i++) {
        if ((_wcsicmp(argv[i], L"--path") == 0) && i + 1 < argc) {
            if (!add_canary_path(opts, argv[++i])) return false;
        } else if ((_wcsicmp(argv[i], L"--path-list") == 0) && i + 1 < argc) {
            if (!add_canary_paths_from_list(opts, argv[++i])) return false;
        } else if ((_wcsicmp(argv[i], L"--dir") == 0) && i + 1 < argc) {
            if (!GetFullPathNameW(argv[++i], MAX_PATH_CHARS, opts->canary_dir, NULL)) { fwprintf(stderr, L"Invalid --dir\n"); return false; }
        } else if ((_wcsicmp(argv[i], L"--count") == 0) && i + 1 < argc) {
            opts->canary_count = (unsigned)wcstoul(argv[++i], NULL, 10);
            if (opts->canary_count == 0 || opts->canary_count > MAX_CANARY_FILES) { fwprintf(stderr, L"--count must be from 1 to %d\n", MAX_CANARY_FILES); return false; }
        } else if ((_wcsicmp(argv[i], L"--prefix") == 0) && i + 1 < argc) {
            wcsncpy_s(opts->canary_prefix, 128, argv[++i], _TRUNCATE);
        } else if ((_wcsicmp(argv[i], L"--extension") == 0) && i + 1 < argc) {
            const wchar_t *ext = argv[++i];
            if (ext[0] == L'.') wcsncpy_s(opts->canary_extension, 64, ext, _TRUNCATE);
            else swprintf_s(opts->canary_extension, 64, L".%s", ext);
        } else if ((_wcsicmp(argv[i], L"--size") == 0) && i + 1 < argc) {
            if (!parse_size_arg(argv[++i], &opts->canary_size)) { fwprintf(stderr, L"Invalid --size. Use bytes, K, M or G, max 1G.\n"); return false; }
        } else if ((_wcsicmp(argv[i], L"--data-mode") == 0) && i + 1 < argc) {
            if (!parse_data_mode(argv[++i], &opts->data_mode)) { fwprintf(stderr, L"Invalid --data-mode. Use text, binary, or fixed.\n"); return false; }
        } else if ((_wcsicmp(argv[i], L"--content") == 0) && i + 1 < argc) {
            wcsncpy_s(opts->content, 1024, argv[++i], _TRUNCATE);
            opts->content_override = true;
            opts->data_mode = CANARY_DATA_FIXED;
        } else if (_wcsicmp(argv[i], L"--suspend") == 0 || _wcsicmp(argv[i], L"--freeze") == 0) {
            opts->suspend_on_access = true;
        } else if (_wcsicmp(argv[i], L"--dump") == 0) {
            opts->dump_on_access = true;
        } else if (_wcsicmp(argv[i], L"--full-dump") == 0) {
            opts->full_dump = true; opts->dump_on_access = true;
        } else if ((_wcsicmp(argv[i], L"--dump-dir") == 0) && i + 1 < argc) {
            if (!GetFullPathNameW(argv[++i], MAX_PATH_CHARS, opts->dump_dir, NULL)) { fwprintf(stderr, L"Invalid --dump-dir\n"); return false; }
        } else if (_wcsicmp(argv[i], L"--check-audit-policy") == 0) {
            opts->check_audit_policy = true;
        } else if (_wcsicmp(argv[i], L"--enable-audit-policy") == 0) {
            opts->enable_audit_policy = true;
        } else if ((_wcsicmp(argv[i], L"--exclude-name") == 0) && i + 1 < argc) {
            if (!split_exclude_csv(opts, argv[++i])) return false;
        } else if (_wcsicmp(argv[i], L"--no-default-excludes") == 0) {
            opts->no_default_excludes = true;
        } else if (_wcsicmp(argv[i], L"--repeat-actions") == 0) {
            opts->repeat_actions = true;
        } else if (_wcsicmp(argv[i], L"--cleanup-on-exit") == 0 || _wcsicmp(argv[i], L"--cleanup") == 0) {
            opts->cleanup_on_exit = true;
        } else if (_wcsicmp(argv[i], L"-q") == 0 || _wcsicmp(argv[i], L"--quiet") == 0) {
            opts->quiet = true;
        } else if (_wcsicmp(argv[i], L"-v") == 0 || _wcsicmp(argv[i], L"--verbose") == 0) {
            opts->verbose = true;
        } else if (_wcsicmp(argv[i], L"-h") == 0 || _wcsicmp(argv[i], L"--help") == 0) {
            usage(argv[0]); return false;
        } else {
            fwprintf(stderr, L"Unknown or incomplete option: %s\n", argv[i]); usage(argv[0]); return false;
        }
    }

    if (opts->canary_path_count == 0) {
        if (!build_generated_canary_paths(opts)) return false;
    }

    if (!opts->no_default_excludes) add_exclude_name(opts, L"explorer.exe");
    add_exclude_name(opts, opts->self_name);
    return true;
}

static void free_options(options_t *opts) {
    for (int i = 0; i < opts->exclude_count; i++) free(opts->exclude_names[i]);
    for (int i = 0; i < opts->canary_path_count; i++) free(opts->canary_paths[i]);
}

static bool xml_get_data_value(const wchar_t *xml, const wchar_t *name, wchar_t *out, size_t out_count) {
    wchar_t pattern1[256], pattern2[256];
    const wchar_t *p, *start, *end;
    size_t len;
    swprintf_s(pattern1, 256, L"<Data Name='%s'>", name);
    swprintf_s(pattern2, 256, L"<Data Name=\"%s\">", name);
    p = wcsstr(xml, pattern1);
    if (!p) p = wcsstr(xml, pattern2);
    if (!p) return false;
    start = wcschr(p, L'>');
    if (!start) return false;
    start++;
    end = wcsstr(start, L"</Data>");
    if (!end) return false;
    len = (size_t)(end - start);
    if (len >= out_count) len = out_count - 1;
    wmemcpy(out, start, len);
    out[len] = L'\0';
    return true;
}

static DWORD parse_event_pid(const wchar_t *s) {
    if (!s || !*s) return 0;
    if (s[0] == L'0' && (s[1] == L'x' || s[1] == L'X')) return (DWORD)wcstoul(s + 2, NULL, 16);
    return (DWORD)wcstoul(s, NULL, 10);
}

static bool event_access_mask_has_read(const wchar_t *mask_text) {
    DWORD mask;
    if (!mask_text || !*mask_text) return true;
    if (mask_text[0] == L'0' && (mask_text[1] == L'x' || mask_text[1] == L'X')) mask = (DWORD)wcstoul(mask_text + 2, NULL, 16);
    else mask = (DWORD)wcstoul(mask_text, NULL, 10);
    return (mask & (FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL)) != 0;
}

static bool render_event_xml(EVT_HANDLE event, wchar_t **xml_out) {
    DWORD used = 0, props = 0;
    wchar_t *xml;
    *xml_out = NULL;
    if (!EvtRender(NULL, event, EvtRenderEventXml, 0, NULL, &used, &props)) {
        DWORD err = GetLastError();
        if (err != ERROR_INSUFFICIENT_BUFFER) { fwprintf(stderr, L"EvtRender sizing failed: %lu\n", err); return false; }
    }
    xml = (wchar_t *)malloc(used);
    if (!xml) return false;
    if (!EvtRender(NULL, event, EvtRenderEventXml, used, xml, &used, &props)) {
        fwprintf(stderr, L"EvtRender failed: %lu\n", GetLastError());
        free(xml); return false;
    }
    *xml_out = xml;
    return true;
}

static unsigned long long suspend_process_threads(DWORD pid, const wchar_t *process_name, CRITICAL_SECTION *print_lock) {
    HANDLE snap;
    THREADENTRY32 te;
    unsigned long long suspended = 0, seen = 0, failed = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"[suspend-fail] pid=%lu process=%s snapshot failed: %lu\n", (unsigned long)pid, process_name, GetLastError());
        return 0;
    }
    ZeroMemory(&te, sizeof(te));
    te.dwSize = sizeof(te);
    if (!Thread32First(snap, &te)) {
        fwprintf(stderr, L"[suspend-fail] pid=%lu process=%s Thread32First failed: %lu\n", (unsigned long)pid, process_name, GetLastError());
        CloseHandle(snap); return 0;
    }
    do {
        if (te.th32OwnerProcessID == pid) {
            HANDLE hThread;
            seen++;
            hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, te.th32ThreadID);
            if (!hThread) { failed++; continue; }
            if (SuspendThread(hThread) == (DWORD)-1) failed++;
            else suspended++;
            CloseHandle(hThread);
        }
    } while (Thread32Next(snap, &te));
    CloseHandle(snap);
    EnterCriticalSection(print_lock);
    fwprintf(stderr, L"[suspend] pid=%lu process=%s suspended_threads=%llu seen=%llu failed=%llu\n", (unsigned long)pid, process_name, suspended, seen, failed);
    LeaveCriticalSection(print_lock);
    return suspended;
}

static void sanitise_filename(wchar_t *s) {
    for (; *s; s++) if (*s == L'\\' || *s == L'/' || *s == L':' || *s == L'*' || *s == L'?' || *s == L'"' || *s == L'<' || *s == L'>' || *s == L'|') *s = L'_';
}

static bool dump_process_memory(DWORD pid, const wchar_t *process_name_or_path, const wchar_t *dump_dir, bool full_dump, CRITICAL_SECTION *print_lock) {
    HANDLE hProcess, hFile;
    wchar_t proc_name[MAX_PATH], dump_path[MAX_PATH_CHARS];
    SYSTEMTIME st;
    MINIDUMP_TYPE dump_type;
    BOOL ok;
    if (!ensure_directory(dump_dir)) { fwprintf(stderr, L"[dump-fail] could not create dump dir %s: %lu\n", dump_dir, GetLastError()); return false; }
    wcsncpy_s(proc_name, MAX_PATH, base_name_w(process_name_or_path), _TRUNCATE);
    sanitise_filename(proc_name);
    GetLocalTime(&st);
    swprintf_s(dump_path, MAX_PATH_CHARS, L"%s\\canary_%04u%02u%02u_%02u%02u%02u_pid%lu_%s.dmp", dump_dir, st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, (unsigned long)pid, proc_name[0] ? proc_name : L"process");
    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hProcess) hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) { fwprintf(stderr, L"[dump-fail] pid=%lu process=%s OpenProcess failed: %lu\n", (unsigned long)pid, process_name_or_path, GetLastError()); return false; }
    hFile = CreateFileW(dump_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) { fwprintf(stderr, L"[dump-fail] CreateFile failed for %s: %lu\n", dump_path, GetLastError()); CloseHandle(hProcess); return false; }
    dump_type = MiniDumpWithDataSegs | MiniDumpWithThreadInfo | MiniDumpWithProcessThreadData;
    if (full_dump) dump_type = (MINIDUMP_TYPE)(dump_type | MiniDumpWithFullMemory | MiniDumpWithHandleData);
    ok = MiniDumpWriteDump(hProcess, pid, hFile, dump_type, NULL, NULL, NULL);
    CloseHandle(hFile);
    CloseHandle(hProcess);
    EnterCriticalSection(print_lock);
    if (ok) fwprintf(stderr, L"[dump] pid=%lu process=%s file=%s\n", (unsigned long)pid, process_name_or_path, dump_path);
    else fwprintf(stderr, L"[dump-fail] pid=%lu process=%s MiniDumpWriteDump failed: %lu\n", (unsigned long)pid, process_name_or_path, GetLastError());
    LeaveCriticalSection(print_lock);
    return ok ? true : false;
}


static void cleanup_canary_files(const options_t *opts, CRITICAL_SECTION *print_lock) {
    int deleted = 0;
    int failed = 0;

    if (!opts || !opts->cleanup_on_exit) return;

    for (int i = 0; i < opts->canary_path_count; i++) {
        const wchar_t *path = opts->canary_paths[i];

        if (!path || !*path) continue;

        if (DeleteFileW(path)) {
            deleted++;
            if (opts->verbose) {
                EnterCriticalSection(print_lock);
                fwprintf(stderr, L"[cleanup] deleted %s\n", path);
                LeaveCriticalSection(print_lock);
            }
        } else {
            DWORD err = GetLastError();

            /*
              The file may already have been removed by a test, cleanup script,
              or malware. Treat that as a non-fatal successful cleanup.
            */
            if (err == ERROR_FILE_NOT_FOUND || err == ERROR_PATH_NOT_FOUND) {
                deleted++;
                if (opts->verbose) {
                    EnterCriticalSection(print_lock);
                    fwprintf(stderr, L"[cleanup] already gone %s\n", path);
                    LeaveCriticalSection(print_lock);
                }
            } else {
                failed++;
                EnterCriticalSection(print_lock);
                fwprintf(stderr, L"[cleanup-fail] could not delete %s: %lu\n", path, err);
                LeaveCriticalSection(print_lock);
            }
        }
    }

    if (!opts->quiet) {
        EnterCriticalSection(print_lock);
        fwprintf(stderr, L"[cleanup] deleted=%d failed=%d\n", deleted, failed);
        LeaveCriticalSection(print_lock);
    }
}

static void process_canary_event(app_context_t *ctx, EVT_HANDLE event) {
    wchar_t *xml = NULL;
    wchar_t object_name[MAX_PATH_CHARS], process_id_text[64], process_name[MAX_PATH_CHARS], access_mask_text[64];
    DWORD pid;
    bool already_acted = false;
    if (!render_event_xml(event, &xml)) return;
    object_name[0] = process_id_text[0] = process_name[0] = access_mask_text[0] = L'\0';
    if (!xml_get_data_value(xml, L"ObjectName", object_name, MAX_PATH_CHARS)) { free(xml); return; }
    if (!is_canary_object_path(ctx->opts, object_name)) { free(xml); return; }
    xml_get_data_value(xml, L"ProcessId", process_id_text, 64);
    xml_get_data_value(xml, L"ProcessName", process_name, MAX_PATH_CHARS);
    xml_get_data_value(xml, L"AccessMask", access_mask_text, 64);
    pid = parse_event_pid(process_id_text);
    if (pid == 0) { free(xml); return; }
    if (!event_access_mask_has_read(access_mask_text)) { free(xml); return; }
    if (is_excluded_process(ctx->opts, pid, process_name)) {
        if (ctx->opts->verbose) {
            EnterCriticalSection(&ctx->print_lock);
            fwprintf(stderr, L"[ignored] pid=%lu process=%s object=%s\n", (unsigned long)pid, process_name[0] ? process_name : L"<unknown>", object_name);
            LeaveCriticalSection(&ctx->print_lock);
        }
        free(xml); return;
    }
    EnterCriticalSection(&ctx->print_lock);
    wprintf(L"[CANARY] pid=%lu process=%s object=%s accessMask=%s\n", (unsigned long)pid, process_name[0] ? process_name : L"<unknown>", object_name, access_mask_text[0] ? access_mask_text : L"<unknown>");
    fflush(stdout);
    LeaveCriticalSection(&ctx->print_lock);
    if ((ctx->opts->suspend_on_access || ctx->opts->dump_on_access) && !ctx->opts->repeat_actions) {
        EnterCriticalSection(&ctx->acted_lock);
        already_acted = pid_set_contains(&ctx->acted_pids, pid);
        if (!already_acted) pid_set_add(&ctx->acted_pids, pid);
        LeaveCriticalSection(&ctx->acted_lock);
        if (already_acted) { free(xml); return; }
    }
    if (ctx->opts->dump_on_access) dump_process_memory(pid, process_name[0] ? process_name : L"process", ctx->opts->dump_dir, ctx->opts->full_dump, &ctx->print_lock);
    if (ctx->opts->suspend_on_access) suspend_process_threads(pid, process_name[0] ? process_name : L"process", &ctx->print_lock);
    free(xml);
}

static DWORD WINAPI event_callback(EVT_SUBSCRIBE_NOTIFY_ACTION action, PVOID user_context, EVT_HANDLE event) {
    app_context_t *ctx = (app_context_t *)user_context;
    if (action == EvtSubscribeActionError) {
        DWORD err = (DWORD)(ULONG_PTR)event;
        EnterCriticalSection(&ctx->print_lock);
        fwprintf(stderr, L"[eventlog-error] subscription error: %lu\n", err);
        LeaveCriticalSection(&ctx->print_lock);
        return ERROR_SUCCESS;
    }
    if (action == EvtSubscribeActionDeliver) process_canary_event(ctx, event);
    return ERROR_SUCCESS;
}

int wmain(int argc, wchar_t **argv) {
    options_t opts;
    app_context_t ctx;
    EVT_HANDLE sub;
    const wchar_t *query = L"*[System[(EventID=4663)]]";
    if (!parse_args(argc, argv, &opts)) { free_options(&opts); return 2; }
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
    ZeroMemory(&ctx, sizeof(ctx));
    ctx.opts = &opts;
    InitializeCriticalSection(&ctx.acted_lock);
    InitializeCriticalSection(&ctx.print_lock);
    if (!enable_privilege(SE_SECURITY_NAME)) fwprintf(stderr, L"Warning: could not enable SeSecurityPrivilege. Setting the SACL may fail. Run elevated.\n");
    if (opts.suspend_on_access || opts.dump_on_access) {
        if (!enable_privilege(SE_DEBUG_NAME) && opts.verbose) fwprintf(stderr, L"Warning: could not enable SeDebugPrivilege. Suspend/dump may fail for some processes.\n");
    }
    {
        bool fs_audit_success_enabled = false;
        int audit_status = check_or_enable_file_system_auditing(&opts, &fs_audit_success_enabled);
        if (opts.check_audit_policy) {
            pid_set_free(&ctx.acted_pids);
            DeleteCriticalSection(&ctx.acted_lock);
            DeleteCriticalSection(&ctx.print_lock);
            free_options(&opts);
            return audit_status == 0 ? 0 : 1;
        }
    }
    for (int i = 0; i < opts.canary_path_count; i++) {
        if (!write_canary_file(&opts, opts.canary_paths[i])) {
            pid_set_free(&ctx.acted_pids); DeleteCriticalSection(&ctx.acted_lock); DeleteCriticalSection(&ctx.print_lock); free_options(&opts); return 1;
        }
        if (!set_canary_sacl(opts.canary_paths[i])) {
            pid_set_free(&ctx.acted_pids); DeleteCriticalSection(&ctx.acted_lock); DeleteCriticalSection(&ctx.print_lock); free_options(&opts); return 1;
        }
    }
    if (!opts.quiet) {
        const wchar_t *mode_name = opts.data_mode == CANARY_DATA_BINARY ? L"binary" : (opts.data_mode == CANARY_DATA_FIXED ? L"fixed" : L"text");
        wprintf(L"Canary files: %d, size=%llu bytes, data-mode=%s\n", opts.canary_path_count, opts.canary_size, mode_name);
        for (int i = 0; i < opts.canary_path_count; i++) wprintf(L"  %s\n", opts.canary_paths[i]);
        wprintf(L"Excluded by default: %s%s\n", opts.no_default_excludes ? L"" : L"explorer.exe, ", opts.self_name);
        if (opts.cleanup_on_exit) wprintf(L"Cleanup on exit: enabled\n");
        wprintf(L"Listening for Security event 4663. Press Ctrl-C to stop.\n");
        wprintf(L"If no events appear, run as admin and enable: auditpol /set /subcategory:\"File System\" /success:enable\n");
    }
    sub = EvtSubscribe(NULL, NULL, L"Security", query, NULL, &ctx, event_callback, EvtSubscribeToFutureEvents);
    if (!sub) {
        fwprintf(stderr, L"EvtSubscribe(Security) failed: %lu\n", GetLastError());
        fwprintf(stderr, L"Run elevated. Security log subscriptions usually require admin rights.\n");
        pid_set_free(&ctx.acted_pids); DeleteCriticalSection(&ctx.acted_lock); DeleteCriticalSection(&ctx.print_lock); free_options(&opts); return 1;
    }
    while (InterlockedCompareExchange(&g_stop, 0, 0) == 0) Sleep(1000);
    EvtClose(sub);
    cleanup_canary_files(&opts, &ctx.print_lock);
    if (!opts.quiet) wprintf(L"Stopped.\n");
    pid_set_free(&ctx.acted_pids);
    DeleteCriticalSection(&ctx.acted_lock);
    DeleteCriticalSection(&ctx.print_lock);
    free_options(&opts);
    return 0;
}
