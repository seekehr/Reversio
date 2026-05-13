/*
 * Reversio Sample Target
 *
 * A comprehensive PE binary designed to exercise every feature that
 * Reversio extracts: imports, exports, sections, TLS callbacks,
 * resources (via .rc), strings, and common RE-interesting patterns.
 *
 * Compile (MSVC x64):
 *   cl /EHsc /Fe:sample.exe main.cpp /link /SUBSYSTEM:CONSOLE
 *
 * Compile (MSVC x64 with resources):
 *   rc /fo resources.res resources.rc
 *   cl /EHsc /Fe:sample.exe main.cpp resources.res /link /SUBSYSTEM:CONSOLE
 *
 * Compile (MinGW-w64):
 *   x86_64-w64-mingw32-g++ -o sample.exe main.cpp -lws2_32 -ladvapi32 -lcrypt32
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")


// ─────────────────────────────────────────────────────────────────────
// Exported functions — populates the PE export table
// ─────────────────────────────────────────────────────────────────────

extern "C" __declspec(dllexport) int    PluginInit(int version);
extern "C" __declspec(dllexport) void   PluginShutdown();
extern "C" __declspec(dllexport) const char* PluginName();

int PluginInit(int version) {
    std::cout << "[plugin] init v" << version << std::endl;
    return version >= 1 ? 0 : -1;
}

void PluginShutdown() {
    std::cout << "[plugin] shutdown" << std::endl;
}

const char* PluginName() {
    return "ReversioSample";
}

// ─────────────────────────────────────────────────────────────────────
// TLS callbacks — Reversio parses the TLS directory (data dir index 9)
// ─────────────────────────────────────────────────────────────────────

static void NTAPI TlsCallback_AntiDebug(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            OutputDebugStringA("TLS: debugger detected");
        }
    }
}

static void NTAPI TlsCallback_Init(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        OutputDebugStringA("TLS: process attached");
    }
}

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:tls_callback_table")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback_table[] = {
    TlsCallback_AntiDebug,
    TlsCallback_Init,
    nullptr
};
#pragma const_seg()
#else
extern "C" {
    __attribute__((section(".CRT$XLB")))
    PIMAGE_TLS_CALLBACK tls_callbacks[] = {
        TlsCallback_AntiDebug,
        TlsCallback_Init,
        nullptr
    };
}
#endif

// ─────────────────────────────────────────────────────────────────────
// Interesting strings — searchable in the binary
// ─────────────────────────────────────────────────────────────────────

static const char* g_c2_domain   = "updates.evil-corp.example.com";
static const char* g_mutex_name  = "Global\\ReversioSampleMutex_v2";
static const char* g_pipe_name   = "\\\\.\\pipe\\reversio_ipc";
static const char* g_reg_key     = "SOFTWARE\\ReversioSample\\Config";
static const char* g_user_agent  = "Mozilla/5.0 (ReversioBot/1.0)";
static const wchar_t* g_service  = L"ReversioSvc";

// ─────────────────────────────────────────────────────────────────────
// Anti-debug / anti-analysis — common RE patterns
// ─────────────────────────────────────────────────────────────────────

namespace AntiDebug {

bool CheckIsDebuggerPresent() {
    return IsDebuggerPresent() != 0;
}

bool CheckRemoteDebugger() {
    BOOL present = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &present);
    return present != 0;
}

bool CheckNtGlobalFlag() {
#ifdef _M_X64
    auto peb = reinterpret_cast<PBYTE>(__readgsqword(0x60));
    DWORD flags = *reinterpret_cast<PDWORD>(peb + 0xBC);
#else
    auto peb = reinterpret_cast<PBYTE>(__readfsdword(0x30));
    DWORD flags = *reinterpret_cast<PDWORD>(peb + 0x68);
#endif
    constexpr DWORD FLG_HEAP_FLAGS = 0x70;
    return (flags & FLG_HEAP_FLAGS) != 0;
}

bool TimingCheck() {
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1);
    QueryPerformanceCounter(&end);
    double elapsed = static_cast<double>(end.QuadPart - start.QuadPart) / freq.QuadPart;
    return elapsed > 0.1;
}

void RunAll() {
    std::cout << "[anti-debug] IsDebuggerPresent:      " << CheckIsDebuggerPresent() << std::endl;
    std::cout << "[anti-debug] RemoteDebugger:          " << CheckRemoteDebugger() << std::endl;
    std::cout << "[anti-debug] NtGlobalFlag heap bits:  " << CheckNtGlobalFlag() << std::endl;
    std::cout << "[anti-debug] Timing anomaly:          " << TimingCheck() << std::endl;
}

} // namespace AntiDebug

// ─────────────────────────────────────────────────────────────────────
// Process enumeration — imports from kernel32 / TlHelp32
// ─────────────────────────────────────────────────────────────────────

namespace ProcessEnum {

struct ProcessInfo {
    DWORD pid;
    std::string name;
};

std::vector<ProcessInfo> Snapshot() {
    std::vector<ProcessInfo> procs;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return procs;

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    if (Process32First(snap, &entry)) {
        do {
            procs.push_back({entry.th32ProcessID, entry.szExeFile});
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return procs;
}

void List(int maxCount = 10) {
    auto procs = Snapshot();
    int count = 0;
    for (auto& p : procs) {
        if (count++ >= maxCount) break;
        std::cout << "  [" << p.pid << "] " << p.name << std::endl;
    }
    std::cout << "  ... (" << procs.size() << " total)" << std::endl;
}

} // namespace ProcessEnum

// ─────────────────────────────────────────────────────────────────────
// Dynamic API resolution — LoadLibrary / GetProcAddress pattern
// ─────────────────────────────────────────────────────────────────────

namespace DynAPI {

using FnNtQueryInformationProcess = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

bool ResolveNtdll() {
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (!hNtdll) return false;

    auto pNtQIP = reinterpret_cast<FnNtQueryInformationProcess>(
        GetProcAddress(hNtdll, "NtQueryInformationProcess"));

    std::cout << "[dynapi] ntdll.dll base:              0x"
              << std::hex << reinterpret_cast<uintptr_t>(hNtdll) << std::dec << std::endl;
    std::cout << "[dynapi] NtQueryInformationProcess:   "
              << (pNtQIP ? "resolved" : "not found") << std::endl;
    return pNtQIP != nullptr;
}

void ResolveKernel32Extras() {
    HMODULE hK32 = GetModuleHandleA("kernel32.dll");
    if (!hK32) return;

    auto pIsWow64 = GetProcAddress(hK32, "IsWow64Process");
    auto pVirtualAllocEx = GetProcAddress(hK32, "VirtualAllocEx");
    auto pWriteProcessMemory = GetProcAddress(hK32, "WriteProcessMemory");

    std::cout << "[dynapi] IsWow64Process:              "
              << (pIsWow64 ? "found" : "missing") << std::endl;
    std::cout << "[dynapi] VirtualAllocEx:              "
              << (pVirtualAllocEx ? "found" : "missing") << std::endl;
    std::cout << "[dynapi] WriteProcessMemory:          "
              << (pWriteProcessMemory ? "found" : "missing") << std::endl;
}

} // namespace DynAPI

// ─────────────────────────────────────────────────────────────────────
// Registry operations — imports from advapi32
// ─────────────────────────────────────────────────────────────────────

namespace Registry {

bool WriteConfig(const std::string& valueName, const std::string& data) {
    HKEY hKey;
    LONG status = RegCreateKeyExA(
        HKEY_CURRENT_USER, g_reg_key, 0, nullptr,
        REG_OPTION_NON_VOLATILE, KEY_WRITE, nullptr, &hKey, nullptr);
    if (status != ERROR_SUCCESS) return false;

    status = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ,
        reinterpret_cast<const BYTE*>(data.c_str()),
        static_cast<DWORD>(data.size() + 1));
    RegCloseKey(hKey);
    return status == ERROR_SUCCESS;
}

std::string ReadConfig(const std::string& valueName) {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, g_reg_key, 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return "";

    char buf[256]{};
    DWORD size = sizeof(buf);
    DWORD type = 0;
    RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type,
        reinterpret_cast<LPBYTE>(buf), &size);
    RegCloseKey(hKey);
    return std::string(buf);
}

void Cleanup() {
    RegDeleteKeyA(HKEY_CURRENT_USER, g_reg_key);
}

} // namespace Registry

// ─────────────────────────────────────────────────────────────────────
// Crypto — imports from advapi32 / crypt32
// ─────────────────────────────────────────────────────────────────────

namespace Crypto {

std::vector<BYTE> XorEncrypt(const std::vector<BYTE>& data, BYTE key) {
    std::vector<BYTE> out(data.size());
    for (size_t i = 0; i < data.size(); ++i)
        out[i] = data[i] ^ key;
    return out;
}

bool HashData(const BYTE* data, DWORD len) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    bool ok = false;

    if (!CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, CRYPT_VERIFYCONTEXT))
        return false;

    if (CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        if (CryptHashData(hHash, data, len, 0)) {
            DWORD hashLen = 32;
            BYTE hash[32]{};
            if (CryptGetHashParam(hHash, HP_HASHVAL, hash, &hashLen, 0)) {
                std::cout << "[crypto] SHA-256: ";
                for (DWORD i = 0; i < hashLen; ++i)
                    printf("%02x", hash[i]);
                std::cout << std::endl;
                ok = true;
            }
        }
        CryptDestroyHash(hHash);
    }
    CryptReleaseContext(hProv, 0);
    return ok;
}

void Demo() {
    const char* msg = "Reversio sample payload";
    std::vector<BYTE> plain(msg, msg + strlen(msg));

    auto enc = XorEncrypt(plain, 0xAA);
    auto dec = XorEncrypt(enc, 0xAA);

    std::cout << "[crypto] XOR roundtrip: "
              << (dec == plain ? "pass" : "FAIL") << std::endl;

    HashData(reinterpret_cast<const BYTE*>(msg), static_cast<DWORD>(strlen(msg)));
}

} // namespace Crypto

// ─────────────────────────────────────────────────────────────────────
// Networking — imports from ws2_32
// ─────────────────────────────────────────────────────────────────────

namespace Network {

bool Init() {
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
}

void Cleanup() {
    WSACleanup();
}

bool ResolveDomain(const char* domain) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int status = getaddrinfo(domain, "443", &hints, &result);
    if (status != 0) {
        std::cout << "[net] DNS failed for " << domain << ": "
                  << gai_strerrorA(status) << std::endl;
        return false;
    }

    auto addr = reinterpret_cast<sockaddr_in*>(result->ai_addr);
    char ip[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));
    std::cout << "[net] " << domain << " -> " << ip << std::endl;

    freeaddrinfo(result);
    return true;
}

bool ConnectTCP(const char* host, const char* port) {
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(host, port, &hints, &result) != 0)
        return false;

    SOCKET sock = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        return false;
    }

    u_long nonBlock = 1;
    ioctlsocket(sock, FIONBIO, &nonBlock);

    connect(sock, result->ai_addr, static_cast<int>(result->ai_addrlen));

    fd_set writeSet;
    FD_ZERO(&writeSet);
    FD_SET(sock, &writeSet);
    timeval tv{2, 0};
    int sel = select(0, nullptr, &writeSet, nullptr, &tv);

    bool connected = sel > 0;
    std::cout << "[net] TCP " << host << ":" << port << " -> "
              << (connected ? "reachable" : "timeout/refused") << std::endl;

    closesocket(sock);
    freeaddrinfo(result);
    return connected;
}

} // namespace Network

// ─────────────────────────────────────────────────────────────────────
// Mutex / named pipe — common IPC patterns
// ─────────────────────────────────────────────────────────────────────

namespace IPC {

HANDLE CreateSingleInstanceMutex() {
    HANDLE hMutex = CreateMutexA(nullptr, FALSE, g_mutex_name);
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        std::cout << "[ipc] Another instance already running" << std::endl;
        CloseHandle(hMutex);
        return nullptr;
    }
    std::cout << "[ipc] Mutex acquired: " << g_mutex_name << std::endl;
    return hMutex;
}

HANDLE CreateIPCPipe() {
    HANDLE hPipe = CreateNamedPipeA(
        g_pipe_name,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
        1, 512, 512, 0, nullptr);

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cout << "[ipc] Pipe creation failed: " << GetLastError() << std::endl;
        return nullptr;
    }
    std::cout << "[ipc] Pipe created: " << g_pipe_name << std::endl;
    return hPipe;
}

} // namespace IPC

// ─────────────────────────────────────────────────────────────────────
// Memory operations — patterns seen in process injection
// ─────────────────────────────────────────────────────────────────────

namespace Memory {

void SelfInspect() {
    MEMORY_BASIC_INFORMATION mbi{};
    auto baseAddr = reinterpret_cast<LPCVOID>(GetModuleHandleA(nullptr));

    if (VirtualQuery(baseAddr, &mbi, sizeof(mbi))) {
        std::cout << "[mem] Image base:    0x"
                  << std::hex << reinterpret_cast<uintptr_t>(mbi.BaseAddress) << std::dec << std::endl;
        std::cout << "[mem] Region size:   " << mbi.RegionSize << " bytes" << std::endl;
        std::cout << "[mem] Protect:       0x" << std::hex << mbi.Protect << std::dec << std::endl;
    }

    struct {
        DWORD  cb;
        DWORD  PageFaultCount;
        SIZE_T PeakWorkingSetSize;
        SIZE_T WorkingSetSize;
        SIZE_T QuotaPeakPagedPoolUsage;
        SIZE_T QuotaPagedPoolUsage;
        SIZE_T QuotaPeakNonPagedPoolUsage;
        SIZE_T QuotaNonPagedPoolUsage;
        SIZE_T PagefileUsage;
        SIZE_T PeakPagefileUsage;
        SIZE_T PrivateUsage;
    } pmc{};
    pmc.cb = sizeof(pmc);
    HANDLE hProcess = GetCurrentProcess();

    HMODULE hPsapi = LoadLibraryA("psapi.dll");
    if (hPsapi) {
        using FnGetProcessMemoryInfo = BOOL(WINAPI*)(HANDLE, LPVOID, DWORD);
        auto pGetPMI = reinterpret_cast<FnGetProcessMemoryInfo>(
            GetProcAddress(hPsapi, "GetProcessMemoryInfo"));
        if (pGetPMI && pGetPMI(hProcess, &pmc, sizeof(pmc))) {
            std::cout << "[mem] Working set:   " << pmc.WorkingSetSize / 1024 << " KB" << std::endl;
            std::cout << "[mem] Private bytes: " << pmc.PrivateUsage / 1024 << " KB" << std::endl;
        }
    }
}

void HeapDemo() {
    HANDLE hHeap = HeapCreate(0, 0x1000, 0);
    if (!hHeap) return;

    void* block = HeapAlloc(hHeap, HEAP_ZERO_MEMORY, 256);
    if (block) {
        memcpy(block, "heap allocated secret data", 26);
        std::cout << "[mem] Heap block:    " << static_cast<char*>(block) << std::endl;
        HeapFree(hHeap, 0, block);
    }
    HeapDestroy(hHeap);
}

} // namespace Memory

// ─────────────────────────────────────────────────────────────────────
// File system operations — kernel32 file APIs
// ─────────────────────────────────────────────────────────────────────

namespace FileOps {

void TempFileDemo() {
    char tempPath[MAX_PATH]{};
    char tempFile[MAX_PATH]{};
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "rev", 0, tempFile);

    HANDLE hFile = CreateFileA(tempFile, GENERIC_WRITE | GENERIC_READ,
        0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return;

    const char* data = "reversio_marker_data_v2";
    DWORD written = 0;
    WriteFile(hFile, data, static_cast<DWORD>(strlen(data)), &written, nullptr);

    SetFilePointer(hFile, 0, nullptr, FILE_BEGIN);
    char readBuf[64]{};
    DWORD bytesRead = 0;
    ReadFile(hFile, readBuf, sizeof(readBuf) - 1, &bytesRead, nullptr);

    std::cout << "[file] Temp:         " << tempFile << std::endl;
    std::cout << "[file] Written:      " << written << " bytes" << std::endl;
    std::cout << "[file] Read back:    " << readBuf << std::endl;

    CloseHandle(hFile);
    DeleteFileA(tempFile);
}

} // namespace FileOps

// ─────────────────────────────────────────────────────────────────────
// System info — GetSystemInfo, environment, etc.
// ─────────────────────────────────────────────────────────────────────

namespace SysInfo {

void Print() {
    SYSTEM_INFO si{};
    GetSystemInfo(&si);

    char compName[MAX_COMPUTERNAME_LENGTH + 1]{};
    DWORD compSize = sizeof(compName);
    GetComputerNameA(compName, &compSize);

    char userName[256]{};
    DWORD userSize = sizeof(userName);
    GetUserNameA(userName, &userSize);

    DWORD ver = GetVersion();
    DWORD major = LOBYTE(LOWORD(ver));
    DWORD minor = HIBYTE(LOWORD(ver));

    std::cout << "[sys] Computer:      " << compName << std::endl;
    std::cout << "[sys] User:          " << userName << std::endl;
    std::cout << "[sys] Processors:    " << si.dwNumberOfProcessors << std::endl;
    std::cout << "[sys] Arch:          " << si.wProcessorArchitecture << std::endl;
    std::cout << "[sys] OS version:    " << major << "." << minor << std::endl;
    std::cout << "[sys] Tick count:    " << GetTickCount64() << " ms" << std::endl;
}

} // namespace SysInfo

// ─────────────────────────────────────────────────────────────────────
// Entry point
// ─────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "  Reversio Sample Target v2.0" << std::endl;
    std::cout << "  Compile & analyze with Reversio" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;

    // --- System Information ---
    std::cout << "--- System Info ---" << std::endl;
    SysInfo::Print();
    std::cout << std::endl;

    // --- Anti-Debug Checks ---
    std::cout << "--- Anti-Debug ---" << std::endl;
    AntiDebug::RunAll();
    std::cout << std::endl;

    // --- Process Enumeration ---
    std::cout << "--- Processes (top 10) ---" << std::endl;
    ProcessEnum::List(10);
    std::cout << std::endl;

    // --- Dynamic API Resolution ---
    std::cout << "--- Dynamic API Resolution ---" << std::endl;
    DynAPI::ResolveNtdll();
    DynAPI::ResolveKernel32Extras();
    std::cout << std::endl;

    // --- Registry ---
    std::cout << "--- Registry ---" << std::endl;
    if (Registry::WriteConfig("InstallPath", "C:\\ReversioSample")) {
        std::cout << "[reg] Written: InstallPath" << std::endl;
        std::string val = Registry::ReadConfig("InstallPath");
        std::cout << "[reg] Read:    " << val << std::endl;
        Registry::Cleanup();
        std::cout << "[reg] Cleaned up" << std::endl;
    }
    std::cout << std::endl;

    // --- Crypto ---
    std::cout << "--- Crypto ---" << std::endl;
    Crypto::Demo();
    std::cout << std::endl;

    // --- Network ---
    std::cout << "--- Network ---" << std::endl;
    if (Network::Init()) {
        Network::ResolveDomain(g_c2_domain);
        Network::ConnectTCP("93.184.216.34", "80");
        Network::Cleanup();
    }
    std::cout << std::endl;

    // --- IPC ---
    std::cout << "--- IPC ---" << std::endl;
    HANDLE hMutex = IPC::CreateSingleInstanceMutex();
    HANDLE hPipe = IPC::CreateIPCPipe();
    if (hPipe && hPipe != INVALID_HANDLE_VALUE) CloseHandle(hPipe);
    if (hMutex) CloseHandle(hMutex);
    std::cout << std::endl;

    // --- Memory ---
    std::cout << "--- Memory ---" << std::endl;
    Memory::SelfInspect();
    Memory::HeapDemo();
    std::cout << std::endl;

    // --- File I/O ---
    std::cout << "--- File I/O ---" << std::endl;
    FileOps::TempFileDemo();
    std::cout << std::endl;

    // --- Exported Plugin API ---
    std::cout << "--- Plugin Exports ---" << std::endl;
    PluginInit(2);
    std::cout << "[export] Name: " << PluginName() << std::endl;
    PluginShutdown();
    std::cout << std::endl;

    std::cout << "========================================" << std::endl;
    std::cout << "  Sample complete. Analyze sample.exe" << std::endl;
    std::cout << "  with: reversio r sample.exe" << std::endl;
    std::cout << "========================================" << std::endl;

    return 0;
}
