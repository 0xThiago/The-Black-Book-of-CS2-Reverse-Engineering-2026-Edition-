# Técnica 039: Anti-Debugging Techniques

> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Anti-Debugging Techniques** detectam e evitam análise com debuggers, ocultando comportamento malicioso. São usadas para proteger cheats contra engenharia reversa.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class AntiDebugger {
private:
    std::vector<DEBUG_CHECK> debugChecks;
    HANDLE hDebugEvent;
    
public:
    void Initialize() {
        // Registrar verificações de debug
        RegisterDebugChecks();
        
        // Iniciar thread de monitoramento
        StartDebugMonitoring();
    }
    
    void PerformDebugChecks() {
        for (const DEBUG_CHECK& check : debugChecks) {
            if (check.function()) {
                // Debugger detectado
                OnDebuggerDetected(check.name);
                break;
            }
        }
    }
    
    void Cleanup() {
        if (hDebugEvent) {
            CloseHandle(hDebugEvent);
        }
    }
    
private:
    void RegisterDebugChecks() {
        // Verificações básicas
        debugChecks.push_back({"IsDebuggerPresent", []() { return IsDebuggerPresent(); }});
        debugChecks.push_back({"CheckRemoteDebuggerPresent", []() { return CheckRemoteDebuggerPresentAPI(); }});
        debugChecks.push_back({"NtQueryInformationProcess", []() { return NtQueryInformationProcessCheck(); }});
        
        // Verificações avançadas
        debugChecks.push_back({"HardwareBreakpoints", []() { return CheckHardwareBreakpoints(); }});
        debugChecks.push_back({"SoftwareBreakpoints", []() { return CheckSoftwareBreakpoints(); }});
        debugChecks.push_back({"MemoryBreakpoints", []() { return CheckMemoryBreakpoints(); }});
        
        // Verificações de timing
        debugChecks.push_back({"TimingCheck", []() { return CheckTimingAnomalies(); }});
        
        // Verificações de sistema
        debugChecks.push_back({"DebugPort", []() { return CheckDebugPort(); }});
        debugChecks.push_back({"DebugObject", []() { return CheckDebugObject(); }});
    }
    
    void StartDebugMonitoring() {
        // Criar thread para verificações periódicas
        hDebugEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        
        std::thread([this]() {
            while (WaitForSingleObject(hDebugEvent, 1000) == WAIT_TIMEOUT) {
                PerformDebugChecks();
            }
        }).detach();
    }
    
    void OnDebuggerDetected(const std::string& checkName) {
        // Log da detecção
        LogDebuggerDetection(checkName);
        
        // Ações anti-debug
        PerformAntiDebugActions();
        
        // Possivelmente crash ou exit
        ExitProcess(0);
    }
    
    static bool CheckRemoteDebuggerPresentAPI() {
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        return isDebugged;
    }
    
    static bool NtQueryInformationProcessCheck() {
        typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        NtQueryInformationProcess_t pNtQueryInformationProcess = 
            (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!pNtQueryInformationProcess) return false;
        
        PROCESS_DEBUG_PORT_INFO debugPort = {0};
        NTSTATUS status = pNtQueryInformationProcess(
            GetCurrentProcess(), 
            ProcessDebugPort, 
            &debugPort, 
            sizeof(debugPort), 
            NULL
        );
        
        return NT_SUCCESS(status) && debugPort.DebugPort != NULL;
    }
    
    static bool CheckHardwareBreakpoints() {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (!GetThreadContext(GetCurrentThread(), &ctx)) {
            return false;
        }
        
        // Verificar Dr0-Dr3
        return ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0;
    }
    
    static bool CheckSoftwareBreakpoints() {
        // Verificar INT3 (0xCC) em funções importantes
        return CheckInt3Breakpoint((PVOID)MessageBoxA) ||
               CheckInt3Breakpoint((PVOID)CreateFileA) ||
               CheckInt3Breakpoint((PVOID)VirtualAlloc);
    }
    
    static bool CheckInt3Breakpoint(PVOID address) {
        __try {
            return *(BYTE*)address == 0xCC;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }
    
    static bool CheckMemoryBreakpoints() {
        // Verificar PAGE_GUARD em regiões importantes
        MEMORY_BASIC_INFORMATION mbi;
        
        PVOID addresses[] = {
            (PVOID)MessageBoxA,
            (PVOID)CreateFileA,
            (PVOID)VirtualAlloc
        };
        
        for (PVOID addr : addresses) {
            if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
                if (mbi.Protect & PAGE_GUARD) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    static bool CheckTimingAnomalies() {
        // Medir tempo de execução
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        // Operação dummy
        volatile int sum = 0;
        for (int i = 0; i < 100000; i++) {
            sum += i;
        }
        
        QueryPerformanceCounter(&end);
        
        // Calcular tempo em ms
        double timeMs = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
        
        // Se muito lento, pode estar sendo debugged
        return timeMs > 10.0; // 10ms threshold
    }
    
    static bool CheckDebugPort() {
        typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        NtQueryInformationProcess_t pNtQueryInformationProcess = 
            (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!pNtQueryInformationProcess) return false;
        
        HANDLE debugPort = NULL;
        NTSTATUS status = pNtQueryInformationProcess(
            GetCurrentProcess(), 
            ProcessDebugPort, 
            &debugPort, 
            sizeof(debugPort), 
            NULL
        );
        
        return NT_SUCCESS(status) && debugPort != NULL;
    }
    
    static bool CheckDebugObject() {
        typedef NTSTATUS(NTAPI* NtQueryInformationProcess_t)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        NtQueryInformationProcess_t pNtQueryInformationProcess = 
            (NtQueryInformationProcess_t)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        if (!pNtQueryInformationProcess) return false;
        
        HANDLE debugObject = NULL;
        NTSTATUS status = pNtQueryInformationProcess(
            GetCurrentProcess(), 
            ProcessDebugObjectHandle, 
            &debugObject, 
            sizeof(debugObject), 
            NULL
        );
        
        if (NT_SUCCESS(status) && debugObject) {
            CloseHandle(debugObject);
            return true;
        }
        
        return false;
    }
    
    void LogDebuggerDetection(const std::string& checkName) {
        // Log para arquivo ou console
        std::ofstream log("debug_detection.log", std::ios::app);
        log << "Debugger detected via: " << checkName << " at " 
            << std::time(nullptr) << std::endl;
        log.close();
    }
    
    void PerformAntiDebugActions() {
        // Ações para dificultar debugging
        RemoveBreakpoints();
        CorruptStack();
        TriggerFalsePositives();
    }
    
    void RemoveBreakpoints() {
        // Tentar remover breakpoints de hardware
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            ctx.Dr0 = ctx.Dr1 = ctx.Dr2 = ctx.Dr3 = 0;
            ctx.Dr6 = ctx.Dr7 = 0;
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }
    
    void CorruptStack() {
        // Corromper stack para causar crashes no debugger
        volatile char buffer[1024];
        memset((void*)buffer, 0xCC, sizeof(buffer)); // INT3
        
        // Overwrite return address
        DWORD* pReturnAddr = (DWORD*)_AddressOfReturnAddress();
        *pReturnAddr = 0xCCCCCCCC;
    }
    
    void TriggerFalsePositives() {
        // Trigger exceptions para confundir debugger
        __try {
            RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Ignorar
        }
    }
};
```

### Advanced Anti-Debugging

```cpp
// Anti-debugging avançado
class AdvancedAntiDebugger : public AntiDebugger {
private:
    VEH_HANDLER vehHandler;
    std::vector<MEMORY_REGION> protectedRegions;
    
public:
    void InitializeAdvanced() {
        AntiDebugger::Initialize();
        
        // Instalar VEH
        InstallVEH();
        
        // Proteger regiões críticas
        ProtectCriticalRegions();
        
        // Anti-VM checks
        PerformAntiVMChecks();
    }
    
    void InstallVEH() {
        vehHandler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    }
    
    void ProtectCriticalRegions() {
        // Proteger código anti-debug
        ProtectRegion((PVOID)AntiDebugger::PerformDebugChecks, 0x1000);
        
        // Proteger strings
        ProtectStringRegions();
    }
    
    void ProtectRegion(PVOID address, SIZE_T size) {
        MEMORY_REGION region;
        region.address = address;
        region.size = size;
        
        // Obter proteção atual
        VirtualQuery(address, &region.mbi, sizeof(region.mbi));
        
        // Definir PAGE_GUARD
        DWORD oldProtect;
        VirtualProtect(address, size, region.mbi.Protect | PAGE_GUARD, &oldProtect);
        
        protectedRegions.push_back(region);
    }
    
    void ProtectStringRegions() {
        // Encontrar e proteger strings sensíveis
        PVOID imageBase = GetModuleHandle(NULL);
        
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pDosHeader->e_lfanew);
        
        // Proteger seção .rdata
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)pSection[i].Name, ".rdata") == 0) {
                PVOID rdataAddr = (PBYTE)imageBase + pSection[i].VirtualAddress;
                ProtectRegion(rdataAddr, pSection[i].Misc.VirtualSize);
                break;
            }
        }
    }
    
    void PerformAntiVMChecks() {
        // Verificar se está rodando em VM
        if (IsRunningInVM()) {
            OnVMDetected();
        }
    }
    
    bool IsRunningInVM() {
        // Verificações de VM
        return CheckCPUID() || CheckRegistryKeys() || CheckProcesses() || CheckMACAddress();
    }
    
    bool CheckCPUID() {
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        
        // Verificar hypervisor bit
        return (cpuInfo[2] & (1 << 31)) != 0;
    }
    
    bool CheckRegistryKeys() {
        // Verificar chaves de registro de VM
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 
                         0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        return false;
    }
    
    bool CheckProcesses() {
        // Verificar processos de VM
        const char* vmProcesses[] = {
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "vboxservice.exe",
            "vboxtray.exe"
        };
        
        for (const char* proc : vmProcesses) {
            if (IsProcessRunning(proc)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool CheckMACAddress() {
        // Verificar MAC address de VM
        const char* vmMacPrefixes[] = {
            "08:00:27", // VirtualBox
            "00:05:69", // VMware
            "00:0C:29", // VMware
            "00:1C:14", // VMware
            "00:50:56"  // VMware
        };
        
        // Obter MAC address
        // ... código para obter MAC ...
        
        return false; // Placeholder
    }
    
    bool IsProcessRunning(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    void OnVMDetected() {
        // Ações quando VM é detectada
        LogVMDetection();
        
        // Possivelmente exit ou comportamento diferente
        ExitProcess(0);
    }
    
    void LogVMDetection() {
        std::ofstream log("vm_detection.log", std::ios::app);
        log << "VM detected at " << std::time(nullptr) << std::endl;
        log.close();
    }
    
    static LONG CALLBACK VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
        // Handler para exceptions
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == STATUS_GUARD_PAGE_VIOLATION) {
            // PAGE_GUARD violation - possível debugging
            OnGuardPageViolation(ExceptionInfo);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
            // Breakpoint hit
            OnBreakpointHit(ExceptionInfo);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
            // Single step
            OnSingleStep(ExceptionInfo);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    static void OnGuardPageViolation(PEXCEPTION_POINTERS ExceptionInfo) {
        // Log acesso a região protegida
        LogGuardPageAccess(ExceptionInfo->ExceptionRecord->ExceptionAddress);
        
        // Reparar proteção
        RepairGuardPageProtection(ExceptionInfo->ExceptionRecord->ExceptionAddress);
    }
    
    static void OnBreakpointHit(PEXCEPTION_POINTERS ExceptionInfo) {
        // Breakpoint atingido - possível debugger
        LogBreakpointHit(ExceptionInfo->ExceptionRecord->ExceptionAddress);
        
        // Remover breakpoint
        RemoveBreakpoint(ExceptionInfo->ExceptionRecord->ExceptionAddress);
    }
    
    static void OnSingleStep(PEXCEPTION_POINTERS ExceptionInfo) {
        // Single stepping detectado
        LogSingleStep();
        
        // Corromper execução
        CorruptExecutionFlow(ExceptionInfo);
    }
    
    static void LogGuardPageAccess(PVOID address) {
        std::ofstream log("guard_page.log", std::ios::app);
        log << "Guard page access at: " << address << std::endl;
        log.close();
    }
    
    static void RepairGuardPageProtection(PVOID address) {
        // Restaurar PAGE_GUARD
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi))) {
            DWORD oldProtect;
            VirtualProtect(address, mbi.RegionSize, mbi.Protect | PAGE_GUARD, &oldProtect);
        }
    }
    
    static void RemoveBreakpoint(PVOID address) {
        // Substituir INT3 por NOP
        DWORD oldProtect;
        if (VirtualProtect(address, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            *(BYTE*)address = 0x90; // NOP
            VirtualProtect(address, 1, oldProtect, &oldProtect);
        }
    }
    
    static void CorruptExecutionFlow(PEXCEPTION_POINTERS ExceptionInfo) {
        // Modificar EIP/RIP para confundir debugger
        #ifdef _WIN64
            ExceptionInfo->ContextRecord->Rip += 1; // Skip instruction
        #else
            ExceptionInfo->ContextRecord->Eip += 1; // Skip instruction
        #endif
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Anti-debugging deixa rastros através de verificações óbvias e comportamento suspeito**

#### 1. Signature-Based Detection
```cpp
// Detecção baseada em assinaturas
class AntiDebugSignatureDetector {
private:
    std::vector<BYTE_SIGNATURE> knownSignatures;
    
public:
    void Initialize() {
        // Registrar assinaturas conhecidas de anti-debug
        RegisterKnownSignatures();
    }
    
    void ScanForAntiDebugSignatures(PVOID baseAddress, SIZE_T size) {
        // Escanear memória por assinaturas
        for (const BYTE_SIGNATURE& sig : knownSignatures) {
            if (FindSignature(baseAddress, size, sig)) {
                ReportAntiDebugSignature(sig.name);
            }
        }
    }
    
    void RegisterKnownSignatures() {
        // IsDebuggerPresent
        knownSignatures.push_back({
            "IsDebuggerPresent",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00}, // CALL DWORD PTR
            "KERNEL32.dll!IsDebuggerPresent"
        });
        
        // CheckRemoteDebuggerPresent
        knownSignatures.push_back({
            "CheckRemoteDebuggerPresent",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00},
            "KERNEL32.dll!CheckRemoteDebuggerPresent"
        });
        
        // NtQueryInformationProcess
        knownSignatures.push_back({
            "NtQueryInformationProcess",
            {0xB8, 0x00, 0x00, 0x00, 0x00, 0xBA, 0x00, 0x00, 0x00, 0x00}, // MOV EAX, syscall
            "ntdll.dll!NtQueryInformationProcess"
        });
        
        // INT3 checks
        knownSignatures.push_back({
            "INT3_Check",
            {0x80, 0x38, 0xCC}, // CMP BYTE PTR [EAX], 0xCC
            "Software breakpoint check"
        });
        
        // Timing checks
        knownSignatures.push_back({
            "Timing_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x2B, 0xC1}, // QueryPerformanceCounter + SUB
            "Timing anomaly detection"
        });
    }
    
    bool FindSignature(PVOID baseAddress, SIZE_T size, const BYTE_SIGNATURE& sig) {
        BYTE* data = (BYTE*)baseAddress;
        
        for (SIZE_T i = 0; i < size - sig.pattern.size(); i++) {
            if (memcmp(&data[i], sig.pattern.data(), sig.pattern.size()) == 0) {
                return true;
            }
        }
        
        return false;
    }
    
    void ReportAntiDebugSignature(const std::string& signatureName) {
        // Reportar detecção de assinatura anti-debug
    }
};
```

#### 2. Behavioral Analysis
```cpp
// Análise comportamental
class AntiDebugBehaviorAnalyzer {
private:
    std::map<DWORD, PROCESS_BEHAVIOR> processBehaviors;
    
public:
    void MonitorProcessBehavior(DWORD processId) {
        // Registrar comportamento normal
        RegisterNormalBehavior(processId);
        
        // Monitorar desvios
        StartBehaviorMonitoring(processId);
    }
    
    void RegisterNormalBehavior(DWORD processId) {
        PROCESS_BEHAVIOR behavior;
        
        // Registrar chamadas de sistema normais
        behavior.expectedSyscalls = {
            "NtReadFile",
            "NtWriteFile", 
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory"
        };
        
        // Registrar tempo de resposta normal
        behavior.expectedResponseTime = 100; // ms
        
        processBehaviors[processId] = behavior;
    }
    
    void StartBehaviorMonitoring(DWORD processId) {
        // Monitorar em thread separado
        std::thread([this, processId]() {
            while (true) {
                CheckBehavioralAnomalies(processId);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }).detach();
    }
    
    void CheckBehavioralAnomalies(DWORD processId) {
        if (processBehaviors.find(processId) == processBehaviors.end()) return;
        
        PROCESS_BEHAVIOR& behavior = processBehaviors[processId];
        
        // Verificar chamadas de sistema suspeitas
        if (HasSuspiciousSyscalls(processId)) {
            ReportSuspiciousSyscalls(processId);
        }
        
        // Verificar tempo de resposta
        if (HasAbnormalResponseTime(processId, behavior.expectedResponseTime)) {
            ReportAbnormalTiming(processId);
        }
        
        // Verificar uso de CPU
        if (HasAbnormalCPUUsage(processId)) {
            ReportAbnormalCPUUsage(processId);
        }
    }
    
    bool HasSuspiciousSyscalls(DWORD processId) {
        // Verificar se processo está fazendo muitas chamadas NtQueryInformationProcess
        // ou outras chamadas suspeitas
        
        return false; // Placeholder
    }
    
    bool HasAbnormalResponseTime(DWORD processId, DWORD expectedTime) {
        // Medir tempo de resposta do processo
        
        return false; // Placeholder
    }
    
    bool HasAbnormalCPUUsage(DWORD processId) {
        // Verificar uso de CPU anormal (baixo quando deveria ser normal)
        
        return false; // Placeholder
    }
    
    void ReportSuspiciousSyscalls(DWORD processId) {
        // Reportar syscalls suspeitos
    }
    
    void ReportAbnormalTiming(DWORD processId) {
        // Reportar timing anormal
    }
    
    void ReportAbnormalCPUUsage(DWORD processId) {
        // Reportar uso anormal de CPU
    }
};
```

#### 3. Anti-Anti-Debug Techniques
```cpp
// Técnicas anti-anti-debug
class AntiAntiDebugger {
public:
    void BypassAntiDebugChecks() {
        // Bypass IsDebuggerPresent
        BypassIsDebuggerPresent();
        
        // Bypass timing checks
        BypassTimingChecks();
        
        // Bypass hardware breakpoint checks
        BypassHardwareBreakpointChecks();
    }
    
    void BypassIsDebuggerPresent() {
        // Hook IsDebuggerPresent para sempre retornar FALSE
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
        
        // Usar MinHook ou similar
        MH_CreateHook(pIsDebuggerPresent, &HkIsDebuggerPresent, &oIsDebuggerPresent);
        MH_EnableHook(pIsDebuggerPresent);
    }
    
    static BOOL WINAPI HkIsDebuggerPresent() {
        return FALSE;
    }
    
    void BypassTimingChecks() {
        // Hook QueryPerformanceCounter
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pQueryPerformanceCounter = GetProcAddress(hKernel32, "QueryPerformanceCounter");
        
        MH_CreateHook(pQueryPerformanceCounter, &HkQueryPerformanceCounter, &oQueryPerformanceCounter);
        MH_EnableHook(pQueryPerformanceCounter);
    }
    
    static BOOL WINAPI HkQueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount) {
        // Chamar original
        BOOL result = oQueryPerformanceCounter(lpPerformanceCount);
        
        // Adicionar ruído para mascarar timing
        lpPerformanceCount->QuadPart += rand() % 1000;
        
        return result;
    }
    
    void BypassHardwareBreakpointChecks() {
        // Hook GetThreadContext
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pGetThreadContext = GetProcAddress(hKernel32, "GetThreadContext");
        
        MH_CreateHook(pGetThreadContext, &HkGetThreadContext, &oGetThreadContext);
        MH_EnableHook(pGetThreadContext);
    }
    
    static BOOL WINAPI HkGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
        // Chamar original
        BOOL result = oGetThreadContext(hThread, lpContext);
        
        if (result && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
            // Limpar registros de debug
            lpContext->Dr0 = lpContext->Dr1 = lpContext->Dr2 = lpContext->Dr3 = 0;
            lpContext->Dr6 = lpContext->Dr7 = 0;
        }
        
        return result;
    }
    
private:
    static decltype(&IsDebuggerPresent) oIsDebuggerPresent;
    static decltype(&QueryPerformanceCounter) oQueryPerformanceCounter;
    static decltype(&GetThreadContext) oGetThreadContext;
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Signature scanning | < 30s | 85% |
| VAC Live | Behavioral analysis | Imediato | 80% |
| BattlEye | Anti-anti-debug hooks | < 1 min | 90% |
| Faceit AC | Timing analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Obfuscation
```cpp
// ✅ Obfuscação de código
class CodeObfuscator {
public:
    void ObfuscateCode() {
        // Ofuscar strings
        ObfuscateStrings();
        
        // Ofuscar fluxo de controle
        ObfuscateControlFlow();
        
        // Adicionar junk code
        AddJunkCode();
    }
    
    void ObfuscateStrings() {
        // Encriptar strings em tempo de execução
        const char* encryptedString = "\x12\x34\x56\x78"; // Encrypted "IsDebuggerPresent"
        
        char* decrypted = DecryptString(encryptedString);
        // Usar decrypted
        free(decrypted);
    }
    
    void ObfuscateControlFlow() {
        // Usar opaque predicates
        if (IsPrime(17)) { // Sempre true
            PerformDebugCheck();
        } else {
            // Código unreachable
            DummyFunction();
        }
    }
    
    void AddJunkCode() {
        // Adicionar código morto
        volatile int junk = 0;
        for (int i = 0; i < 100; i++) {
            junk += rand();
        }
    }
    
    bool IsPrime(int n) {
        if (n <= 1) return false;
        for (int i = 2; i * i <= n; i++) {
            if (n % i == 0) return false;
        }
        return true;
    }
    
    char* DecryptString(const char* encrypted) {
        // XOR decryption
        size_t len = strlen(encrypted);
        char* decrypted = (char*)malloc(len + 1);
        
        for (size_t i = 0; i < len; i++) {
            decrypted[i] = encrypted[i] ^ 0xAA; // XOR key
        }
        decrypted[len] = '\0';
        
        return decrypted;
    }
};
```

### 2. Polymorphic Code
```cpp
// ✅ Código polimórfico
class PolymorphicCodeGenerator {
public:
    void GeneratePolymorphicChecks() {
        // Gerar verificações diferentes a cada execução
        int checkType = rand() % 5;
        
        switch (checkType) {
            case 0:
                CheckDebuggerPresent_Variant1();
                break;
            case 1:
                CheckDebuggerPresent_Variant2();
                break;
            case 2:
                CheckDebuggerPresent_Variant3();
                break;
            case 3:
                CheckTiming_Variant1();
                break;
            case 4:
                CheckTiming_Variant2();
                break;
        }
    }
    
    void CheckDebuggerPresent_Variant1() {
        // Variante 1: Usar PEB
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->BeingDebugged) {
            OnDebuggerDetected();
        }
    }
    
    void CheckDebuggerPresent_Variant2() {
        // Variante 2: Usar NtQueryInformationProcess
        HANDLE debugPort = NULL;
        NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugPort, 
                                &debugPort, sizeof(debugPort), NULL);
        if (debugPort) {
            OnDebuggerDetected();
        }
    }
    
    void CheckDebuggerPresent_Variant3() {
        // Variante 3: Usar heap flags
        PPEB peb = (PPEB)__readgsqword(0x60);
        if (peb->NtGlobalFlag & 0x70) { // FLG_HEAP_ENABLE_TAIL_CHECK, etc.
            OnDebuggerDetected();
        }
    }
    
    void CheckTiming_Variant1() {
        // Variante 1: Usar rdtsc
        uint64_t start = __rdtsc();
        Sleep(1);
        uint64_t end = __rdtsc();
        
        if (end - start < 1000000) { // Muito rápido - possível VM/debugger
            OnDebuggerDetected();
        }
    }
    
    void CheckTiming_Variant2() {
        // Variante 2: Usar GetTickCount
        DWORD start = GetTickCount();
        volatile int dummy = 0;
        for (int i = 0; i < 100000; i++) dummy += i;
        DWORD end = GetTickCount();
        
        if (end - start > 100) { // Muito lento
            OnDebuggerDetected();
        }
    }
    
    void OnDebuggerDetected() {
        // Handler polimórfico
        int responseType = rand() % 3;
        
        switch (responseType) {
            case 0:
                ExitProcess(0);
                break;
            case 1:
                TerminateProcess(GetCurrentProcess(), 0);
                break;
            case 2:
                RaiseException(EXCEPTION_BREAKPOINT, EXCEPTION_NONCONTINUABLE, 0, NULL);
                break;
        }
    }
};
```

### 3. Environmental Awareness
```cpp
// ✅ Consciência ambiental
class EnvironmentalAwareness {
public:
    void AnalyzeEnvironment() {
        // Detectar se está em ambiente de análise
        if (IsAnalysisEnvironment()) {
            AdaptBehavior();
        }
    }
    
    bool IsAnalysisEnvironment() {
        return IsDebuggerAttached() || 
               IsDisassemblerPresent() || 
               IsSandboxEnvironment() ||
               IsVirtualMachine();
    }
    
    bool IsDebuggerAttached() {
        return IsDebuggerPresent() || CheckRemoteDebuggerPresentAPI();
    }
    
    bool IsDisassemblerPresent() {
        // Verificar processos de desassembler
        const char* disassemblers[] = {
            "ida.exe",
            "ida64.exe", 
            "x64dbg.exe",
            "x32dbg.exe",
            "ollydbg.exe",
            "windbg.exe"
        };
        
        for (const char* proc : disassemblers) {
            if (FindProcess(proc)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool IsSandboxEnvironment() {
        // Verificar características de sandbox
        return CheckSandboxFiles() || CheckSandboxRegistry() || CheckSandboxNetwork();
    }
    
    bool IsVirtualMachine() {
        // Verificar se está em VM
        return CheckVMArtifacts() || CheckVMMemory() || CheckVMProcesses();
    }
    
    void AdaptBehavior() {
        // Adaptar comportamento baseado no ambiente
        if (IsDebuggerAttached()) {
            // Comportamento anti-debug
            PerformAntiDebugActions();
        } else if (IsSandboxEnvironment()) {
            // Comportamento anti-sandbox
            PerformAntiSandboxActions();
        } else if (IsVirtualMachine()) {
            // Comportamento anti-VM
            PerformAntiVMActions();
        }
    }
    
    void PerformAntiDebugActions() {
        // Ações específicas para debuggers
        RemoveBreakpoints();
        CorruptDebugInfo();
    }
    
    void PerformAntiSandboxActions() {
        // Ações específicas para sandboxes
        DelayExecution();
        CheckUserInteraction();
    }
    
    void PerformAntiVMActions() {
        // Ações específicas para VMs
        DetectHypervisor();
        ModifyVMBehavior();
    }
    
    bool FindProcess(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    bool CheckSandboxFiles() {
        // Verificar arquivos de sandbox
        const char* sandboxFiles[] = {
            "C:\\sandbox\\",
            "C:\\analysis\\",
            "C:\\cuckoo\\"
        };
        
        for (const char* path : sandboxFiles) {
            if (PathFileExistsA(path)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool CheckSandboxRegistry() {
        // Verificar chaves de registro de sandbox
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Sandbox", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return true;
        }
        
        return false;
    }
    
    bool CheckSandboxNetwork() {
        // Verificar conectividade de rede limitada
        return false; // Placeholder
    }
    
    bool CheckVMArtifacts() {
        // Verificar artefatos de VM
        return CheckVMRegistry() || CheckVMMacros() || CheckVMDevices();
    }
    
    bool CheckVMMemory() {
        // Verificar assinaturas de VM na memória
        return false; // Placeholder
    }
    
    bool CheckVMProcesses() {
        // Verificar processos de VM
        const char* vmProcs[] = {
            "vmtoolsd.exe",
            "vboxservice.exe",
            "vmmemctl.exe"
        };
        
        for (const char* proc : vmProcs) {
            if (FindProcess(proc)) {
                return true;
            }
        }
        
        return false;
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Signature detection |
| 2020-2024 | ⚠️ Médio risco | Behavioral analysis |
| 2025-2026 | ⚠️ Alto risco | Advanced bypass |

---

## 🎯 Lições Aprendidas

1. **Verificações São Assinaturas**: Código anti-debug é facilmente identificado por padrões.

2. **Comportamento é Rastreado**: Ações suspeitas são monitoradas.

3. **Timing é Analisado**: Anomalias de tempo são detectadas.

4. **Obfuscação é Melhor**: Código ofuscado é mais difícil de analisar.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#39]]
- [[Code_Obfuscation]]
- [[Polymorphic_Code]]
- [[Environmental_Awareness]]

---

*Anti-debugging tem risco moderado. Considere obfuscação para mais stealth.*