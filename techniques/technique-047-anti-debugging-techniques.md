# 📖 Técnica 047: Anti-Debugging Techniques

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 047: Anti-Debugging Techniques]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Anti-Debugging Techniques** detectam presença de debuggers e ferramentas de análise, impedindo debugging e análise dinâmica do código.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class AntiDebugger {
private:
    std::vector<DEBUG_CHECK> debugChecks;
    DETECTION_REPORT report;
    
public:
    AntiDebugger() {
        InitializeDebugChecks();
    }
    
    void InitializeDebugChecks() {
        // Verificações de debugger
        debugChecks.push_back({CHECK_ISDEBUGGERPRESENT, "IsDebuggerPresent", []() { return CheckIsDebuggerPresent(); }});
        debugChecks.push_back({CHECK_REMOTEDEBUGGER, "Remote debugger", []() { return CheckRemoteDebuggerPresent(); }});
        debugChecks.push_back({CHECK_DEBUGPORT, "Debug port", []() { return CheckDebugPort(); }});
        debugChecks.push_back({CHECK_DEBUGOBJECT, "Debug object", []() { return CheckDebugObjectHandle(); }});
        
        // Verificações de timing
        debugChecks.push_back({CHECK_TIMING, "Timing checks", []() { return CheckTimingAnomalies(); }});
        debugChecks.push_back({CHECK_RDTSC, "RDTSC timing", []() { return CheckRDTSCDebugging(); }});
        debugChecks.push_back({CHECK_QUERYPERF, "QueryPerformanceCounter", []() { return CheckQueryPerformanceCounter(); }});
        
        // Verificações de hardware breakpoints
        debugChecks.push_back({CHECK_HARDWARE_BREAKPOINTS, "Hardware breakpoints", []() { return CheckHardwareBreakpoints(); }});
        debugChecks.push_back({CHECK_DEBUG_REGISTERS, "Debug registers", []() { return CheckDebugRegisters(); }});
        
        // Verificações de software breakpoints
        debugChecks.push_back({CHECK_SOFTWARE_BREAKPOINTS, "Software breakpoints", []() { return CheckSoftwareBreakpoints(); }});
        debugChecks.push_back({CHECK_INT3, "INT3 instructions", []() { return CheckINT3Breakpoints(); }});
        
        // Verificações de exceptions
        debugChecks.push_back({CHECK_EXCEPTION_HANDLING, "Exception handling", []() { return CheckExceptionHandling(); }});
        debugChecks.push_back({CHECK_VEH, "Vectored exception handlers", []() { return CheckVectoredExceptionHandlers(); }});
        
        // Verificações de processo
        debugChecks.push_back({CHECK_PARENT_PROCESS, "Parent process", []() { return CheckParentProcess(); }});
        debugChecks.push_back({CHECK_DEBUGGER_PROCESSES, "Debugger processes", []() { return CheckDebuggerProcesses(); }});
        
        // Verificações avançadas
        debugChecks.push_back({CHECK_NTQUERYINFO, "NtQueryInformationProcess", []() { return CheckNtQueryInformationProcess(); }});
        debugChecks.push_back({CHECK_HEAP_FLAGS, "Heap flags", []() { return CheckHeapFlags(); }});
        debugChecks.push_back({CHECK_TLS_CALLBACKS, "TLS callbacks", []() { return CheckTLSCallbacks(); }});
    }
    
    bool PerformDebugChecks() {
        report.debuggerDetected = false;
        report.checkResults.clear();
        
        for (const DEBUG_CHECK& check : debugChecks) {
            bool result = check.function();
            report.checkResults.push_back({check.name, result});
            
            if (result) {
                IdentifyDebuggerType(check);
                report.debuggerDetected = true;
            }
        }
        
        return report.debuggerDetected;
    }
    
    void IdentifyDebuggerType(const DEBUG_CHECK& check) {
        // Identificar tipo de debugger baseado na verificação
        if (check.type == CHECK_ISDEBUGGERPRESENT || check.type == CHECK_REMOTEDEBUGGER) {
            report.detectedDebuggers.push_back("User-mode debugger");
        } else if (check.type == CHECK_DEBUGPORT || check.type == CHECK_DEBUGOBJECT) {
            report.detectedDebuggers.push_back("Kernel-mode debugger");
        } else if (check.type == CHECK_TIMING || check.type == CHECK_RDTSC) {
            report.detectedDebuggers.push_back("Timing-based analysis");
        } else if (check.type == CHECK_HARDWARE_BREAKPOINTS) {
            report.detectedDebuggers.push_back("Hardware debugging");
        }
    }
    
    void OnDebuggerDetected() {
        // Ações quando debugger é detectado
        LogDebuggerDetected();
        
        // Comportamento diferente em debug
        ModifyBehaviorForDebug();
        
        // Possivelmente crash ou exit
        if (ShouldExitOnDebug()) {
            ExitProcess(0);
        }
    }
    
    void LogDebuggerDetected() {
        std::ofstream log("debugger_detection.log", std::ios::app);
        log << "Debugger detected at " << std::time(nullptr) << std::endl;
        for (const std::string& debugger : report.detectedDebuggers) {
            log << "  - " << debugger << std::endl;
        }
        log.close();
    }
    
    void ModifyBehaviorForDebug() {
        // Modificar comportamento quando em debug
        // Delay execution, corrupt data, etc.
        Sleep(8000); // 8 second delay
        
        // Corromper dados importantes
        CorruptImportantData();
    }
    
    bool ShouldExitOnDebug() {
        // Decidir se deve sair baseado na configuração
        return true; // Sempre sair por segurança
    }
    
    void CorruptImportantData() {
        // Corromper dados para tornar debugging difícil
        // Implementar corrupção de dados
    }
    
    // Implementações das verificações
    static bool CheckIsDebuggerPresent() {
        return IsDebuggerPresent();
    }
    
    static bool CheckRemoteDebuggerPresent() {
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        return isDebugged;
    }
    
    static bool CheckDebugPort() {
        // Verificar se processo tem debug port
        HANDLE hProcess = GetCurrentProcess();
        DWORD debugPort = 0;
        DWORD returned = 0;
        
        NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), &returned);
        return debugPort != 0;
    }
    
    static bool CheckDebugObjectHandle() {
        // Verificar se processo tem debug object handle
        HANDLE hDebugObject = NULL;
        DWORD returned = 0;
        
        NtQueryInformationProcess(GetCurrentProcess(), ProcessDebugObjectHandle, &hDebugObject, sizeof(hDebugObject), &returned);
        return hDebugObject != NULL;
    }
    
    static bool CheckTimingAnomalies() {
        DWORD start = GetTickCount();
        Sleep(100);
        DWORD end = GetTickCount();
        
        DWORD actualSleep = end - start;
        return actualSleep > 150; // Sleep muito longo (debugger single-stepping)
    }
    
    static bool CheckRDTSCDebugging() {
        uint64_t start = __rdtsc();
        
        // Código que deve executar rapidamente
        for (volatile int i = 0; i < 1000; i++) {
            // Loop vazio
        }
        
        uint64_t end = __rdtsc();
        
        uint64_t diff = end - start;
        return diff > 10000000; // Muito lento (debugging)
    }
    
    static bool CheckQueryPerformanceCounter() {
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        Sleep(100);
        
        QueryPerformanceCounter(&end);
        
        double timeMs = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
        return timeMs > 200; // Muito lento
    }
    
    static bool CheckHardwareBreakpoints() {
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3;
        }
        
        return false;
    }
    
    static bool CheckDebugRegisters() {
        // Verificar debug registers diretamente
        __try {
            uint64_t dr0 = 0;
            __asm {
                mov rax, dr0
                mov dr0, rax
            }
            return false; // Acesso permitido
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // Acesso negado - debugger presente
        }
    }
    
    static bool CheckSoftwareBreakpoints() {
        // Verificar breakpoints de software no código
        PVOID baseAddress = GetModuleHandle(NULL);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
        
        // Verificar se há INT3 (0xCC) no código
        BYTE* codeSection = (BYTE*)baseAddress + ntHeader->OptionalHeader.BaseOfCode;
        SIZE_T codeSize = ntHeader->OptionalHeader.SizeOfCode;
        
        for (SIZE_T i = 0; i < codeSize; i++) {
            if (codeSection[i] == 0xCC) {
                return true; // INT3 encontrado
            }
        }
        
        return false;
    }
    
    static bool CheckINT3Breakpoints() {
        // Verificar INT3 instructions
        __try {
            __asm {
                int 3  // INT3
            }
            return false; // Não executou INT3
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // INT3 capturado - debugger presente
        }
    }
    
    static bool CheckExceptionHandling() {
        // Verificar se exceptions são tratadas por debugger
        __try {
            RaiseException(0x12345678, 0, 0, NULL);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exception tratada - verificar se foi pelo debugger
            return GetExceptionCode() == 0x12345678;
        }
        
        return false;
    }
    
    static bool CheckVectoredExceptionHandlers() {
        // Verificar VEH instalados
        return GetFirstVectoredExceptionHandler() != NULL;
    }
    
    static bool CheckParentProcess() {
        // Verificar se processo pai é um debugger
        DWORD parentPid = GetParentProcessId();
        
        char parentName[MAX_PATH];
        if (GetProcessNameById(parentPid, parentName, MAX_PATH)) {
            const char* debuggers[] = {
                "ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
                "immunitydebugger.exe", "radare2.exe", "gdb.exe"
            };
            
            for (const char* debugger : debuggers) {
                if (_stricmp(parentName, debugger) == 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    static bool CheckDebuggerProcesses() {
        // Verificar se processos de debugger estão rodando
        const char* debuggerProcs[] = {
            "ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "ida64.exe",
            "immunitydebugger.exe", "radare2.exe", "gdb.exe", "dbgview.exe"
        };
        
        return CheckProcessList(debuggerProcs, sizeof(debuggerProcs) / sizeof(debuggerProcs[0]));
    }
    
    static bool CheckNtQueryInformationProcess() {
        // Usar NtQueryInformationProcess diretamente
        HANDLE hProcess = GetCurrentProcess();
        DWORD debugFlags = 0;
        DWORD returned = 0;
        
        NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessDebugFlags, &debugFlags, sizeof(debugFlags), &returned);
        return status == STATUS_SUCCESS && debugFlags == 0;
    }
    
    static bool CheckHeapFlags() {
        // Verificar flags do heap
        HANDLE hHeap = GetProcessHeap();
        ULONG heapFlags = 0;
        
        if (HeapQueryInformation(hHeap, HeapCompatibilityInformation, &heapFlags, sizeof(heapFlags), NULL)) {
            return (heapFlags & HEAP_VALIDATE_ALL) != 0; // Debug heap
        }
        
        return false;
    }
    
    static bool CheckTLSCallbacks() {
        // Verificar TLS callbacks (usados por alguns debuggers)
        PVOID baseAddress = GetModuleHandle(NULL);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
        PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)baseAddress + dosHeader->e_lfanew);
        
        // Verificar diretório TLS
        IMAGE_DATA_DIRECTORY tlsDir = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        return tlsDir.VirtualAddress != 0;
    }
    
    // Utility functions
    static DWORD GetParentProcessId() {
        // Implementar obtenção do PID do processo pai
        return 0; // Placeholder
    }
    
    static bool GetProcessNameById(DWORD processId, char* processName, size_t bufferSize) {
        // Implementar obtenção do nome do processo por ID
        return false; // Placeholder
    }
    
    static bool CheckProcessList(const char* processes[], size_t count) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (size_t i = 0; i < count; i++) {
                    if (_stricmp(pe.szExeFile, processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    static NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass,
                                                   PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                   PULONG ReturnLength) {
        // Implementar chamada para NtQueryInformationProcess
        return STATUS_SUCCESS; // Placeholder
    }
    
    static PVOID GetFirstVectoredExceptionHandler() {
        // Implementar obtenção do primeiro VEH
        return NULL; // Placeholder
    }
};
```

### Advanced Anti-Debugging Techniques

```cpp
// Técnicas avançadas anti-debugging
class AdvancedAntiDebugger : public AntiDebugger {
private:
    std::vector<ADVANCED_DEBUG_CHECK> advancedChecks;
    ANTI_DEBUG_TECHNIQUES techniques;
    
public:
    AdvancedAntiDebugger() {
        InitializeAdvancedChecks();
        InitializeAntiDebugTechniques();
    }
    
    void InitializeAdvancedChecks() {
        // Verificações avançadas
        advancedChecks.push_back({CHECK_THREAD_HIDE, "Thread hiding", []() { return CheckThreadHiding(); }});
        advancedChecks.push_back({CHECK_MEMORY_BREAKPOINTS, "Memory breakpoints", []() { return CheckMemoryBreakpoints(); }});
        advancedChecks.push_back({CHECK_API_HOOKS, "API hooks", []() { return CheckAPIHooks(); }});
        advancedChecks.push_back({CHECK_INSTRUMENTATION, "Instrumentation", []() { return CheckInstrumentation(); }});
        advancedChecks.push_back({CHECK_SYMBOLS, "Debug symbols", []() { return CheckDebugSymbols(); }});
        advancedChecks.push_back({CHECK_SEH, "SEH chain", []() { return CheckSEHChain(); }});
        advancedChecks.push_back({CHECK_UNWIND, "Stack unwind", []() { return CheckStackUnwind(); }});
        advancedChecks.push_back({CHECK_PATCHGUARD, "PatchGuard", []() { return CheckPatchGuard(); }});
    }
    
    void InitializeAntiDebugTechniques() {
        techniques.useTimingAttacks = true;
        techniques.useExceptionAttacks = true;
        techniques.useMemoryAttacks = true;
        techniques.useThreadAttacks = true;
        techniques.useAPIAttacks = true;
    }
    
    bool PerformAdvancedDebugChecks() {
        // Executar verificações básicas primeiro
        if (AntiDebugger::PerformDebugChecks()) {
            return true;
        }
        
        // Executar verificações avançadas
        for (const ADVANCED_DEBUG_CHECK& check : advancedChecks) {
            if (check.function()) {
                report.debuggerDetected = true;
                report.advancedDetection = true;
                return true;
            }
        }
        
        return false;
    }
    
    // Implementações avançadas
    static bool CheckThreadHiding() {
        // Verificar se threads estão sendo escondidas do debugger
        DWORD threadCount = 0;
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, GetCurrentProcessId());
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            
            if (Thread32First(hSnapshot, &te)) {
                do {
                    if (te.th32OwnerProcessID == GetCurrentProcessId()) {
                        threadCount++;
                    }
                } while (Thread32Next(hSnapshot, &te));
            }
            
            CloseHandle(hSnapshot);
        }
        
        // Se thread count é suspeito
        return threadCount < 1; // Menos de 1 thread visível
    }
    
    static bool CheckMemoryBreakpoints() {
        // Verificar breakpoints de memória
        MEMORY_BASIC_INFORMATION mbi;
        
        // Verificar regiões críticas
        PVOID addresses[] = {
            GetModuleHandle(NULL), // Base do executável
            GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")
        };
        
        for (PVOID addr : addresses) {
            if (VirtualQuery(addr, &mbi, sizeof(mbi))) {
                if (mbi.Protect & PAGE_GUARD) {
                    return true; // Memory breakpoint detectado
                }
            }
        }
        
        return false;
    }
    
    static bool CheckAPIHooks() {
        // Verificar hooks em APIs críticas
        const char* criticalAPIs[] = {
            "kernel32.dll!IsDebuggerPresent",
            "kernel32.dll!CheckRemoteDebuggerPresent",
            "ntdll.dll!NtQueryInformationProcess"
        };
        
        for (const char* api : criticalAPIs) {
            if (IsAPIHooked(api)) {
                return true;
            }
        }
        
        return false;
    }
    
    static bool CheckInstrumentation() {
        // Verificar instrumentação (como Intel PT, etc.)
        // Implementar verificação de instrumentação
        
        return false; // Placeholder
    }
    
    static bool CheckDebugSymbols() {
        // Verificar se símbolos de debug estão carregados
        return false; // Placeholder
    }
    
    static bool CheckSEHChain() {
        // Verificar cadeia SEH modificada
        __try {
            RaiseException(0xC0000005, 0, 0, NULL); // Access violation
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Verificar se SEH foi manipulado
            return GetExceptionCode() != 0xC0000005;
        }
        
        return false;
    }
    
    static bool CheckStackUnwind() {
        // Verificar unwind de stack
        __try {
            // Causar stack overflow controlado
            volatile char buffer[1024 * 1024]; // 1MB stack allocation
            buffer[0] = 1;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Verificar se stack unwind foi interceptado
            return true;
        }
        
        return false;
    }
    
    static bool CheckPatchGuard() {
        // Verificar se PatchGuard está ativo (Windows)
        // PatchGuard impede modificações no kernel
        
        return false; // Placeholder
    }
    
    // Anti-debug techniques
    void ApplyAntiDebugTechniques() {
        if (techniques.useTimingAttacks) {
            ApplyTimingAttacks();
        }
        
        if (techniques.useExceptionAttacks) {
            ApplyExceptionAttacks();
        }
        
        if (techniques.useMemoryAttacks) {
            ApplyMemoryAttacks();
        }
        
        if (techniques.useThreadAttacks) {
            ApplyThreadAttacks();
        }
        
        if (techniques.useAPIAttacks) {
            ApplyAPIAttacks();
        }
    }
    
    void ApplyTimingAttacks() {
        // Ataques baseados em timing
        // Fazer código executar mais lentamente quando em debug
        
        for (int i = 0; i < 1000000; i++) {
            __asm {
                nop
                nop
                nop
                nop
                nop
            }
        }
    }
    
    void ApplyExceptionAttacks() {
        // Ataques baseados em exceptions
        __try {
            // Causar muitas exceptions
            for (int i = 0; i < 100; i++) {
                RaiseException(0x12345678 + i, 0, 0, NULL);
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Exceptions tratadas - pode ser debugger
        }
    }
    
    void ApplyMemoryAttacks() {
        // Ataques baseados em memória
        // Alocar/desalocar memória rapidamente
        
        for (int i = 0; i < 100; i++) {
            void* ptr = malloc(1024 * 1024); // 1MB
            if (ptr) {
                memset(ptr, 0xCC, 1024 * 1024); // Preencher com INT3
                free(ptr);
            }
        }
    }
    
    void ApplyThreadAttacks() {
        // Ataques baseados em threads
        // Criar/destruir threads rapidamente
        
        for (int i = 0; i < 10; i++) {
            HANDLE hThread = CreateThread(NULL, 0, DummyThreadProc, NULL, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, 100);
                CloseHandle(hThread);
            }
        }
    }
    
    void ApplyAPIAttacks() {
        // Ataques baseados em APIs
        // Chamar APIs suspeitas
        
        for (int i = 0; i < 100; i++) {
            IsDebuggerPresent();
            CheckRemoteDebuggerPresent(GetCurrentProcess(), NULL);
        }
    }
    
    // Utility functions
    static bool IsAPIHooked(const char* apiName) {
        // Verificar se API está hookada
        char moduleName[256], functionName[256];
        sscanf(apiName, "%[^!]!%s", moduleName, functionName);
        
        HMODULE hModule = GetModuleHandleA(moduleName);
        if (!hModule) return false;
        
        PVOID pFunction = GetProcAddress(hModule, functionName);
        if (!pFunction) return false;
        
        // Verificar prólogo da função
        __try {
            BYTE* bytes = (BYTE*)pFunction;
            return bytes[0] == 0xE9 || bytes[0] == 0xFF || bytes[0] == 0xCC; // JMP, CALL, INT3
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // Não conseguiu ler - possível hook
        }
    }
    
    static DWORD WINAPI DummyThreadProc(LPVOID lpParameter) {
        // Thread dummy para ataques
        Sleep(10);
        return 0;
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
    std::vector<DEBUG_SIGNATURE> knownSignatures;
    
public:
    void InitializeSignatures() {
        // Assinaturas de verificações anti-debugging conhecidas
        knownSignatures.push_back({
            "IsDebuggerPresent_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0, 0x74}, // CALL IsDebuggerPresent; TEST EAX,EAX; JZ
            "IsDebuggerPresent API check"
        });
        
        knownSignatures.push_back({
            "CheckRemoteDebugger_Check",
            {0x6A, 0x00, 0xFF, 0x74, 0x24, 0x04, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // PUSH 0; PUSH [ESP+4]; CALL CheckRemoteDebuggerPresent; TEST EAX,EAX
            "CheckRemoteDebuggerPresent API check"
        });
        
        knownSignatures.push_back({
            "Timing_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x2B, 0xC3, 0x3D, 0x90, 0x01, 0x00, 0x00}, // CALL GetTickCount; SUB EAX,EBX; CMP EAX,400
            "Timing anomaly check"
        });
        
        knownSignatures.push_back({
            "RDTSC_Check",
            {0x0F, 0x31, 0x48, 0x2B, 0xC1, 0x48, 0x81, 0xF8, 0x80, 0xC6, 0xA4, 0x7E, 0x00, 0x00, 0x00, 0x00}, // RDTSC; SUB RAX,RCX; CMP RAX,7EA4C680
            "RDTSC timing check"
        });
        
        knownSignatures.push_back({
            "Hardware_Breakpoint_Check",
            {0x6A, 0x10, 0x68, 0x00, 0x10, 0x00, 0x00, 0x6A, 0xFF, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // PUSH 10h; PUSH 1000h; PUSH -1; CALL GetThreadContext; TEST EAX,EAX
            "Hardware breakpoint check"
        });
        
        knownSignatures.push_back({
            "INT3_Check",
            {0xCD, 0x03, 0xEB, 0x00}, // INT 3; JMP
            "INT3 breakpoint test"
        });
        
        knownSignatures.push_back({
            "Debug_Port_Check",
            {0x6A, 0x07, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // PUSH 7; PUSH 0; PUSH 0; PUSH 0; CALL NtQueryInformationProcess; TEST EAX,EAX
            "Debug port check"
        });
        
        knownSignatures.push_back({
            "Heap_Flags_Check",
            {0x6A, 0x02, 0x8D, 0x44, 0x24, 0x08, 0x50, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // PUSH 2; LEA EAX,[ESP+8]; PUSH EAX; CALL HeapQueryInformation; TEST EAX,EAX
            "Heap flags check"
        });
    }
    
    void ScanForAntiDebugSignatures(PVOID baseAddress, SIZE_T size) {
        BYTE* code = (BYTE*)baseAddress;
        
        for (const DEBUG_SIGNATURE& sig : knownSignatures) {
            if (FindSignature(code, size, sig)) {
                ReportAntiDebugSignature(sig.description);
            }
        }
    }
    
    bool FindSignature(BYTE* code, SIZE_T size, const DEBUG_SIGNATURE& sig) {
        for (SIZE_T i = 0; i < size - sig.pattern.size(); i++) {
            if (memcmp(&code[i], sig.pattern.data(), sig.pattern.size()) == 0) {
                return true;
            }
        }
        return false;
    }
    
    void ReportAntiDebugSignature(const std::string& description) {
        std::cout << "Anti-debug signature detected: " << description << std::endl;
    }
};
```

#### 2. Behavioral Analysis
```cpp
// Análise comportamental
class AntiDebugBehavioralAnalyzer {
private:
    std::map<DWORD, PROCESS_DEBUG_BEHAVIOR> processBehaviors;
    
public:
    void MonitorProcessDebugBehavior(DWORD processId) {
        // Registrar comportamento normal
        RegisterNormalDebugBehavior(processId);
        
        // Monitorar desvios
        StartDebugBehaviorMonitoring(processId);
    }
    
    void RegisterNormalDebugBehavior(DWORD processId) {
        PROCESS_DEBUG_BEHAVIOR behavior;
        
        // APIs que um processo normal chama
        behavior.expectedAPIs = {
            "kernel32.dll!LoadLibraryA",
            "kernel32.dll!GetProcAddress",
            "user32.dll!MessageBoxA"
        };
        
        // Comportamento de timing normal
        behavior.expectedTiming.maxAPICallTime = 100; // ms
        
        processBehaviors[processId] = behavior;
    }
    
    void StartDebugBehaviorMonitoring(DWORD processId) {
        std::thread([this, processId]() {
            while (true) {
                CheckDebugBehavioralAnomalies(processId);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }).detach();
    }
    
    void CheckDebugBehavioralAnomalies(DWORD processId) {
        if (processBehaviors.find(processId) == processBehaviors.end()) return;
        
        PROCESS_DEBUG_BEHAVIOR& behavior = processBehaviors[processId];
        
        // Verificar APIs suspeitas de detecção de debugger
        if (HasSuspiciousDebugAPICalls(processId)) {
            ReportSuspiciousDebugAPIs(processId);
        }
        
        // Verificar timing anormal
        if (HasAbnormalDebugTiming(processId, behavior.expectedTiming)) {
            ReportAbnormalDebugTiming(processId);
        }
        
        // Verificar acesso suspeito ao sistema
        if (HasSuspiciousSystemAccess(processId)) {
            ReportSuspiciousSystemAccess(processId);
        }
        
        // Verificar comportamento evasivo
        if (HasEvasiveDebugBehavior(processId)) {
            ReportEvasiveDebugBehavior(processId);
        }
    }
    
    bool HasSuspiciousDebugAPICalls(DWORD processId) {
        // Verificar se processo está chamando muitas APIs de detecção de debugger
        // IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess, etc.
        
        return false; // Placeholder
    }
    
    bool HasAbnormalDebugTiming(DWORD processId, const DEBUG_TIMING_PROFILE& expected) {
        // Verificar se processo tem delays suspeitos ou execução muito lenta
        
        return false; // Placeholder
    }
    
    bool HasSuspiciousSystemAccess(DWORD processId) {
        // Verificar acesso suspeito a debug objects, ports, etc.
        
        return false; // Placeholder
    }
    
    bool HasEvasiveDebugBehavior(DWORD processId) {
        // Verificar comportamento evasivo (exceptions, memory corruption, etc.)
        
        return false; // Placeholder
    }
    
    void ReportSuspiciousDebugAPIs(DWORD processId) {
        std::cout << "Suspicious debugger detection APIs detected in process " << processId << std::endl;
    }
    
    void ReportAbnormalDebugTiming(DWORD processId) {
        std::cout << "Abnormal debugger timing detected in process " << processId << std::endl;
    }
    
    void ReportSuspiciousSystemAccess(DWORD processId) {
        std::cout << "Suspicious system access in process " << processId << std::endl;
    }
    
    void ReportEvasiveDebugBehavior(DWORD processId) {
        std::cout << "Evasive debugger behavior detected in process " << processId << std::endl;
    }
};
```

#### 3. Anti-Anti-Debugging Techniques
```cpp
// Técnicas anti-anti-debugging
class AntiAntiDebugger {
public:
    void BypassAntiDebugChecks() {
        // Bypass verificações comuns
        BypassIsDebuggerPresent();
        BypassCheckRemoteDebuggerPresent();
        BypassTimingChecks();
        BypassHardwareBreakpointChecks();
        BypassNtQueryInformationProcess();
        BypassHeapFlagsChecks();
    }
    
    void BypassIsDebuggerPresent() {
        // Hook IsDebuggerPresent
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pIsDebuggerPresent = GetProcAddress(hKernel32, "IsDebuggerPresent");
        
        MH_CreateHook(pIsDebuggerPresent, &HkIsDebuggerPresent, &oIsDebuggerPresent);
        MH_EnableHook(pIsDebuggerPresent);
    }
    
    static BOOL WINAPI HkIsDebuggerPresent() {
        return FALSE; // Sempre retornar falso
    }
    
    void BypassCheckRemoteDebuggerPresent() {
        // Hook CheckRemoteDebuggerPresent
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pCheckRemoteDebuggerPresent = GetProcAddress(hKernel32, "CheckRemoteDebuggerPresent");
        
        MH_CreateHook(pCheckRemoteDebuggerPresent, &HkCheckRemoteDebuggerPresent, &oCheckRemoteDebuggerPresent);
        MH_EnableHook(pCheckRemoteDebuggerPresent);
    }
    
    static BOOL WINAPI HkCheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent) {
        *pbDebuggerPresent = FALSE;
        return TRUE;
    }
    
    void BypassTimingChecks() {
        // Hook GetTickCount e RDTSC
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pGetTickCount = GetProcAddress(hKernel32, "GetTickCount");
        
        MH_CreateHook(pGetTickCount, &HkGetTickCount, &oGetTickCount);
        MH_EnableHook(pGetTickCount);
        
        // Para RDTSC, usar instrução de interceptação
        InstallRDTSCInterceptor();
    }
    
    static DWORD WINAPI HkGetTickCount() {
        static DWORD fakeTicks = 0;
        fakeTicks += 100; // Incremento normal
        return fakeTicks;
    }
    
    void InstallRDTSCInterceptor() {
        // Instalar interceptor para RDTSC
        // Usar VEH ou similar
    }
    
    void BypassHardwareBreakpointChecks() {
        // Hook GetThreadContext
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pGetThreadContext = GetProcAddress(hKernel32, "GetThreadContext");
        
        MH_CreateHook(pGetThreadContext, &HkGetThreadContext, &oGetThreadContext);
        MH_EnableHook(pGetThreadContext);
    }
    
    static BOOL WINAPI HkGetThreadContext(HANDLE hThread, LPCONTEXT lpContext) {
        BOOL result = oGetThreadContext(hThread, lpContext);
        
        if (result && (lpContext->ContextFlags & CONTEXT_DEBUG_REGISTERS)) {
            // Limpar debug registers
            lpContext->Dr0 = lpContext->Dr1 = lpContext->Dr2 = lpContext->Dr3 = 0;
            lpContext->Dr6 = lpContext->Dr7 = 0;
        }
        
        return result;
    }
    
    void BypassNtQueryInformationProcess() {
        // Hook NtQueryInformationProcess
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        PVOID pNtQueryInformationProcess = GetProcAddress(hNtdll, "NtQueryInformationProcess");
        
        MH_CreateHook(pNtQueryInformationProcess, &HkNtQueryInformationProcess, &oNtQueryInformationProcess);
        MH_EnableHook(pNtQueryInformationProcess);
    }
    
    static NTSTATUS NTAPI HkNtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass,
                                                     PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                     PULONG ReturnLength) {
        if (ProcessInformationClass == ProcessDebugPort ||
            ProcessInformationClass == ProcessDebugObjectHandle ||
            ProcessInformationClass == ProcessDebugFlags) {
            // Retornar valores indicando não debug
            if (ProcessInformationClass == ProcessDebugPort) {
                *(PDWORD)ProcessInformation = 0;
            } else if (ProcessInformationClass == ProcessDebugFlags) {
                *(PDWORD)ProcessInformation = 1; // No debug flags
            }
            if (ReturnLength) *ReturnLength = ProcessInformationLength;
            return STATUS_SUCCESS;
        }
        
        return oNtQueryInformationProcess(ProcessHandle, ProcessInformationClass, ProcessInformation,
                                        ProcessInformationLength, ReturnLength);
    }
    
    void BypassHeapFlagsChecks() {
        // Hook HeapQueryInformation
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pHeapQueryInformation = GetProcAddress(hKernel32, "HeapQueryInformation");
        
        MH_CreateHook(pHeapQueryInformation, &HkHeapQueryInformation, &oHeapQueryInformation);
        MH_EnableHook(pHeapQueryInformation);
    }
    
    static BOOL WINAPI HkHeapQueryInformation(HANDLE HeapHandle, HEAP_INFORMATION_CLASS HeapInformationClass,
                                            PVOID HeapInformation, SIZE_T HeapInformationLength,
                                            PSIZE_T ReturnLength) {
        BOOL result = oHeapQueryInformation(HeapHandle, HeapInformationClass, HeapInformation,
                                          HeapInformationLength, ReturnLength);
        
        if (result && HeapInformationClass == HeapCompatibilityInformation) {
            // Limpar flags de debug
            *(PULONG)HeapInformation &= ~HEAP_VALIDATE_ALL;
        }
        
        return result;
    }
    
    // Original function pointers
    static decltype(&IsDebuggerPresent) oIsDebuggerPresent;
    static decltype(&CheckRemoteDebuggerPresent) oCheckRemoteDebuggerPresent;
    static decltype(&GetTickCount) oGetTickCount;
    static decltype(&GetThreadContext) oGetThreadContext;
    static decltype(&NtQueryInformationProcess) oNtQueryInformationProcess;
    static decltype(&HeapQueryInformation) oHeapQueryInformation;
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Signature scanning | < 30s | 85% |
| VAC Live | Behavioral analysis | Imediato | 80% |
| BattlEye | Anti-bypass hooks | < 1 min | 90% |
| Faceit AC | Timing analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Polymorphic Anti-Debugging
```cpp
// ✅ Anti-debugging polimórfico
class PolymorphicAntiDebugger {
private:
    std::vector<POLYMORPHIC_DEBUG_CHECK> polymorphicChecks;
    
public:
    PolymorphicAntiDebugger() {
        GeneratePolymorphicChecks();
    }
    
    void GeneratePolymorphicChecks() {
        // Gerar verificações diferentes a cada execução
        polymorphicChecks.clear();
        
        // Adicionar variações de verificações
        AddIsDebuggerPresentVariations();
        AddTimingVariations();
        AddHardwareBreakpointVariations();
        AddProcessVariations();
    }
    
    void AddIsDebuggerPresentVariations() {
        // Variações da verificação IsDebuggerPresent
        polymorphicChecks.push_back({
            "IDP_Var1",
            []() { return IsDebuggerPresent(); }
        });
        
        polymorphicChecks.push_back({
            "IDP_Var2", 
            []() {
                BOOL debugged = FALSE;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
                return debugged;
            }
        });
        
        polymorphicChecks.push_back({
            "IDP_Var3",
            []() {
                HANDLE hProcess = GetCurrentProcess();
                DWORD debugPort = 0;
                DWORD returned = 0;
                NtQueryInformationProcess(hProcess, ProcessDebugPort, &debugPort, sizeof(debugPort), &returned);
                return debugPort != 0;
            }
        });
    }
    
    void AddTimingVariations() {
        // Variações de verificação de timing
        polymorphicChecks.push_back({
            "Timing_Var1",
            []() {
                DWORD start = GetTickCount();
                Sleep(100);
                DWORD end = GetTickCount();
                return (end - start) > 150;
            }
        });
        
        polymorphicChecks.push_back({
            "Timing_Var2",
            []() {
                uint64_t start = __rdtsc();
                for (volatile int i = 0; i < 10000; i++);
                uint64_t end = __rdtsc();
                return (end - start) > 10000000;
            }
        });
        
        polymorphicChecks.push_back({
            "Timing_Var3",
            []() {
                LARGE_INTEGER start, end, freq;
                QueryPerformanceFrequency(&freq);
                QueryPerformanceCounter(&start);
                Sleep(100);
                QueryPerformanceCounter(&end);
                double timeMs = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart * 1000;
                return timeMs > 200;
            }
        });
    }
    
    void AddHardwareBreakpointVariations() {
        // Variações de verificação de hardware breakpoints
        polymorphicChecks.push_back({
            "HWBP_Var1",
            []() {
                CONTEXT ctx = {0};
                ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                return GetThreadContext(GetCurrentThread(), &ctx) && (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
            }
        });
        
        polymorphicChecks.push_back({
            "HWBP_Var2",
            []() {
                __try {
                    uint64_t dr0 = 0;
                    __asm {
                        mov rax, dr0
                        mov dr0, rax
                    }
                    return false;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    return true;
                }
            }
        });
    }
    
    void AddProcessVariations() {
        // Variações de verificação de processos
        const char* debuggerLists[3][5] = {
            {"ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe", "gdb.exe"},
            {"immunitydebugger.exe", "radare2.exe", "dbgview.exe", "processhacker.exe", "cheatengine.exe"},
            {"x32dbg.exe", "idau.exe", "hopper.exe", "binaryninja.exe", "rizin.exe"}
        };
        
        for (int i = 0; i < 3; i++) {
            polymorphicChecks.push_back({
                std::string("Proc_Var") + std::to_string(i + 1),
                [debuggerLists, i]() {
                    return CheckProcessList(debuggerLists[i], 5);
                }
            });
        }
    }
    
    bool PerformPolymorphicChecks() {
        // Selecionar subconjunto aleatório de verificações
        std::vector<POLYMORPHIC_DEBUG_CHECK> selectedChecks;
        std::sample(polymorphicChecks.begin(), polymorphicChecks.end(), 
                   std::back_inserter(selectedChecks), 
                   3 + rand() % 4, std::mt19937{std::random_device{}()}); // 3-6 checks
        
        // Executar verificações selecionadas
        for (const POLYMORPHIC_DEBUG_CHECK& check : selectedChecks) {
            if (check.function()) {
                return true; // Debugger detectado
            }
            
            // Delay aleatório entre verificações
            Sleep(20 + rand() % 80);
        }
        
        return false;
    }
    
    static bool CheckProcessList(const char* processes[], size_t count) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (size_t i = 0; i < count; i++) {
                    if (_stricmp(pe.szExeFile, processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    static NTSTATUS NTAPI NtQueryInformationProcess(HANDLE ProcessHandle, DWORD ProcessInformationClass,
                                                   PVOID ProcessInformation, ULONG ProcessInformationLength,
                                                   PULONG ReturnLength) {
        // Placeholder
        return STATUS_SUCCESS;
    }
};
```

### 2. Context-Aware Anti-Debugging
```cpp
// ✅ Anti-debugging consciente do contexto
class ContextAwareAntiDebugger {
private:
    SYSTEM_CONTEXT context;
    DETECTION_STRATEGY strategy;
    
public:
    void PerformContextAwareAntiDebugging() {
        // Coletar contexto do sistema
        GatherSystemContext();
        
        // Avaliar contexto
        EvaluateContext();
        
        // Escolher estratégia de detecção
        ChooseDetectionStrategy();
        
        // Executar detecção
        ExecuteDetection();
    }
    
    void GatherSystemContext() {
        context.isElevated = IsProcessElevated();
        context.hasDebuggerAttached = CheckDebuggerAttached();
        context.isBeingAnalyzed = CheckAnalysisIndicators();
        context.systemLoad = GetSystemLoad();
        context.userActivity = GetUserActivityLevel();
    }
    
    void EvaluateContext() {
        // Avaliar se contexto indica debugging
        context.confidenceLevel = CalculateConfidenceLevel();
        context.isLikelyDebugged = context.confidenceLevel > 0.7;
        context.isSuspiciousContext = context.confidenceLevel > 0.4;
    }
    
    void ChooseDetectionStrategy() {
        if (context.isLikelyDebugged) {
            // Contexto hostil - detecção stealth
            strategy.useStealthChecks = true;
            strategy.exitOnDetection = true;
            strategy.checkFrequency = HIGH;
        } else if (context.isSuspiciousContext) {
            // Contexto suspeito - detecção moderada
            strategy.useStandardChecks = true;
            strategy.modifyBehavior = true;
            strategy.checkFrequency = MEDIUM;
        } else {
            // Contexto normal - detecção leve
            strategy.useLightChecks = true;
            strategy.checkFrequency = LOW;
        }
    }
    
    void ExecuteDetection() {
        if (strategy.useStealthChecks) {
            ExecuteStealthDetection();
        } else if (strategy.useStandardChecks) {
            ExecuteStandardDetection();
        } else {
            ExecuteLightDetection();
        }
    }
    
    void ExecuteStealthDetection() {
        // Detecção stealth - verificações espaçadas e sutis
        std::thread([this]() {
            while (true) {
                if (PerformStealthCheck()) {
                    HandleStealthDetection();
                    break;
                }
                Sleep(CalculateStealthDelay());
            }
        }).detach();
    }
    
    void ExecuteStandardDetection() {
        // Detecção padrão
        AntiDebugger debugger;
        if (debugger.PerformDebugChecks()) {
            HandleDetection();
        }
    }
    
    void ExecuteLightDetection() {
        // Detecção leve - apenas verificações básicas
        if (IsDebuggerPresent() || CheckRemoteDebuggerPresent()) {
            HandleLightDetection();
        }
    }
    
    bool PerformStealthCheck() {
        // Verificação stealth
        return CheckSubtleDebugIndicator();
    }
    
    void HandleDetection() {
        if (strategy.exitOnDetection) {
            ExitProcess(0);
        } else if (strategy.modifyBehavior) {
            ModifyBehaviorForDebug();
        }
    }
    
    void HandleStealthDetection() {
        // Detecção stealth - comportamento sutil
        LogStealthDetection();
        ModifyBehaviorSlightly();
    }
    
    void HandleLightDetection() {
        // Detecção leve - log apenas
        LogLightDetection();
    }
    
    double CalculateConfidenceLevel() {
        double confidence = 0.0;
        
        if (context.hasDebuggerAttached) confidence += 0.8;
        if (context.isBeingAnalyzed) confidence += 0.5;
        if (context.systemLoad < 0.3) confidence += 0.2; // Sistema ocioso
        if (!context.userActivity) confidence += 0.3; // Sem atividade do usuário
        
        return min(confidence, 1.0);
    }
    
    bool CheckSubtleDebugIndicator() {
        // Verificação sutil
        return CheckUnusualTiming() || CheckUnusualMemory() || CheckUnusualThreads();
    }
    
    DWORD CalculateStealthDelay() {
        // Delay baseado na estratégia
        switch (strategy.checkFrequency) {
            case LOW: return 30000; // 30 segundos
            case MEDIUM: return 10000; // 10 segundos
            case HIGH: return 2000; // 2 segundos
            default: return 10000;
        }
    }
    
    // Utility functions
    static bool IsProcessElevated() {
        // Verificar se processo está elevado
        return false; // Placeholder
    }
    
    static bool CheckDebuggerAttached() {
        return IsDebuggerPresent();
    }
    
    static bool CheckAnalysisIndicators() {
        // Verificar indicadores de análise
        return CheckDebuggerProcesses() || CheckAnalysisFiles();
    }
    
    static double GetSystemLoad() {
        // Obter carga do sistema
        return 0.5; // Placeholder
    }
    
    static bool GetUserActivityLevel() {
        // Verificar atividade do usuário
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD idleTime = GetTickCount() - lii.dwTime;
        return idleTime < 30000; // Atividade nos últimos 30 segundos
    }
    
    static bool CheckDebuggerProcesses() {
        const char* debuggers[] = {"ollydbg.exe", "x64dbg.exe", "windbg.exe", "ida.exe"};
        return CheckProcessList(debuggers, 4);
    }
    
    static bool CheckAnalysisFiles() {
        return PathFileExistsA("C:\\analysis\\") || PathFileExistsA("C:\\debug\\");
    }
    
    static bool CheckUnusualTiming() {
        // Verificar timing incomum
        return false; // Placeholder
    }
    
    static bool CheckUnusualMemory() {
        // Verificar uso de memória incomum
        return false; // Placeholder
    }
    
    static bool CheckUnusualThreads() {
        // Verificar threads incomuns
        return false; // Placeholder
    }
    
    static bool CheckProcessList(const char* processes[], size_t count) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (size_t i = 0; i < count; i++) {
                    if (_stricmp(pe.szExeFile, processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    void LogStealthDetection() { /* Log discreto */ }
    void LogLightDetection() { /* Log leve */ }
    void ModifyBehaviorForDebug() { /* Modificação para debug */ }
    void ModifyBehaviorSlightly() { /* Modificação sutil */ }
};
```

### 3. Machine Learning-Based Anti-Debugging
```cpp
// ✅ Anti-debugging baseado em machine learning
class MLBasedAntiDebugger {
private:
    ML_MODEL debugModel;
    FEATURE_EXTRACTOR extractor;
    
public:
    void PerformMLBasedAntiDebugging() {
        // Carregar modelo treinado
        LoadDebugModel();
        
        // Extrair features
        ExtractDebugFeatures();
        
        // Classificar
        ClassifyDebugging();
    }
    
    void LoadDebugModel() {
        // Carregar modelo de ML treinado para detectar debugging
        // Modelo treinado com dados de comportamento normal vs debugged
        
        debugModel.LoadModel("debug_detection.model");
    }
    
    void ExtractDebugFeatures() {
        // Extrair features comportamentais
        extractor.ExtractTimingFeatures();
        extractor.ExtractAPIFeatures();
        extractor.ExtractMemoryFeatures();
        extractor.ExtractThreadFeatures();
        extractor.ExtractExceptionFeatures();
    }
    
    void ClassifyDebugging() {
        // Usar modelo para classificar
        FEATURE_VECTOR features = extractor.GetFeatures();
        float confidence = debugModel.Predict(features);
        
        if (confidence > 0.75) {
            OnDebuggerDetected(confidence);
        }
    }
    
    void OnDebuggerDetected(float confidence) {
        // Debugger detectado por ML
        LogDetection(confidence);
        HandleDetection();
    }
    
    // Feature extraction
    void ExtractTimingFeatures() {
        // Features de timing
        extractor.AddFeature("avg_sleep_time", CalculateAverageSleepTime());
        extractor.AddFeature("timing_variability", CalculateTimingVariability());
        extractor.AddFeature("api_call_timing", CalculateAPICallTiming());
    }
    
    void ExtractAPIFeatures() {
        // Features de API
        extractor.AddFeature("debugger_api_calls", CountDebuggerAPICalls());
        extractor.AddFeature("system_api_calls", CountSystemAPICalls());
        extractor.AddFeature("unusual_api_patterns", AnalyzeUnusualAPIPatterns());
    }
    
    void ExtractMemoryFeatures() {
        // Features de memória
        extractor.AddFeature("memory_access_patterns", AnalyzeMemoryAccessPatterns());
        extractor.AddFeature("heap_allocations", CountHeapAllocations());
        extractor.AddFeature("memory_protection_changes", CountMemoryProtectionChanges());
    }
    
    void ExtractThreadFeatures() {
        // Features de threads
        extractor.AddFeature("thread_creation_rate", CalculateThreadCreationRate());
        extractor.AddFeature("thread_suspension_patterns", AnalyzeThreadSuspensionPatterns());
        extractor.AddFeature("cross_thread_activity", AnalyzeCrossThreadActivity());
    }
    
    void ExtractExceptionFeatures() {
        // Features de exceptions
        extractor.AddFeature("exception_frequency", CalculateExceptionFrequency());
        extractor.AddFeature("exception_types", AnalyzeExceptionTypes());
        extractor.AddFeature("seh_manipulation", DetectSEHManipulation());
    }
    
    // Utility functions
    static double CalculateAverageSleepTime() {
        // Calcular tempo médio de sleep
        return 0.0; // Placeholder
    }
    
    static double CalculateTimingVariability() {
        // Calcular variabilidade de timing
        return 0.0; // Placeholder
    }
    
    static double CalculateAPICallTiming() {
        // Calcular timing de chamadas de API
        return 0.0; // Placeholder
    }
    
    static int CountDebuggerAPICalls() {
        // Contar chamadas de API relacionadas a debugger
        return 0; // Placeholder
    }
    
    static int CountSystemAPICalls() {
        // Contar chamadas de API do sistema
        return 0; // Placeholder
    }
    
    static double AnalyzeUnusualAPIPatterns() {
        // Analisar padrões incomuns de API
        return 0.0; // Placeholder
    }
    
    static double AnalyzeMemoryAccessPatterns() {
        // Analisar padrões de acesso à memória
        return 0.0; // Placeholder
    }
    
    static int CountHeapAllocations() {
        // Contar alocações de heap
        return 0; // Placeholder
    }
    
    static int CountMemoryProtectionChanges() {
        // Contar mudanças de proteção de memória
        return 0; // Placeholder
    }
    
    static double CalculateThreadCreationRate() {
        // Calcular taxa de criação de threads
        return 0.0; // Placeholder
    }
    
    static double AnalyzeThreadSuspensionPatterns() {
        // Analisar padrões de suspensão de threads
        return 0.0; // Placeholder
    }
    
    static double AnalyzeCrossThreadActivity() {
        // Analisar atividade entre threads
        return 0.0; // Placeholder
    }
    
    static double CalculateExceptionFrequency() {
        // Calcular frequência de exceptions
        return 0.0; // Placeholder
    }
    
    static double AnalyzeExceptionTypes() {
        // Analisar tipos de exception
        return 0.0; // Placeholder
    }
    
    static double DetectSEHManipulation() {
        // Detectar manipulação de SEH
        return 0.0; // Placeholder
    }
    
    void LogDetection(float confidence) {
        std::cout << "ML-based debugger detection: confidence = " << confidence << std::endl;
    }
    
    void HandleDetection() {
        // Lidar com detecção
        ExitProcess(0);
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
| 2025-2026 | ⚠️ Alto risco | Advanced evasion |

---

## 🎯 Lições Aprendidas

1. **Debuggers São Detectáveis**: APIs e comportamentos revelam debugging.

2. **Comportamento é Rastreado**: Ações evasivas são monitoradas.

3. **Timing é Analisado**: Anomalias de tempo são detectadas.

4. **ML é Melhor**: Detecção baseada em machine learning é mais robusta.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#47]]
- [[Polymorphic_Anti_Debugging]]
- [[Context_Aware_Anti_Debugging]]
- [[ML_Based_Anti_Debugging]]

---

*Anti-debugging techniques tem risco moderado. Considere polymorphic approaches para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
