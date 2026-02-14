# 📖 Técnica 013: DLL Injection via APC

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 013: DLL Injection via APC]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Threading & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**APC (Asynchronous Procedure Call) Injection** usa o mecanismo de APCs do Windows para injetar DLLs em threads de processos alvo. É mais stealth que CreateRemoteThread mas ainda detectável por análise de padrões.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO COM RISCO MODERADO
BOOL InjectDLLViaAPC(HANDLE hProcess, const char* dllPath) {
    // 1. Alocar memória para path da DLL
    SIZE_T pathSize = strlen(dllPath) + 1;
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, pathSize, 
                                      MEM_COMMIT, PAGE_READWRITE);
    
    if (!remotePath) return FALSE;
    
    // 2. Escrever path
    if (!WriteProcessMemory(hProcess, remotePath, dllPath, pathSize, NULL)) {
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        return FALSE;
    }
    
    // 3. Obter endereço de LoadLibraryA
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
    
    // 4. Enumerar threads do processo
    DWORD threadIds[1024];
    DWORD threadCount = EnumerateProcessThreads(hProcess, threadIds, 1024);
    
    // 5. Queue APC para cada thread
    for (DWORD i = 0; i < threadCount; i++) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadIds[i]);
        
        if (hThread) {
            // Queue APC
            if (QueueUserAPC((PAPCFUNC)loadLibraryAddr, hThread, (ULONG_PTR)remotePath)) {
                // Sucesso - APC queued
                break; // Injetar apenas na primeira thread
            }
            
            CloseHandle(hThread);
        }
    }
    
    // 6. Aguardar injeção (thread deve estar alertável)
    Sleep(100);
    
    // 7. Limpar
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    
    return TRUE;
}

DWORD EnumerateProcessThreads(HANDLE hProcess, DWORD* threadIds, DWORD maxCount) {
    // Usar CreateToolhelp32Snapshot para enumerar threads
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD count = 0;
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == GetProcessId(hProcess) && count < maxCount) {
                    threadIds[count++] = te.th32ThreadID;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
    
    return count;
}
```

### Por que é Detectado

> [!WARNING]
> **APCs injetados são detectáveis por análise de thread context e call stacks**

#### 1. APC Queue Monitoring
```cpp
// Monitorar APCs queued
void MonitorAPCQueues() {
    // Enumerar threads do sistema
    EnumThreads();
    
    for (auto& thread : threads) {
        if (IsGameThread(thread.id)) {
            AnalyzeThreadAPCs(thread.handle);
        }
    }
}

void AnalyzeThreadAPCs(HANDLE hThread) {
    // Usar undocumented APIs para inspecionar APC queue
    // ou hook NtQueueApcThread
    
    NTSTATUS status;
    PAPC_ENTRY apcEntry;
    
    // Enumerar APCs na queue
    status = EnumerateAPCs(hThread, &apcEntry);
    
    while (NT_SUCCESS(status)) {
        // Verificar se APC é suspeito
        if (IsSuspiciousAPC(apcEntry)) {
            LogSuspiciousAPC(hThread, apcEntry);
        }
        
        apcEntry = apcEntry->Next;
    }
}

bool IsSuspiciousAPC(PAPC_ENTRY apcEntry) {
    // APCs que chamam LoadLibrary são suspeitos
    if (apcEntry->KernelRoutine == (PKKERNEL_ROUTINE)GetProcAddress(
        GetModuleHandleA("kernel32.dll"), "LoadLibraryA")) {
        return true;
    }
    
    // APCs com parâmetros suspeitos
    if (IsSuspiciousAPCParameter(apcEntry->NormalContext)) {
        return true;
    }
    
    return false;
}
```

#### 2. Thread Context Analysis
```cpp
// Analisar contexto de threads após APC
void AnalyzeThreadContext(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    
    if (GetThreadContext(hThread, &context)) {
        // Verificar se RIP aponta para LoadLibrary
        if (IsLoadLibraryAddress(context.Rip)) {
            LogAPCInjection(hThread);
        }
        
        // Verificar stack
        AnalyzeThreadStack(hThread);
    }
}

void AnalyzeThreadStack(HANDLE hThread) {
    STACKFRAME64 stackFrame = {0};
    // Inicializar stack frame...
    
    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(),
                      hThread, &stackFrame, &context, NULL,
                      SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        
        // Verificar se stack contém APC dispatcher
        if (IsAPCDispatcherFrame(stackFrame)) {
            LogAPCExecution(hThread, stackFrame.AddrPC.Offset);
        }
    }
}
```

#### 3. Memory Allocation Patterns
```cpp
// Detectar padrões de alocação para injeção
class AllocationPatternDetector {
private:
    std::vector<MEMORY_ALLOCATION> recentAllocations;
    
public:
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MEMORY_ALLOCATION alloc = {hProcess, address, size, GetTickCount()};
        recentAllocations.push_back(alloc);
        
        AnalyzeAllocationPattern();
    }
    
    void AnalyzeAllocationPattern() {
        // Padrão típico: alloc string + APC injection
        if (HasInjectionPattern()) {
            ReportAPCInjection();
        }
    }
    
    bool HasInjectionPattern() {
        // Verificar alocações recentes
        DWORD currentTime = GetTickCount();
        
        for (auto& alloc : recentAllocations) {
            if ((currentTime - alloc.timestamp) < 5000) { // Últimos 5s
                // Verificar se alocação contém path de DLL
                if (IsDLLPathAllocation(alloc)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool IsDLLPathAllocation(const MEMORY_ALLOCATION& alloc) {
        // Ler conteúdo da alocação
        char buffer[1024];
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(alloc.hProcess, alloc.address, buffer, 
                             min(alloc.size, sizeof(buffer)), &bytesRead)) {
            // Verificar se é path de DLL
            if (IsValidDLLPath(buffer)) {
                return true;
            }
        }
        
        return false;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | APC monitoring | < 30s | 85% |
| VAC Live | Context analysis | Imediato | 90% |
| BattlEye | Pattern detection | < 1 min | 80% |
| Faceit AC | Stack analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Kernel APC Injection
```cpp
// ✅ APC injection via kernel
NTSTATUS InjectViaKernelAPC(PEPROCESS targetProcess, PVOID shellcode, SIZE_T size) {
    // 1. Alocar memória no processo alvo via kernel
    PVOID remoteBuffer = AllocateKernelMemory(targetProcess, size);
    memcpy(remoteBuffer, shellcode, size);
    
    // 2. Encontrar thread alertável no processo
    PETHREAD targetThread = FindAlertableThread(targetProcess);
    
    // 3. Queue kernel APC
    KeInitializeApc(&apc, (PKTHREAD)targetThread, OriginalApcEnvironment,
                   KernelRoutine, NULL, (PKNORMAL_ROUTINE)remoteBuffer, UserMode, NULL);
    
    KeInsertQueueApc(&apc, NULL, NULL, 0);
    
    return STATUS_SUCCESS;
}

PETHREAD FindAlertableThread(PEPROCESS process) {
    // Enumerar threads do processo
    PLIST_ENTRY threadList = (PLIST_ENTRY)((PUCHAR)process + ThreadListOffset);
    
    for (PLIST_ENTRY entry = threadList->Flink; entry != threadList; entry = entry->Flink) {
        PETHREAD thread = CONTAINING_RECORD(entry, ETHREAD, ThreadListEntry);
        
        // Verificar se thread está alertável
        if (IsThreadAlertable(thread)) {
            return thread;
        }
    }
    
    return NULL;
}
```

### 2. Thread Hijacking
```cpp
// ✅ Hijack existing thread
NTSTATUS HijackThread(HANDLE threadHandle, PVOID shellcode, SIZE_T size) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    
    // 1. Suspender thread
    SuspendThread(threadHandle);
    
    // 2. Obter contexto atual
    GetThreadContext(threadHandle, &context);
    
    // 3. Salvar contexto original
    CONTEXT originalContext = context;
    
    // 4. Modificar RIP para apontar para shellcode
    context.Rip = (DWORD64)shellcode;
    
    // 5. Executar shellcode
    SetThreadContext(threadHandle, &context);
    ResumeThread(threadHandle);
    
    // 6. Aguardar execução
    Sleep(100);
    
    // 7. Restaurar contexto original
    SetThreadContext(threadHandle, &context);
    ResumeThread(threadHandle);
    
    return STATUS_SUCCESS;
}
```

### 3. Exception-Based Injection
```cpp
// ✅ Injeção via exception handling
class ExceptionInjector {
public:
    void InjectViaException(HANDLE hProcess, PVOID shellcode, SIZE_T size) {
        // 1. Instalar exception handler
        InstallExceptionHandler(hProcess);
        
        // 2. Causar exception controlada
        TriggerException(hProcess);
        
        // 3. Exception handler executa shellcode
        // Handler substitui por shellcode
    }
    
private:
    void InstallExceptionHandler(HANDLE hProcess) {
        // Modificar VEH (Vectored Exception Handler)
        AddVectoredExceptionHandler(hProcess, ExceptionHandler);
    }
    
    LONG ExceptionHandler(PEXCEPTION_POINTERS exceptionInfo) {
        // Verificar tipo de exception
        if (exceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT) {
            // Executar shellcode ao invés de continuar
            ExecuteShellcode(exceptionInfo->ContextRecord);
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    void TriggerException(HANDLE hProcess) {
        // Injetar breakpoint instruction
        BYTE int3 = 0xCC;
        WriteProcessMemory(hProcess, targetAddress, &int3, 1, NULL);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC APC Monitor
```cpp
// VAC APC injection detection
class VAC_APCMonitor {
private:
    std::vector<APC_INFO> monitoredAPCs;
    
public:
    void Initialize() {
        // Hook NtQueueApcThread
        InstallHook("ntdll.dll", "NtQueueApcThread", HookedNtQueueApcThread);
        
        // Monitorar APC queues
        StartAPCScanning();
    }
    
    NTSTATUS HookedNtQueueApcThread(
        HANDLE ThreadHandle,
        PVOID ApcRoutine,
        PVOID ApcArgument1,
        PVOID ApcArgument2,
        PVOID ApcArgument3
    ) {
        // Verificar se APC é suspeito
        if (IsGameThread(ThreadHandle) && IsSuspiciousAPC(ApcRoutine, ApcArgument1)) {
            LogSuspiciousAPC(ThreadHandle, ApcRoutine);
            
            // Possivelmente bloquear
            return STATUS_ACCESS_DENIED;
        }
        
        return OriginalNtQueueApcThread(ThreadHandle, ApcRoutine, ApcArgument1, 
                                       ApcArgument2, ApcArgument3);
    }
    
    bool IsSuspiciousAPC(PVOID apcRoutine, PVOID apcArgument) {
        // APCs que chamam LoadLibrary
        if (apcRoutine == GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA")) {
            return true;
        }
        
        // Verificar se argumento é path suspeito
        if (IsSuspiciousPath((const char*)apcArgument)) {
            return true;
        }
        
        return false;
    }
};
```

### BattlEye Thread Analyzer
```cpp
// BE thread and APC analysis
void BE_AnalyzeThreads() {
    // Enumerate all threads
    EnumSystemThreads();
    
    for (auto& thread : threads) {
        if (IsGameProcess(thread.processId)) {
            // Check thread context
            AnalyzeThreadContext(thread.handle);
            
            // Check APC queue
            AnalyzeAPCQueue(thread.handle);
            
            // Check stack trace
            AnalyzeStackTrace(thread.handle);
        }
    }
}

void AnalyzeAPCQueue(HANDLE hThread) {
    // Use undocumented kernel functions to inspect APC queue
    // or monitor APC insertion via hooks
}

void AnalyzeStackTrace(HANDLE hThread) {
    // Walk thread stack
    // Look for APC dispatcher frames
    // Verify call sequence legitimacy
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ⚠️ Risco | APC monitoring |
| 2020-2024 | ⚠️ Risco | Pattern analysis |
| 2025-2026 | ⚠️ Moderado | Advanced analysis |

---

## 🎯 Lições Aprendadas

1. **APCs São Monitorados**: Queuing de APCs é rastreado.

2. **Contextos São Analisados**: Thread contexts revelam injeções.

3. **Stacks São Examinados**: Call stacks mostram execução de APCs.

4. **Kernel APCs São Mais Seguros**: Operar em ring 0 evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#13]]
- [[Kernel_APC_Injection]]
- [[Thread_Hijacking]]
- [[Exception_Based_Injection]]

---

*APC injection ainda funciona mas é arriscado. Considere kernel APCs para stealth superior.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
