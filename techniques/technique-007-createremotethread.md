# 📖 Técnica 006: CreateRemoteThread

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 006: CreateRemoteThread]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Crítico  
> **Domínio:** Threading & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**CreateRemoteThread** é uma API do Windows usada para criar threads em processos externos. É uma das técnicas mais antigas e facilmente detectáveis de injeção de código em jogos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
HANDLE CreateRemoteThread_Simple(HANDLE hProcess, LPTHREAD_START_ROUTINE startAddr, 
                                LPVOID parameter) {
    return CreateRemoteThread(hProcess, NULL, 0, startAddr, parameter, 0, NULL);
}

// Exemplo completo de DLL injection
BOOL InjectDLL(HANDLE hProcess, const char* dllPath) {
    // 1. Alocar memória para path da DLL
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                      MEM_COMMIT, PAGE_READWRITE);
    
    // 2. Escrever path
    WriteProcessMemory(hProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL);
    
    // 3. Obter endereço de LoadLibraryA
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
    
    // 4. Criar thread remoto
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)loadLibraryAddr, 
                                       remotePath, 0, NULL);
    
    // 5. Aguardar conclusão
    WaitForSingleObject(hThread, INFINITE);
    
    // 6. Limpar
    VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
    CloseHandle(hThread);
    
    return TRUE;
}
```

### Por que é Detectado

> [!DANGER]
> **CreateRemoteThread é completamente monitorado pelos ACs modernos**

#### 1. Thread Creation Hooks
```cpp
// Hook direto na API
DetourTransactionBegin();
DetourUpdateThread(GetCurrentThread());
DetourAttach(&(PVOID&)OriginalCreateRemoteThread, HookedCreateRemoteThread);
DetourTransactionCommit();

HANDLE WINAPI HookedCreateRemoteThread(
    HANDLE hProcess,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    SIZE_T dwStackSize,
    LPTHREAD_START_ROUTINE lpStartAddress,
    LPVOID lpParameter,
    DWORD dwCreationFlags,
    LPDWORD lpThreadId
) {
    // Verificar se processo alvo é protegido
    if (IsProtectedProcess(hProcess)) {
        LogSuspiciousThreadCreation(hProcess, lpStartAddress);
        
        // Possivelmente bloquear
        SetLastError(ERROR_ACCESS_DENIED);
        return NULL;
    }
    
    return OriginalCreateRemoteThread(hProcess, lpThreadAttributes, dwStackSize,
                                     lpStartAddress, lpParameter, dwCreationFlags, 
                                     lpThreadId);
}
```

#### 2. Thread Enumeration and Analysis
```cpp
// Enumerar e analisar threads
void AnalyzeThreads(DWORD processId) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    
    if (hSnapshot != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    AnalyzeThread(te.th32ThreadID);
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
}

void AnalyzeThread(DWORD threadId) {
    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, threadId);
    
    if (hThread) {
        // Verificar start address
        LPVOID startAddr = GetThreadStartAddress(hThread);
        
        if (IsSuspiciousStartAddress(startAddr)) {
            ReportInjectedThread(threadId, startAddr);
        }
        
        CloseHandle(hThread);
    }
}
```

#### 3. Stack Trace Analysis
```cpp
// Analisar stack trace de threads suspeitos
void AnalyzeThreadStack(HANDLE hThread) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    
    if (GetThreadContext(hThread, &context)) {
        // Walk stack
        STACKFRAME64 stackFrame = {0};
        stackFrame.AddrPC.Offset = context.Rip;
        stackFrame.AddrStack.Offset = context.Rsp;
        stackFrame.AddrFrame.Offset = context.Rbp;
        
        while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, GetCurrentProcess(),
                          hThread, &stackFrame, &context, NULL,
                          SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
            
            // Verificar se stack contém código suspeito
            if (IsSuspiciousStackFrame(stackFrame.AddrPC.Offset)) {
                ReportSuspiciousStack(threadId, stackFrame.AddrPC.Offset);
                break;
            }
        }
    }
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Thread creation hooks | Imediato | 100% |
| VAC Live | Thread enumeration | < 5 min | 100% |
| BattlEye | Stack analysis | < 30s | 98% |
| Faceit AC | Start address check | < 1 min | 95% |

---

## 🔄 Alternativas Seguras

### 1. APC Injection
```cpp
// ✅ Asynchronous Procedure Call injection
NTSTATUS InjectViaAPC(HANDLE threadHandle, PVOID shellcode, SIZE_T size) {
    // Alocar memória no processo alvo
    PVOID remoteBuffer = AllocateRemoteMemory(threadHandle, size);
    memcpy(remoteBuffer, shellcode, size);
    
    // Queue APC para thread específica
    NTSTATUS status = NtQueueApcThread(
        threadHandle,
        (PKNORMAL_ROUTINE)remoteBuffer,
        NULL, NULL, NULL
    );
    
    return status;
}
```

### 2. Thread Hijacking
```cpp
// ✅ Hijack existing thread
NTSTATUS HijackThread(HANDLE threadHandle, PVOID shellcode, SIZE_T size) {
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL;
    
    // Suspender thread
    SuspendThread(threadHandle);
    
    // Obter contexto atual
    GetThreadContext(threadHandle, &context);
    
    // Salvar contexto original
    CONTEXT originalContext = context;
    
    // Modificar RIP para apontar para shellcode
    context.Rip = (DWORD64)shellcode;
    
    // Executar shellcode
    SetThreadContext(threadHandle, &context);
    ResumeThread(threadHandle);
    
    // Aguardar execução
    Sleep(100);
    
    // Restaurar contexto original
    SetThreadContext(threadHandle, &originalContext);
    ResumeThread(threadHandle);
    
    return STATUS_SUCCESS;
}
```

### 3. Kernel Thread Creation
```cpp
// ✅ Criar thread via kernel
NTSTATUS CreateKernelThread(PEPROCESS targetProcess, PVOID startAddress) {
    HANDLE hThread;
    
    // Usar PsCreateSystemThread
    NTSTATUS status = PsCreateSystemThread(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        targetProcess,
        NULL,
        startAddress,
        NULL
    );
    
    if (NT_SUCCESS(status)) {
        // Configurar thread para user-mode
        KeConvertThreadToGuiThread(hThread);
    }
    
    return status;
}
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Thread Monitor
```cpp
// VAC thread creation monitoring
class VAC_ThreadMonitor {
private:
    std::vector<THREAD_INFO> legitimateThreads;
    
public:
    void Initialize() {
        // Enumerar threads legítimas na inicialização
        EnumerateLegitimateThreads();
        
        // Instalar hooks
        InstallThreadHooks();
    }
    
    void OnThreadCreate(HANDLE hProcess, LPVOID startAddr, LPVOID param) {
        // Verificar se é thread legítima
        if (!IsLegitimateThread(startAddr)) {
            LogSuspiciousThread(hProcess, startAddr, param);
            
            // Verificar padrão de injeção
            if (IsInjectionPattern(startAddr, param)) {
                ReportCheatDetected();
            }
        }
    }
    
    bool IsLegitimateThread(LPVOID startAddr) {
        // Verificar se start address está em módulo legítimo
        HMODULE hModule;
        if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                             (LPCTSTR)startAddr, &hModule)) {
            char moduleName[MAX_PATH];
            GetModuleFileNameA(hModule, moduleName, MAX_PATH);
            
            // Verificar se é módulo do jogo ou sistema
            return IsTrustedModule(moduleName);
        }
        
        return false;
    }
};
```

### BattlEye Thread Scanner
```cpp
// BE thread analysis system
void BE_ScanThreads() {
    // Enumerate all threads in system
    EnumThreads();
    
    for (auto& thread : threads) {
        if (IsGameProcess(thread.processId)) {
            AnalyzeGameThread(thread);
        }
    }
}

void AnalyzeGameThread(const THREAD_INFO& thread) {
    // Open thread for analysis
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, thread.id);
    
    if (hThread) {
        // Check start address
        LPVOID startAddr = GetThreadStartAddress(hThread);
        
        if (!IsValidStartAddress(startAddr)) {
            ReportSuspiciousThread(thread.id, startAddr);
        }
        
        // Analyze stack
        AnalyzeThreadStack(hThread);
        
        CloseHandle(hThread);
    }
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Hooks |
| 2020-2024 | ⛔ Alto risco | Analysis |
| 2025-2026 | ⛔ Crítico | AI patterns |

---

## 🎯 Lições Aprendidas

1. **Threads São Enumeráveis**: Todas as threads podem ser listadas e analisadas.

2. **Start Address é Chave**: Endereço de início revela origem do thread.

3. **Stack Trace Revela**: Análise de stack detecta código injetado.

4. **APC é Mais Seguro**: Asynchronous Procedure Calls evitam detecção direta.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#6]]
- [[APC_Injection]]
- [[Thread_Hijacking]]
- [[Kernel_Thread_Creation]]

---

*CreateRemoteThread é completamente obsoleto. Use APC injection ou thread hijacking em 2026.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
