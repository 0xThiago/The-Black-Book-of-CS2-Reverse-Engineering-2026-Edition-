# Técnica 031 - Thread Hijacking

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 014 - DLL Injection via APC]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Injection & Loading  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Thread Hijacking** sequestra uma thread existente, modifica seu contexto para executar código arbitrário, e depois restaura o contexto original. É mais stealth que criar novas threads.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ThreadHijacker {
private:
    HANDLE hTargetProcess;
    
public:
    void Initialize(DWORD targetProcessId) {
        hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    }
    
    bool HijackAndInject(const char* dllPath) {
        // Encontrar thread alvo
        HANDLE hTargetThread = FindTargetThread();
        if (!hTargetThread) return false;
        
        // Suspender thread
        SuspendThread(hTargetThread);
        
        // Salvar contexto original
        CONTEXT originalContext;
        originalContext.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hTargetThread, &originalContext)) {
            ResumeThread(hTargetThread);
            CloseHandle(hTargetThread);
            return false;
        }
        
        // Criar shellcode para LoadLibrary
        std::vector<BYTE> shellcode = CreateLoadLibraryShellcode(dllPath);
        
        // Alocar memória para shellcode
        LPVOID shellcodeAddr = VirtualAllocEx(hTargetProcess, NULL, shellcode.size(),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) {
            ResumeThread(hTargetThread);
            CloseHandle(hTargetThread);
            return false;
        }
        
        // Injetar shellcode
        if (!WriteProcessMemory(hTargetProcess, shellcodeAddr, shellcode.data(), shellcode.size(), NULL)) {
            VirtualFreeEx(hTargetProcess, shellcodeAddr, 0, MEM_RELEASE);
            ResumeThread(hTargetThread);
            CloseHandle(hTargetThread);
            return false;
        }
        
        // Modificar contexto para executar shellcode
        CONTEXT modifiedContext = originalContext;
        modifiedContext.Rip = (uintptr_t)shellcodeAddr; // x64
        
        // PUSH endereço de retorno (contexto original)
        modifiedContext.Rsp -= 8;
        WriteProcessMemory(hTargetProcess, (LPVOID)modifiedContext.Rsp, &originalContext.Rip, 8, NULL);
        
        // Aplicar contexto modificado
        if (!SetThreadContext(hTargetThread, &modifiedContext)) {
            VirtualFreeEx(hTargetProcess, shellcodeAddr, 0, MEM_RELEASE);
            ResumeThread(hTargetThread);
            CloseHandle(hTargetThread);
            return false;
        }
        
        // Resumir thread (executa shellcode)
        ResumeThread(hTargetThread);
        
        // Aguardar execução completar
        Sleep(100);
        
        // Limpar memória
        VirtualFreeEx(hTargetProcess, shellcodeAddr, 0, MEM_RELEASE);
        
        CloseHandle(hTargetThread);
        return true;
    }
    
private:
    HANDLE FindTargetThread() {
        // Criar snapshot de threads
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD targetProcessId = GetProcessId(hTargetProcess);
        HANDLE hThread = NULL;
        
        // Enumerar threads
        if (Thread32First(hSnapshot, &te)) {
            do {
                // Verificar se thread pertence ao processo alvo
                if (te.th32OwnerProcessID == targetProcessId) {
                    // Abrir handle da thread
                    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        // Verificar se thread é adequada para hijacking
                        if (IsSuitableForHijacking(hThread)) {
                            break; // Encontrou thread adequada
                        } else {
                            CloseHandle(hThread);
                            hThread = NULL;
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return hThread;
    }
    
    bool IsSuitableForHijacking(HANDLE hThread) {
        // Verificar se thread não é crítica do sistema
        // Verificar se thread não está em syscall
        // Verificar se thread tem stack suficiente
        
        // Obter informações da thread
        THREAD_BASIC_INFORMATION tbi;
        if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL) != 0) {
            return false;
        }
        
        // Verificar se thread está em user-mode
        // (simplificado - em prática seria mais complexo)
        return true;
    }
    
    std::vector<BYTE> CreateLoadLibraryShellcode(const char* dllPath) {
        std::vector<BYTE> shellcode;
        
        // x64 shellcode para LoadLibraryA
        // SUB RSP, 28h (shadow space + alignment)
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xEC);
        shellcode.push_back(0x28);
        
        // LEA RCX, [RIP + dllPath]
        shellcode.push_back(0x48);
        shellcode.push_back(0x8D);
        shellcode.push_back(0x0D);
        // Offset será calculado depois
        
        // Placeholder para dllPath
        size_t pathOffset = shellcode.size();
        for (size_t i = 0; i < strlen(dllPath) + 1; i++) {
            shellcode.push_back(0x00); // Placeholder
        }
        
        // MOV RAX, LoadLibraryA
        shellcode.push_back(0x48);
        shellcode.push_back(0xB8);
        uintptr_t loadLibraryAddr = (uintptr_t)LoadLibraryA;
        shellcode.insert(shellcode.end(), (BYTE*)&loadLibraryAddr, (BYTE*)&loadLibraryAddr + 8);
        
        // CALL RAX
        shellcode.push_back(0xFF);
        shellcode.push_back(0xD0);
        
        // ADD RSP, 28h
        shellcode.push_back(0x48);
        shellcode.push_back(0x83);
        shellcode.push_back(0xC4);
        shellcode.push_back(0x28);
        
        // RET
        shellcode.push_back(0xC3);
        
        // Copiar dllPath para o placeholder
        memcpy(&shellcode[pathOffset], dllPath, strlen(dllPath) + 1);
        
        // Calcular offset para LEA
        int32_t offset = (int32_t)(pathOffset - (shellcode.size() - 1));
        memcpy(&shellcode[7], &offset, 4);
        
        return shellcode;
    }
};
```

### Context Preservation

```cpp
// Preservação de contexto de thread
class ContextPreserver {
private:
    HANDLE hTargetProcess;
    
public:
    void Initialize(DWORD targetProcessId) {
        hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    }
    
    bool HijackWithContextPreservation(HANDLE hThread, const std::vector<BYTE>& shellcode) {
        // Salvar contexto completo
        CONTEXT originalContext = {0};
        originalContext.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &originalContext)) return false;
        
        // Salvar stack state
        STACK_STATE stackState = SaveStackState(hThread, originalContext);
        
        // Executar shellcode
        bool result = ExecuteShellcodeInThread(hThread, shellcode, originalContext);
        
        // Restaurar stack state
        RestoreStackState(hThread, stackState);
        
        // Restaurar contexto
        SetThreadContext(hThread, &originalContext);
        
        return result;
    }
    
private:
    STACK_STATE SaveStackState(HANDLE hThread, const CONTEXT& context) {
        STACK_STATE state;
        
        // Salvar região da stack ao redor de RSP
        uintptr_t stackBase = context.Rsp - STACK_SAVE_SIZE / 2;
        state.stackData.resize(STACK_SAVE_SIZE);
        
        ReadProcessMemory(hTargetProcess, (LPCVOID)stackBase, 
                         state.stackData.data(), STACK_SAVE_SIZE, NULL);
        
        state.stackBase = stackBase;
        return state;
    }
    
    void RestoreStackState(HANDLE hThread, const STACK_STATE& state) {
        // Restaurar dados da stack
        WriteProcessMemory(hTargetProcess, (LPVOID)state.stackBase,
                          state.stackData.data(), state.stackData.size(), NULL);
    }
    
    bool ExecuteShellcodeInThread(HANDLE hThread, const std::vector<BYTE>& shellcode, CONTEXT& context) {
        // Alocar shellcode
        LPVOID shellcodeAddr = VirtualAllocEx(hTargetProcess, NULL, shellcode.size(),
                                            MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!shellcodeAddr) return false;
        
        // Injetar shellcode
        WriteProcessMemory(hTargetProcess, shellcodeAddr, shellcode.data(), shellcode.size(), NULL);
        
        // Modificar contexto
        CONTEXT modifiedContext = context;
        modifiedContext.Rip = (uintptr_t)shellcodeAddr;
        
        // Salvar endereço de retorno
        modifiedContext.Rsp -= 8;
        WriteProcessMemory(hTargetProcess, (LPVOID)modifiedContext.Rsp, &context.Rip, 8, NULL);
        
        // Aplicar contexto
        SetThreadContext(hThread, &modifiedContext);
        
        // Resumir e aguardar
        ResumeThread(hThread);
        Sleep(100);
        SuspendThread(hThread);
        
        // Limpar
        VirtualFreeEx(hTargetProcess, shellcodeAddr, 0, MEM_RELEASE);
        
        return true;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Thread hijacking deixa rastros de modificações no contexto e execuções suspeitas**

#### 1. Context Modification Detection
```cpp
// Detecção de modificações no contexto
class ContextModificationDetector {
private:
    std::map<HANDLE, CONTEXT_SNAPSHOT> threadContexts;
    
public:
    void OnThreadCreate(HANDLE hThread) {
        // Capturar contexto inicial
        CONTEXT_SNAPSHOT snapshot;
        snapshot.context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &snapshot.context);
        snapshot.timestamp = GetTickCount();
        
        threadContexts[hThread] = snapshot;
    }
    
    void OnThreadContextChange(HANDLE hThread) {
        // Verificar mudanças no contexto
        if (threadContexts.count(hThread)) {
            CONTEXT_SNAPSHOT& original = threadContexts[hThread];
            
            CONTEXT current;
            current.ContextFlags = CONTEXT_FULL;
            GetThreadContext(hThread, &current);
            
            // Comparar contextos
            if (HasSuspiciousContextChange(original.context, current)) {
                ReportContextHijacking(hThread, original, current);
            }
        }
    }
    
    bool HasSuspiciousContextChange(const CONTEXT& original, const CONTEXT& current) {
        // Verificar mudanças no RIP (instrução pointer)
        if (original.Rip != current.Rip) {
            // Verificar se RIP aponta para memória privada
            MEMORY_BASIC_INFORMATION mbi;
            if (VirtualQuery((LPCVOID)current.Rip, &mbi, sizeof(mbi))) {
                if (mbi.Type == MEM_PRIVATE) {
                    return true;
                }
            }
        }
        
        // Verificar mudanças no RSP (stack pointer)
        if (abs((intptr_t)original.Rsp - (intptr_t)current.Rsp) > STACK_CHANGE_THRESHOLD) {
            return true;
        }
        
        // Verificar registros modificados
        if (HaveRegistersChanged(original, current)) {
            return true;
        }
        
        return false;
    }
    
    bool HaveRegistersChanged(const CONTEXT& original, const CONTEXT& current) {
        // Comparar registros importantes
        return original.Rax != current.Rax ||
               original.Rbx != current.Rbx ||
               original.Rcx != current.Rcx ||
               original.Rdx != current.Rdx;
    }
};
```

#### 2. Thread Execution Pattern Analysis
```cpp
// Análise de padrões de execução de thread
class ThreadExecutionAnalyzer {
private:
    std::map<HANDLE, EXECUTION_PATTERN> executionPatterns;
    
public:
    void OnThreadResume(HANDLE hThread) {
        if (executionPatterns.count(hThread) == 0) {
            EXECUTION_PATTERN pattern = {0};
            pattern.resumeTime = GetTickCount();
            executionPatterns[hThread] = pattern;
        }
    }
    
    void OnThreadSuspend(HANDLE hThread) {
        if (executionPatterns.count(hThread)) {
            executionPatterns[hThread].suspendTime = GetTickCount();
        }
    }
    
    void OnThreadExecute(HANDLE hThread) {
        if (executionPatterns.count(hThread)) {
            EXECUTION_PATTERN& pattern = executionPatterns[hThread];
            pattern.executionCount++;
            pattern.lastExecution = GetTickCount();
            
            // Analisar padrão
            AnalyzeExecutionPattern(hThread, pattern);
        }
    }
    
    void AnalyzeExecutionPattern(HANDLE hThread, const EXECUTION_PATTERN& pattern) {
        // Verificar execuções muito curtas
        if (pattern.suspendTime > 0) {
            DWORD executionDuration = pattern.suspendTime - pattern.resumeTime;
            if (executionDuration < MIN_EXECUTION_TIME) {
                ReportSuspiciousExecution(hThread, pattern);
            }
        }
        
        // Verificar alta frequência de suspend/resume
        if (pattern.executionCount > MAX_EXECUTION_COUNT) {
            ReportHighFrequencyExecution(hThread, pattern);
        }
        
        // Verificar timing suspeito
        DWORD timeSinceLastExecution = GetTickCount() - pattern.lastExecution;
        if (timeSinceLastExecution < EXECUTION_TIME_WINDOW) {
            ReportRapidExecution(hThread, pattern);
        }
    }
};
```

#### 3. Memory Allocation Correlation
```cpp
// Correlação entre alocações de memória e hijacking
class MemoryHijackCorrelator {
private:
    std::map<HANDLE, std::vector<MEMORY_OPERATION>> memoryOps;
    
public:
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MEMORY_OPERATION op = {MEMORY_ALLOC, address, size, GetTickCount()};
        memoryOps[hProcess].push_back(op);
    }
    
    void OnThreadContextChange(HANDLE hThread, uintptr_t newRip) {
        // Verificar se novo RIP corresponde a alocação recente
        HANDLE hProcess = GetProcessFromThread(hThread);
        
        if (memoryOps.count(hProcess)) {
            auto& ops = memoryOps[hProcess];
            
            for (auto it = ops.rbegin(); it != ops.rend(); ++it) {
                if (it->type == MEMORY_ALLOC) {
                    DWORD timeDiff = GetTickCount() - it->timestamp;
                    
                    // Alocação recente próxima ao RIP
                    if (timeDiff < CORRELATION_TIME_WINDOW &&
                        IsAddressInAllocation(newRip, *it)) {
                        ReportMemoryHijackCorrelation(hProcess, hThread, *it, newRip);
                        break;
                    }
                }
            }
        }
    }
    
    bool IsAddressInAllocation(uintptr_t address, const MEMORY_OPERATION& op) {
        uintptr_t allocStart = (uintptr_t)op.address;
        uintptr_t allocEnd = allocStart + op.size;
        
        return address >= allocStart && address < allocEnd;
    }
    
    HANDLE GetProcessFromThread(HANDLE hThread) {
        THREAD_BASIC_INFORMATION tbi;
        if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL) == 0) {
            return OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, (DWORD)tbi.ClientId.UniqueProcess);
        }
        return NULL;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Context modification | < 30s | 70% |
| VAC Live | Execution patterns | Imediato | 75% |
| BattlEye | Memory correlation | < 1 min | 80% |
| Faceit AC | Thread state analysis | < 30s | 65% |

---

## 🔄 Alternativas Seguras

### 1. SetWindowsHookEx Injection
```cpp
// ✅ SetWindowsHookEx injection
class HookInjector {
private:
    HANDLE hTargetProcess;
    
public:
    void Initialize(DWORD targetProcessId) {
        hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    }
    
    bool InjectViaHook(const char* dllPath) {
        // Carregar DLL localmente
        HMODULE hLocalDLL = LoadLibraryA(dllPath);
        if (!hLocalDLL) return false;
        
        // Instalar hook global
        HHOOK hHook = SetWindowsHookExA(WH_GETMESSAGE, 
                                       (HOOKPROC)GetProcAddress(hLocalDLL, "HookProc"),
                                       hLocalDLL, 0); // Global hook
        
        if (!hHook) {
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Trigger hook no processo alvo
        TriggerHookInTargetProcess();
        
        // Remover hook
        UnhookWindowsHookEx(hHook);
        FreeLibrary(hLocalDLL);
        
        return true;
    }
    
private:
    void TriggerHookInTargetProcess() {
        // Enviar mensagem para trigger o hook
        PostThreadMessage(GetWindowThreadProcessId(FindWindow(NULL, "Target Window"), NULL),
                         WM_USER, 0, 0);
    }
};
```

### 2. QueueUserWorkItem Injection
```cpp
// ✅ QueueUserWorkItem injection
class WorkItemInjector {
private:
    HANDLE hTargetProcess;
    
public:
    void Initialize(DWORD targetProcessId) {
        hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    }
    
    bool InjectViaWorkItem(const char* dllPath) {
        // Alocar memória para DLL path
        LPVOID remotePath = VirtualAllocEx(hTargetProcess, NULL, strlen(dllPath) + 1,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) return false;
        
        WriteProcessMemory(hTargetProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL);
        
        // Queue work item
        if (!QueueUserWorkItem((LPTHREAD_START_ROUTINE)LoadLibraryA, remotePath, WT_EXECUTEDEFAULT)) {
            VirtualFreeEx(hTargetProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Aguardar execução
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hTargetProcess, remotePath, 0, MEM_RELEASE);
        
        return true;
    }
};
```

### 3. Fiber Injection
```cpp
// ✅ Fiber injection
class FiberInjector {
private:
    HANDLE hTargetProcess;
    
public:
    void Initialize(DWORD targetProcessId) {
        hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetProcessId);
    }
    
    bool InjectViaFiber(const char* dllPath) {
        // Converter thread em fiber
        PVOID mainFiber = ConvertThreadToFiber(NULL);
        if (!mainFiber) return false;
        
        // Criar fiber com payload
        PVOID payloadFiber = CreateFiber(0, (LPFIBER_START_ROUTINE)LoadLibraryA, 
                                       (LPVOID)dllPath);
        if (!payloadFiber) {
            ConvertFiberToThread();
            return false;
        }
        
        // Switch para fiber
        SwitchToFiber(payloadFiber);
        
        // Limpar
        DeleteFiber(payloadFiber);
        ConvertFiberToThread();
        
        return true;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Thread Hijacking Detection
```cpp
// VAC thread hijacking detection
class VAC_ThreadHijackDetector {
private:
    ContextModificationDetector contextDetector;
    ThreadExecutionAnalyzer executionAnalyzer;
    MemoryHijackCorrelator correlator;
    
public:
    void Initialize() {
        contextDetector.Initialize();
        executionAnalyzer.Initialize();
        correlator.Initialize();
    }
    
    void OnThreadCreate(HANDLE hThread) {
        contextDetector.OnThreadCreate(hThread);
        executionAnalyzer.OnThreadCreate(hThread);
    }
    
    void OnThreadContextChange(HANDLE hThread) {
        contextDetector.OnThreadContextChange(hThread);
        correlator.OnThreadContextChange(hThread, GetCurrentRip(hThread));
    }
    
    void OnThreadResume(HANDLE hThread) {
        executionAnalyzer.OnThreadResume(hThread);
    }
    
    void OnThreadSuspend(HANDLE hThread) {
        executionAnalyzer.OnThreadSuspend(hThread);
    }
    
private:
    uintptr_t GetCurrentRip(HANDLE hThread) {
        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(hThread, &context);
        return context.Rip;
    }
};
```

### BattlEye Thread Analysis
```cpp
// BE thread hijacking analysis
void BE_DetectThreadHijacking() {
    // Monitor thread context changes
    MonitorThreadContextChanges();
    
    // Analyze execution patterns
    AnalyzeExecutionPatterns();
    
    // Correlate memory allocations
    CorrelateMemoryAllocations();
}

void MonitorThreadContextChanges() {
    // Hook GetThreadContext/SetThreadContext
    // Detect suspicious RIP changes
}

void AnalyzeExecutionPatterns() {
    // Track suspend/resume patterns
    // Detect rapid context switches
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Context monitoring |
| 2025-2026 | ⚠️ Alto risco | Pattern analysis |

---

## 🎯 Lições Aprendidas

1. **Contextos São Monitorados**: Mudanças no RIP/RSP são detectadas.

2. **Padrões de Execução São Analisados**: Suspend/resume frequentes são suspeitos.

3. **Correlação é Detectada**: Alocações + mudanças de contexto são correlacionadas.

4. **SetWindowsHookEx é Mais Stealth**: Usar hooks do Windows é menos detectável.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#31]]
- [[SetWindowsHookEx_Injection]]
- [[QueueUserWorkItem_Injection]]
- [[Fiber_Injection]]

---

*Thread hijacking tem risco moderado. Considere SetWindowsHookEx para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
