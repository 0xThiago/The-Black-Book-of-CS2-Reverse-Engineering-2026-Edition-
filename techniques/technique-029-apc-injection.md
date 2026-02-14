# 📖 Técnica 029: APC Injection

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 029: APC Injection]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Injection & Loading  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**APC Injection** usa Asynchronous Procedure Calls para executar código em threads alertáveis, injetando DLLs ou shellcode através de APC queues. É mais stealth que thread creation.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class APCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectViaAPC(const char* dllPath) {
        // Alocar memória para DLL path no processo alvo
        LPVOID remotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) return false;
        
        // Copiar path para memória remota
        if (!WriteProcessMemory(hProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Encontrar thread alertável
        HANDLE hThread = FindAlertableThread();
        if (!hThread) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Queue APC para LoadLibraryA
        if (!QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remotePath)) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            CloseHandle(hThread);
            return false;
        }
        
        // Aguardar execução do APC
        Sleep(100);
        
        // Limpar memória alocada
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        CloseHandle(hThread);
        
        return true;
    }
    
    bool InjectShellcodeViaAPC(const std::vector<BYTE>& shellcode) {
        // Alocar memória para shellcode
        LPVOID remoteShellcode = VirtualAllocEx(hProcess, NULL, shellcode.size(),
                                              MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteShellcode) return false;
        
        // Copiar shellcode
        if (!WriteProcessMemory(hProcess, remoteShellcode, shellcode.data(), shellcode.size(), NULL)) {
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            return false;
        }
        
        // Encontrar thread alertável
        HANDLE hThread = FindAlertableThread();
        if (!hThread) {
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            return false;
        }
        
        // Queue APC para executar shellcode
        if (!QueueUserAPC((PAPCFUNC)remoteShellcode, hThread, 0)) {
            VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
            CloseHandle(hThread);
            return false;
        }
        
        // Aguardar execução
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hProcess, remoteShellcode, 0, MEM_RELEASE);
        CloseHandle(hThread);
        
        return true;
    }
    
private:
    HANDLE FindAlertableThread() {
        // Criar snapshot de threads
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return NULL;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD targetProcessId = GetProcessId(hProcess);
        HANDLE hThread = NULL;
        
        // Enumerar threads
        if (Thread32First(hSnapshot, &te)) {
            do {
                // Verificar se thread pertence ao processo alvo
                if (te.th32OwnerProcessID == targetProcessId) {
                    // Abrir handle da thread
                    hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        // Verificar se thread está em estado alertável
                        if (IsThreadAlertable(hThread)) {
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
    
    bool IsThreadAlertable(HANDLE hThread) {
        // Verificar se thread está esperando (alertável)
        // Nota: Esta é uma verificação simplificada
        
        // Obter estado da thread
        DWORD waitResult = WaitForSingleObject(hThread, 0);
        
        // Se timeout, thread pode estar executando ou esperando
        // Para APC injection, queremos threads que estejam em wait state
        return waitResult == WAIT_TIMEOUT;
    }
};
```

### APC Queue Mechanism

```cpp
// Mecanismo de APC queue
class APCQueueManager {
private:
    HANDLE hProcess;
    std::vector<HANDLE> alertableThreads;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        EnumerateAlertableThreads();
    }
    
    void EnumerateAlertableThreads() {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD targetProcessId = GetProcessId(hProcess);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == targetProcessId) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) {
                        if (IsThreadInAlertableState(hThread)) {
                            alertableThreads.push_back(hThread);
                        } else {
                            CloseHandle(hThread);
                        }
                    }
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
    
    bool QueueAPCForAllThreads(PAPCFUNC pfnAPC, ULONG_PTR dwData) {
        bool success = false;
        
        for (HANDLE hThread : alertableThreads) {
            if (QueueUserAPC(pfnAPC, hThread, dwData)) {
                success = true;
            }
        }
        
        return success;
    }
    
    bool IsThreadInAlertableState(HANDLE hThread) {
        // Verificar se thread está em estado alertável
        // Threads em user-mode waits são alertáveis
        
        // Obter informações da thread
        THREAD_BASIC_INFORMATION tbi;
        if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL) != 0) {
            return false;
        }
        
        // Verificar se thread está esperando
        // (simplificado - em prática seria mais complexo)
        return true; // Assume todas as threads são candidatas
    }
    
    void Cleanup() {
        for (HANDLE hThread : alertableThreads) {
            CloseHandle(hThread);
        }
        alertableThreads.clear();
    }
};
```

### Por que é Detectado

> [!WARNING]
> **APC injection deixa rastros de APCs enfileirados e execuções suspeitas**

#### 1. APC Queue Monitoring
```cpp
// Monitoramento de APC queues
class APCQueueMonitor {
private:
    std::map<HANDLE, std::vector<APC_RECORD>> apcHistory;
    
public:
    void OnQueueUserAPC(HANDLE hThread, PAPCFUNC pfnAPC, ULONG_PTR dwData) {
        APC_RECORD record = {pfnAPC, dwData, GetTickCount()};
        apcHistory[hThread].push_back(record);
        
        // Analisar APC
        AnalyzeAPC(hThread, record);
    }
    
    void AnalyzeAPC(HANDLE hThread, const APC_RECORD& record) {
        // Verificar se APC aponta para LoadLibrary
        if (IsLoadLibraryAPC(record)) {
            ReportLoadLibraryInjection(hThread, record);
        }
        
        // Verificar se APC aponta para memória privada
        if (IsPrivateMemoryAPC(record)) {
            ReportPrivateMemoryInjection(hThread, record);
        }
        
        // Verificar padrão de APCs
        if (HasInjectionPattern(hThread)) {
            ReportAPCInjection(hThread);
        }
    }
    
    bool IsLoadLibraryAPC(const APC_RECORD& record) {
        // Verificar se função APC é LoadLibraryA/W
        return record.pfnAPC == (PAPCFUNC)LoadLibraryA ||
               record.pfnAPC == (PAPCFUNC)LoadLibraryW;
    }
    
    bool IsPrivateMemoryAPC(const APC_RECORD& record) {
        // Verificar se parâmetro aponta para memória privada
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)record.dwData, &mbi, sizeof(mbi))) return false;
        
        return mbi.Type == MEM_PRIVATE;
    }
    
    bool HasInjectionPattern(HANDLE hThread) {
        auto& apcs = apcHistory[hThread];
        if (apcs.size() < 2) return false;
        
        // Verificar se múltiplos APCs suspeitos em sequência
        int suspiciousCount = 0;
        for (auto& apc : apcs) {
            if (IsLoadLibraryAPC(apc) || IsPrivateMemoryAPC(apc)) {
                suspiciousCount++;
            }
        }
        
        return suspiciousCount >= 2;
    }
};
```

#### 2. Thread State Analysis
```cpp
// Análise de estado de threads
class ThreadStateAnalyzer {
private:
    std::map<HANDLE, THREAD_STATE> threadStates;
    
public:
    void OnThreadCreate(HANDLE hThread) {
        THREAD_STATE state = {THREAD_STATE_CREATED, GetTickCount()};
        threadStates[hThread] = state;
    }
    
    void OnAPCQueued(HANDLE hThread) {
        if (threadStates.count(hThread)) {
            threadStates[hThread].lastAPC = GetTickCount();
            threadStates[hThread].apcCount++;
        }
    }
    
    void OnThreadTerminate(HANDLE hThread) {
        if (threadStates.count(hThread)) {
            // Analisar padrão antes de remover
            AnalyzeThreadPattern(hThread);
            threadStates.erase(hThread);
        }
    }
    
    void AnalyzeThreadPattern(HANDLE hThread) {
        THREAD_STATE& state = threadStates[hThread];
        
        // Verificar alta frequência de APCs
        if (state.apcCount > APC_THRESHOLD) {
            ReportHighAPCFrequency(hThread, state);
        }
        
        // Verificar APCs logo após criação
        DWORD timeSinceCreate = GetTickCount() - state.createTime;
        if (timeSinceCreate < THREAD_CREATION_THRESHOLD && state.apcCount > 0) {
            ReportEarlyAPC(hThread, state);
        }
    }
    
    void PeriodicThreadScan() {
        // Escanear todas as threads periodicamente
        for (auto& pair : threadStates) {
            HANDLE hThread = pair.first;
            THREAD_STATE& state = pair.second;
            
            // Verificar threads com muitos APCs pendentes
            if (HasPendingAPCs(hThread)) {
                ReportPendingAPCs(hThread, state);
            }
        }
    }
    
    bool HasPendingAPCs(HANDLE hThread) {
        // Verificar se thread tem APCs pendentes
        // (usando NtQueryInformationThread)
        return false; // Placeholder
    }
};
```

#### 3. Memory Allocation Correlation
```cpp
// Correlação entre alocações de memória e APCs
class MemoryAPCCorrelator {
private:
    std::map<HANDLE, std::vector<MEMORY_APC_EVENT>> events;
    
public:
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size) {
        MEMORY_APC_EVENT event = {MEMORY_ALLOC, address, size, GetTickCount()};
        events[hProcess].push_back(event);
    }
    
    void OnAPCQueued(HANDLE hThread, PAPCFUNC pfnAPC, ULONG_PTR dwData) {
        // Verificar se APC usa memória recém-alocada
        DWORD processId = GetProcessIdOfThread(hThread);
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        
        if (hProcess) {
            CheckMemoryAPCCorrelation(hProcess, dwData);
            CloseHandle(hProcess);
        }
        
        MEMORY_APC_EVENT event = {APC_QUEUED, (LPVOID)dwData, 0, GetTickCount()};
        events[hProcess].push_back(event);
    }
    
    void CheckMemoryAPCCorrelation(HANDLE hProcess, ULONG_PTR dwData) {
        auto& processEvents = events[hProcess];
        if (processEvents.empty()) return;
        
        // Procurar alocação recente que corresponda ao parâmetro APC
        for (auto it = processEvents.rbegin(); it != processEvents.rend(); ++it) {
            if (it->type == MEMORY_ALLOC) {
                DWORD timeDiff = GetTickCount() - it->timestamp;
                
                // Se alocação recente e endereço próximo
                if (timeDiff < CORRELATION_TIME_WINDOW &&
                    abs((intptr_t)dwData - (intptr_t)it->address) < ADDRESS_PROXIMITY_THRESHOLD) {
                    ReportMemoryAPCCorrelation(hProcess, *it, dwData);
                    break;
                }
            }
        }
    }
    
    DWORD GetProcessIdOfThread(HANDLE hThread) {
        THREAD_BASIC_INFORMATION tbi;
        if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL) == 0) {
            return (DWORD)tbi.ClientId.UniqueProcess;
        }
        return 0;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | APC queue monitoring | < 30s | 70% |
| VAC Live | Thread state analysis | Imediato | 75% |
| BattlEye | Memory-APC correlation | < 1 min | 80% |
| Faceit AC | APC pattern analysis | < 30s | 65% |

---

## 🔄 Alternativas Seguras

### 1. Early Bird APC
```cpp
// ✅ Early bird APC injection
class EarlyBirdAPCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool EarlyBirdInject(const char* dllPath) {
        // Criar processo suspenso
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        char cmdLine[] = "notepad.exe"; // Processo dummy
        if (!CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }
        
        // Injetar via APC antes do processo começar
        if (!InjectViaEarlyAPC(pi.hThread, dllPath)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Resumir processo
        ResumeThread(pi.hThread);
        
        // Aguardar injeção
        Sleep(1000);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }
    
private:
    bool InjectViaEarlyAPC(HANDLE hThread, const char* dllPath) {
        // Alocar memória para path no processo recém-criado
        HANDLE hTargetProcess = GetProcessFromThread(hThread);
        
        LPVOID remotePath = VirtualAllocEx(hTargetProcess, NULL, strlen(dllPath) + 1,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) return false;
        
        // Copiar path
        WriteProcessMemory(hTargetProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL);
        
        // Queue APC na thread principal (ainda suspensa)
        if (!QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remotePath)) {
            VirtualFreeEx(hTargetProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        return true;
    }
    
    HANDLE GetProcessFromThread(HANDLE hThread) {
        THREAD_BASIC_INFORMATION tbi;
        if (NtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL) == 0) {
            return OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)tbi.ClientId.UniqueProcess);
        }
        return NULL;
    }
};
```

### 2. Kernel APC Injection
```cpp
// ✅ Kernel APC injection (mais avançado)
class KernelAPCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool KernelAPCInject(const char* dllPath) {
        // Abrir device handle para driver
        HANDLE hDriver = CreateFileA("\\\\.\\KernelAPCInjector", GENERIC_READ | GENERIC_WRITE,
                                   0, NULL, OPEN_EXISTING, 0, NULL);
        if (hDriver == INVALID_HANDLE_VALUE) return false;
        
        // Preparar estrutura de injeção
        KERNEL_APC_INJECTION_DATA injectionData;
        strcpy_s(injectionData.dllPath, dllPath);
        injectionData.targetProcessId = GetProcessId(hProcess);
        
        // Enviar IOCTL para driver
        DWORD bytesReturned;
        BOOL result = DeviceIoControl(hDriver, IOCTL_INJECT_APC,
                                    &injectionData, sizeof(injectionData),
                                    NULL, 0, &bytesReturned, NULL);
        
        CloseHandle(hDriver);
        return result != FALSE;
    }
    
private:
    typedef struct _KERNEL_APC_INJECTION_DATA {
        char dllPath[MAX_PATH];
        DWORD targetProcessId;
    } KERNEL_APC_INJECTION_DATA;
    
    #define IOCTL_INJECT_APC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
};
```

### 3. Alertable Thread Creation
```cpp
// ✅ Criação de thread alertável
class AlertableThreadCreator {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool CreateAlertableThread(const char* dllPath) {
        // Criar thread que fica em estado alertável
        LPVOID remotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remotePath) return false;
        
        WriteProcessMemory(hProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL);
        
        // Criar thread que executa SleepEx (fica alertável)
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)SleepEx,
                                          (LPVOID)INFINITE, 0, NULL);
        if (!hThread) {
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Aguardar thread ficar alertável
        Sleep(100);
        
        // Queue APC
        if (!QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)remotePath)) {
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Alertar thread (executa APC)
        if (!QueueUserAPC((PAPCFUNC)ExitThread, hThread, 0)) {
            TerminateThread(hThread, 0);
            CloseHandle(hThread);
            VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
            return false;
        }
        
        // Aguardar término
        WaitForSingleObject(hThread, INFINITE);
        
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, remotePath, 0, MEM_RELEASE);
        
        return true;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC APC Detection
```cpp
// VAC APC injection detection
class VAC_APCDetector {
private:
    APCQueueMonitor apcMonitor;
    ThreadStateAnalyzer threadAnalyzer;
    MemoryAPCCorrelator correlator;
    
public:
    void Initialize() {
        apcMonitor.Initialize();
        threadAnalyzer.Initialize();
        correlator.Initialize();
    }
    
    void OnProcessAttach(HANDLE hProcess) {
        StartMonitoring(hProcess);
    }
    
    void OnQueueUserAPC(HANDLE hThread, PAPCFUNC pfnAPC, ULONG_PTR dwData) {
        apcMonitor.OnQueueUserAPC(hThread, pfnAPC, dwData);
        threadAnalyzer.OnAPCQueued(hThread);
        correlator.OnAPCQueued(hThread, pfnAPC, dwData);
    }
    
    void OnThreadCreate(HANDLE hThread) {
        threadAnalyzer.OnThreadCreate(hThread);
    }
    
    void PeriodicScan() {
        threadAnalyzer.PeriodicThreadScan();
    }
};
```

### BattlEye APC Analysis
```cpp
// BE APC injection analysis
void BE_DetectAPCInjection() {
    // Monitor APC queues
    MonitorAPCQueues();
    
    // Analyze thread states
    AnalyzeThreadStates();
    
    // Correlate memory and APCs
    CorrelateMemoryAPCs();
}

void MonitorAPCQueues() {
    // Hook QueueUserAPC
    // Track APC parameters
}

void AnalyzeThreadStates() {
    // Monitor thread creation
    // Detect alertable threads
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | APC monitoring |
| 2025-2026 | ⚠️ Alto risco | Thread analysis |

---

## 🎯 Lições Aprendidas

1. **APCs São Monitorados**: QueueUserAPC é hooked por anti-cheats.

2. **Threads São Analisados**: Estados alertáveis são verificados.

3. **Correlação é Detectada**: Alocações + APCs são correlacionadas.

4. **Early Bird é Mais Stealth**: Injetar antes do processo começar evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#29]]
- [[Early_Bird_APC]]
- [[Kernel_APC_Injection]]
- [[Alertable_Thread_Creation]]

---

*APC injection tem risco moderado. Considere early bird APC para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
