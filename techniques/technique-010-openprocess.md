# Técnica 009: OpenProcess

> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Handles & Acesso  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**OpenProcess** é a API fundamental do Windows para obter handles de processos externos. Embora seja uma função legítima do sistema, seu uso com permissões elevadas em jogos é um indicador claro de atividade de cheating.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
HANDLE OpenGameProcess(DWORD pid) {
    // Abrir processo com permissões completas
    return OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
}

// Exemplo de uso em cheat
void CheatMain() {
    DWORD cs2Pid = FindProcessByName("cs2.exe");
    
    if (cs2Pid) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, 
                                     FALSE, cs2Pid);
        
        if (hProcess) {
            // Usar handle para memory reading/writing
            ReadGameMemory(hProcess);
            WriteCheatData(hProcess);
            
            CloseHandle(hProcess);
        }
    }
}
```

### Por que é Detectado

> [!DANGER]
> **OpenProcess com permissões elevadas é completamente monitorado**

#### 1. Process Handle Callbacks
```cpp
// ObRegisterCallbacks intercepta OpenProcess
OB_OPERATION_REGISTRATION operations[] = {
    {
        PsProcessType,                    // Tipo de objeto
        OB_OPERATION_HANDLE_CREATE,       // Operação
        ProcessHandleCallback,            // Callback
        NULL
    }
};

void ProcessHandleCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION PreInfo
) {
    ACCESS_MASK desiredAccess = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
    
    // Verificar permissões suspeitas
    if (desiredAccess & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) {
        PEPROCESS sourceProcess = PreInfo->Object;
        PEPROCESS targetProcess = (PEPROCESS)PreInfo->Object;
        
        // Log da tentativa
        LogHandleCreation(sourceProcess, targetProcess, desiredAccess);
        
        // Verificar se alvo é jogo protegido
        if (IsProtectedGame(targetProcess)) {
            // Possivelmente bloquear
            if (IsSuspiciousSource(sourceProcess)) {
                PreInfo->Parameters->CreateHandleInformation.DesiredAccess = 0;
            }
        }
    }
}
```

#### 2. Handle Enumeration
```cpp
// Enumerar handles abertos periodicamente
void EnumerateProcessHandles() {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    ULONG bufferSize = 0x10000;
    
    do {
        handleInfo = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePool(PagedPool, bufferSize);
        
        status = ZwQuerySystemInformation(
            SystemHandleInformation,
            handleInfo,
            bufferSize,
            &bufferSize
        );
        
        if (!NT_SUCCESS(status)) {
            ExFreePool(handleInfo);
        }
        
    } while (status == STATUS_INFO_LENGTH_MISMATCH);
    
    // Processar handles
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        
        // Verificar handles de processo
        if (handle.ObjectTypeIndex == GetProcessObjectType()) {
            AnalyzeProcessHandle(handle);
        }
    }
    
    ExFreePool(handleInfo);
}

void AnalyzeProcessHandle(const SYSTEM_HANDLE& handle) {
    // Verificar se processo alvo é jogo
    if (IsGameProcess(handle.ProcessId)) {
        // Verificar permissões do handle
        if (HasSuspiciousAccess(handle.GrantedAccess)) {
            LogSuspiciousHandle(handle);
        }
    }
}
```

#### 3. Cross-Process Access Patterns
```cpp
// Analisar padrões de acesso entre processos
class ProcessAccessAnalyzer {
private:
    std::map<DWORD, std::vector<ACCESS_EVENT>> accessLog;
    
public:
    void OnHandleCreate(DWORD sourcePid, DWORD targetPid, ACCESS_MASK access) {
        ACCESS_EVENT event = {sourcePid, targetPid, access, GetTickCount()};
        accessLog[sourcePid].push_back(event);
        
        AnalyzeAccessPattern(sourcePid);
    }
    
    void AnalyzeAccessPattern(DWORD sourcePid) {
        auto& events = accessLog[sourcePid];
        
        // Padrão típico de cheat: acesso frequente a jogo
        if (HasCheatPattern(events)) {
            ReportCheatDetected(sourcePid);
        }
        
        // Acesso a múltiplos jogos simultaneamente
        if (HasMultiGameAccess(events)) {
            ReportSuspiciousActivity(sourcePid);
        }
    }
    
    bool HasCheatPattern(const std::vector<ACCESS_EVENT>& events) {
        int gameAccessCount = 0;
        DWORD lastAccess = 0;
        
        for (auto& event : events) {
            if (IsGameProcess(event.targetPid)) {
                gameAccessCount++;
                
                if (lastAccess && (event.timestamp - lastAccess) < 1000) {
                    return true; // Acesso frequente
                }
                
                lastAccess = event.timestamp;
            }
        }
        
        return gameAccessCount > 5; // Múltiplos acessos
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | ObRegisterCallbacks | Imediato | 100% |
| VAC Live | Handle enumeration | < 5 min | 100% |
| BattlEye | Access patterns | < 30s | 98% |
| Faceit AC | Cross-process analysis | < 1 min | 95% |

---

## 🔄 Alternativas Seguras

### 1. Kernel Handle Creation
```cpp
// ✅ Criar handles via kernel
HANDLE CreateKernelHandle(DWORD targetPid, ACCESS_MASK access) {
    PEPROCESS targetProcess;
    HANDLE hProcess;
    
    // Obter EPROCESS do processo alvo
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) return NULL;
    
    // Criar handle via kernel
    status = ObOpenObjectByPointer(
        targetProcess,
        OBJ_KERNEL_HANDLE,
        NULL,
        access,
        *PsProcessType,
        KernelMode,
        &hProcess
    );
    
    ObDereferenceObject(targetProcess);
    return NT_SUCCESS(status) ? hProcess : NULL;
}
```

### 2. Direct Kernel Access
```cpp
// ✅ Acesso direto sem handles
NTSTATUS ReadProcessMemoryDirect(DWORD targetPid, PVOID address, 
                                PVOID buffer, SIZE_T size) {
    PEPROCESS targetProcess;
    
    // Obter processo alvo
    NTSTATUS status = PsLookupProcessByProcessId((HANDLE)targetPid, &targetProcess);
    if (!NT_SUCCESS(status)) return status;
    
    // Acesso direto à memória
    status = MmCopyVirtualMemory(
        targetProcess,
        address,
        PsGetCurrentProcess(),
        buffer,
        size,
        KernelMode,
        NULL
    );
    
    ObDereferenceObject(targetProcess);
    return status;
}
```

### 3. Physical Memory Access
```cpp
// ✅ Acesso via memória física
class PhysicalMemoryAccessor {
private:
    PHYSICAL_ADDRESS physAddr;
    
public:
    void Initialize(DWORD targetPid) {
        // Obter CR3 do processo alvo
        physAddr = GetProcessCR3(targetPid);
    }
    
    template<typename T>
    T Read(uintptr_t virtualAddr) {
        // Traduzir endereço virtual para físico
        PHYSICAL_ADDRESS physAddr = TranslateVirtualToPhysical(virtualAddr);
        
        // Mapear página física
        PVOID mappedPage = MmMapIoSpace(physAddr, PAGE_SIZE, MmNonCached);
        
        if (mappedPage) {
            T value = *(T*)((uintptr_t)mappedPage + (virtualAddr & 0xFFF));
            MmUnmapIoSpace(mappedPage, PAGE_SIZE);
            return value;
        }
        
        return T();
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Handle Monitor
```cpp
// VAC process handle monitoring
class VAC_HandleMonitor {
private:
    std::vector<OB_CALLBACK> callbacks;
    
public:
    void Initialize() {
        // Registrar callbacks para handles de processo
        OB_OPERATION_REGISTRATION reg = {
            PsProcessType,
            OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE,
            HandleCreateCallback,
            this
        };
        
        ObRegisterCallbacks(&reg, &callbacks);
    }
    
    static OB_PREOP_CALLBACK_STATUS HandleCreateCallback(
        PVOID RegistrationContext,
        POB_PRE_OPERATION_INFORMATION PreInfo
    ) {
        ACCESS_MASK access = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
        
        // Verificar acesso suspeito
        if (access & SUSPICIOUS_ACCESS_MASK) {
            PEPROCESS source = (PEPROCESS)PsGetCurrentProcess();
            PEPROCESS target = (PEPROCESS)PreInfo->Object;
            
            // Log e possível bloqueio
            if (IsCheatAttempt(source, target, access)) {
                return OB_PREOP_DENY_ACCESS;
            }
        }
        
        return OB_PREOP_SUCCESS;
    }
    
    static bool IsCheatAttempt(PEPROCESS source, PEPROCESS target, ACCESS_MASK access) {
        // Verificar se alvo é processo protegido
        if (!IsProtectedProcess(target)) return false;
        
        // Verificar se fonte é suspeita
        if (IsSuspiciousProcess(source)) return true;
        
        // Verificar combinação de permissões
        return HasCheatAccessPattern(access);
    }
};
```

### BattlEye Process Scanner
```cpp
// BE process access monitoring
void BE_MonitorProcessAccess() {
    // Enumerate all handles periodically
    EnumSystemHandles();
    
    // Analyze access patterns
    AnalyzeAccessPatterns();
}

void EnumSystemHandles() {
    // Use NtQuerySystemInformation to get all handles
    // Filter for process handles with suspicious access
}

void AnalyzeAccessPatterns() {
    for (auto& handle : processHandles) {
        if (IsGameProcess(handle.targetPid)) {
            if (HasSuspiciousAccess(handle.accessMask)) {
                ReportSuspiciousAccess(handle.sourcePid, handle.targetPid);
            }
        }
    }
}

bool HasSuspiciousAccess(ACCESS_MASK access) {
    return (access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                      PROCESS_CREATE_THREAD | PROCESS_SUSPEND_RESUME));
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Callbacks |
| 2020-2024 | ⛔ Alto risco | Enumeration |
| 2025-2026 | ⛔ Crítico | AI patterns |

---

## 🎯 Lições Aprendadas

1. **Handles São Rastreados**: Toda criação de handle é monitorada.

2. **Permissões Revelam Intenção**: Acesso VM_READ/WRITE é característico.

3. **Padrões São Analisados**: Frequência e alvos de acesso são examinados.

4. **Kernel Access é Essencial**: Operar em ring 0 evita callbacks usermode.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#9]]
- [[Kernel_Handle_Creation]]
- [[Direct_Kernel_Access]]
- [[Physical_Memory_Access]]

---

*OpenProcess é completamente monitorado. Use técnicas kernel-level para acesso a processos em 2026.*