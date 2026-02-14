# 📖 Técnica 003: ReadProcessMemory (RPM)

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 003: ReadProcessMemory (RPM)]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Memória & Evasão  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**ReadProcessMemory** é a API padrão do Windows para leitura de memória de processos externos. Embora seja uma função legítima do sistema, seu uso em cheats é facilmente detectável pelos modernos sistemas anti-cheat de 2026.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
BOOL ReadMemory(HANDLE hProcess, LPCVOID address, LPVOID buffer, SIZE_T size) {
    SIZE_T bytesRead;
    return ReadProcessMemory(hProcess, address, buffer, size, &bytesRead);
}

// Exemplo de uso em cheat
uintptr_t GetLocalPlayer() {
    HANDLE hCS2 = OpenProcess(PROCESS_VM_READ, FALSE, GetCS2PID());
    uintptr_t localPlayer;
    
    ReadProcessMemory(hCS2, (LPCVOID)(client_dll + dwLocalPlayer), 
                     &localPlayer, sizeof(uintptr_t), NULL);
    
    return localPlayer;
}
```

### Por que é Detectado

> [!WARNING]
> **ObRegisterCallbacks detecta handles com permissões de leitura/escrita**

#### 1. Object Callbacks
```cpp
// VAC/BE registram callbacks no kernel
OB_OPERATION_REGISTRATION operations[] = {
    {
        PsProcessType,              // Tipo de objeto
        OB_OPERATION_HANDLE_CREATE, // Operação
        VAC_ProcessHandleCallback,  // Callback function
        NULL
    }
};

// Callback é chamado sempre que um handle é criado
void VAC_ProcessHandleCallback(
    PVOID RegistrationContext,
    POB_PRE_OPERATION_INFORMATION PreInfo
) {
    if (PreInfo->ObjectType == PsProcessType) {
        ACCESS_MASK desiredAccess = PreInfo->Parameters->CreateHandleInformation.DesiredAccess;
        
        // PROCESS_VM_READ é suspeito
        if (desiredAccess & PROCESS_VM_READ) {
            // Log para análise posterior
            LogSuspiciousHandle(PreInfo->Object);
        }
    }
}
```

#### 2. Handle Enumeration
```cpp
// ACs enumeram handles periodicamente
void EnumerateProcessHandles(DWORD pid) {
    NTSTATUS status;
    PSYSTEM_HANDLE_INFORMATION handleInfo;
    
    // NtQuerySystemInformation com SystemHandleInformation
    status = NtQuerySystemInformation(
        SystemHandleInformation,
        handleInfo,
        bufferSize,
        &returnLength
    );
    
    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE handle = handleInfo->Handles[i];
        
        if (handle.ProcessId == pid && 
            handle.ObjectTypeIndex == ProcessObjectType) {
            
            // Verificar se handle tem PROCESS_VM_READ
            if (HasReadAccess(handle.GrantedAccess)) {
                FlagAsCheat();
            }
        }
    }
}
```

#### 3. Memory Access Patterns
```cpp
// Padrões de acesso revelam cheats
struct MemoryAccessPattern {
    uintptr_t address;
    SIZE_T size;
    DWORD timestamp;
    DWORD frequency;
};

void AnalyzeAccessPatterns() {
    // Cheat típico: ler offsets conhecidos periodicamente
    if (IsReadingKnownOffsets()) {
        ReportCheat();
    }
    
    // Acesso muito frequente = bot
    if (accessFrequency > HUMAN_THRESHOLD) {
        ReportCheat();
    }
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | ObRegisterCallbacks | Imediato | 95% |
| VAC Live | Handle enumeration | < 5 min | 100% |
| BattlEye | Kernel callbacks | Imediato | 98% |
| Faceit AC | Memory scanning | < 1 min | 90% |

---

## 🔄 Alternativas Seguras

### 1. Kernel Memory Reading
```cpp
// ✅ Ring 0 memory access
NTSTATUS ReadProcessMemory_Kernel(PEPROCESS targetProcess, PVOID address, 
                                  PVOID buffer, SIZE_T size) {
    KAPC_STATE apcState;
    SIZE_T bytes;
    
    // Attach to target context
    KeStackAttachProcess(targetProcess, &apcState);
    
    // Direct memory copy
    NTSTATUS status = MmCopyVirtualMemory(
        targetProcess, address,
        PsGetCurrentProcess(), buffer,
        size, KernelMode, &bytes
    );
    
    KeUnstackDetachProcess(&apcState);
    return status;
}
```

### 2. Physical Memory Mapping
```cpp
// ✅ Physical memory access
PVOID MapPhysicalMemory(PHYSICAL_ADDRESS physAddr, SIZE_T size) {
    return MmMapIoSpace(physAddr, size, MmNonCached);
}

PHYSICAL_ADDRESS VirtualToPhysical(PVOID va) {
    // Translate virtual to physical address
    return TranslateVirtualAddress(va, GetProcessCr3());
}
```

### 3. DMA Memory Reading
```cpp
// ✅ Hardware DMA access
class DMAMemoryReader {
private:
    PCILeech* dma;
    
public:
    template<typename T>
    T Read(uintptr_t address) {
        T value;
        dma->ReadMemory(address, &value, sizeof(T));
        return value;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Detection System
```cpp
// Como VAC detecta RPM
class VAC_MemoryProtector {
private:
    std::vector<HANDLE_CALLBACK> callbacks;
    
public:
    void Initialize() {
        // Registrar callback para handles
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
        
        if (access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)) {
            // Log suspicious activity
            LogSuspiciousAccess(PreInfo->Object, access);
            
            // Optionally deny access
            if (IsKnownCheatProcess()) {
                return OB_PREOP_DENY_ACCESS;
            }
        }
        
        return OB_PREOP_SUCCESS;
    }
};
```

### BattlEye Memory Scanner
```cpp
// BE memory protection
void BE_ScanMemoryAccess() {
    // Enumerate all handles
    EnumerateHandles();
    
    // Check for suspicious patterns
    for (auto& handle : handles) {
        if (IsCheatMemoryPattern(handle)) {
            ReportToServer(handle.processId);
        }
    }
}

bool IsCheatMemoryPattern(const SYSTEM_HANDLE& handle) {
    // Check access mask
    if (!(handle.GrantedAccess & PROCESS_VM_READ)) {
        return false;
    }
    
    // Check if target is game process
    if (!IsGameProcess(handle.ProcessId)) {
        return false;
    }
    
    // Check if source is suspicious
    return IsSuspiciousProcess(handle.SourceProcessId);
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

## 🎯 Lições Aprendidas

1. **Handles São Rastreados**: Qualquer handle com permissões especiais é logado.

2. **Callbacks São Inevitáveis**: ObRegisterCallbacks intercepta todas as operações de handle.

3. **Padrões Revelam**: Acesso frequente a offsets conhecidos é característico de cheats.

4. **Kernel Bypass**: Operar em ring 0 evita todas as detecções usermode.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#3]]
- [[Kernel_Memory_Access]]
- [[Handle_Manipulation]]
- [[DMA_Techniques]]

---

*RPM é obsoleto desde 2020. Use técnicas kernel-level para acesso à memória em 2026.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
