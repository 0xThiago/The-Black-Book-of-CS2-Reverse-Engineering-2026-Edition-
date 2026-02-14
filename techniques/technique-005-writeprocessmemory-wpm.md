# 📖 Técnica 004: WriteProcessMemory (WPM)

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 004: WriteProcessMemory (WPM)]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Crítico  
> **Domínio:** Memória & Evasão  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**WriteProcessMemory** é a contrapartida de escrita da API ReadProcessMemory. Embora seja uma função legítima do sistema, escrever na memória de processos externos é uma das formas mais detectáveis de cheating em jogos modernos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
BOOL WriteMemory(HANDLE hProcess, LPVOID address, LPCVOID buffer, SIZE_T size) {
    SIZE_T bytesWritten;
    return WriteProcessMemory(hProcess, address, buffer, size, &bytesWritten);
}

// Exemplo de uso em cheat (ESP hack)
void EnableESP() {
    HANDLE hCS2 = OpenProcess(PROCESS_VM_WRITE, FALSE, GetCS2PID());
    
    // Escrever valor para ativar ESP
    BYTE enableESP = 1;
    WriteProcessMemory(hCS2, (LPVOID)(client_dll + dwESPEnabled), 
                      &enableESP, sizeof(BYTE), NULL);
}
```

### Por que é Detectado

> [!DANGER]
> **WPM deixa rastros digitais permanentes na memória**

#### 1. Memory Page Protections
```cpp
// Sistema monitora mudanças em proteções de página
void MonitorPageProtections() {
    MEMORY_BASIC_INFORMATION mbi;
    
    // Enumerar todas as regiões de memória
    for (uintptr_t addr = 0; addr < 0x7FFFFFFFFFFF; addr += mbi.RegionSize) {
        if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
            
            // Verificar se página foi modificada
            if (HasPageBeenModified(mbi.BaseAddress, mbi.RegionSize)) {
                LogMemoryModification(addr, mbi.Protect);
            }
        }
    }
}
```

#### 2. Integrity Checks
```cpp
// ACs calculam hashes de regiões críticas
class MemoryIntegrityChecker {
private:
    std::map<uintptr_t, std::string> originalHashes;
    
public:
    void Initialize() {
        // Calcular hashes iniciais
        CalculateOriginalHashes();
    }
    
    bool CheckIntegrity() {
        for (auto& [address, originalHash] : originalHashes) {
            std::string currentHash = CalculateHash(address, PAGE_SIZE);
            
            if (currentHash != originalHash) {
                ReportMemoryTampering(address);
                return false;
            }
        }
        return true;
    }
};
```

#### 3. Write Detection Callbacks
```cpp
// Kernel callbacks detectam writes
NTSTATUS MemoryWriteCallback(
    IN PVOID CallbackContext,
    IN PVOID Arg1,
    IN PVOID Arg2
) {
    PMEMORY_WRITE_INFO writeInfo = (PMEMORY_WRITE_INFO)Arg1;
    
    // Verificar se write é suspeito
    if (IsGameMemoryRegion(writeInfo->Address)) {
        if (IsExternalWrite(writeInfo->ProcessId)) {
            LogSuspiciousWrite(writeInfo);
            
            // Possivelmente bloquear
            return STATUS_ACCESS_DENIED;
        }
    }
    
    return STATUS_SUCCESS;
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory integrity | < 30s | 100% |
| VAC Live | Write callbacks | Imediato | 100% |
| BattlEye | Page monitoring | < 10s | 98% |
| Faceit AC | Hash verification | < 1 min | 95% |

---

## 🔄 Alternativas Seguras

### 1. Kernel Memory Writing
```cpp
// ✅ Ring 0 memory writing
NTSTATUS WriteProcessMemory_Kernel(PEPROCESS targetProcess, PVOID address, 
                                   PVOID buffer, SIZE_T size) {
    KAPC_STATE apcState;
    SIZE_T bytes;
    
    // Attach to target context
    KeStackAttachProcess(targetProcess, &apcState);
    
    // Direct memory write
    NTSTATUS status = MmCopyVirtualMemory(
        PsGetCurrentProcess(), buffer,
        targetProcess, address,
        size, KernelMode, &bytes
    );
    
    KeUnstackDetachProcess(&apcState);
    return status;
}
```

### 2. PTE Manipulation
```cpp
// ✅ Page Table Entry manipulation
class PTEManipulator {
private:
    CR3 cr3;
    
public:
    void WriteMemory(uintptr_t address, PVOID buffer, SIZE_T size) {
        // Map page as writable
        MapPageWritable(address);
        
        // Direct write
        memcpy((PVOID)address, buffer, size);
        
        // Restore original protection
        RestorePageProtection(address);
    }
    
private:
    void MapPageWritable(uintptr_t address) {
        // Manipulate PTE to make page writable
        ModifyPTE(address, PTE_WRITABLE);
    }
};
```

### 3. DMA Memory Writing
```cpp
// ✅ Hardware DMA writing
class DMAWriter {
private:
    PCILeech* dma;
    
public:
    template<typename T>
    void Write(uintptr_t address, T value) {
        dma->WriteMemory(address, &value, sizeof(T));
    }
    
    // Write array of bytes
    void WriteBytes(uintptr_t address, const BYTE* buffer, SIZE_T size) {
        dma->WriteMemory(address, buffer, size);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Protection
```cpp
// VAC memory integrity system
class VAC_MemoryGuard {
private:
    std::vector<MEMORY_REGION> protectedRegions;
    
public:
    void Initialize() {
        // Definir regiões críticas
        protectedRegions = {
            {client_dll, client_dll_size, "client.dll"},
            {engine_dll, engine_dll_size, "engine.dll"},
            {server_dll, server_dll_size, "server.dll"}
        };
        
        // Calcular hashes iniciais
        CalculateInitialHashes();
        
        // Instalar hooks
        InstallMemoryHooks();
    }
    
    void CheckIntegrity() {
        for (auto& region : protectedRegions) {
            if (!VerifyRegionHash(region)) {
                ReportCheatDetected(region.name);
            }
        }
    }
};
```

### BattlEye Write Detection
```cpp
// BE write monitoring
void BE_MonitorWrites() {
    // Usar ETW para monitorar writes
    EVENT_TRACE_PROPERTIES traceProps = {0};
    traceProps.Wnode.BufferSize = sizeof(EVENT_TRACE_PROPERTIES);
    traceProps.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    traceProps.LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL;
    traceProps.MaximumFileSize = 1; // 1MB
    
    // Iniciar trace de memory writes
    StartTrace(&sessionHandle, L"BE_MemoryTrace", &traceProps);
    
    // Processar eventos
    ProcessTrace(&sessionHandle, 1, NULL, NULL);
}

void ProcessMemoryWriteEvent(PEVENT_TRACE pEvent) {
    if (pEvent->Header.Class.Type == MemoryWriteEvent) {
        MEMORY_WRITE_EVENT* writeEvent = (MEMORY_WRITE_EVENT*)pEvent->MofData;
        
        // Verificar se é write suspeito
        if (IsSuspiciousWrite(writeEvent)) {
            ReportToServer(writeEvent->ProcessId);
        }
    }
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Integrity |
| 2020-2024 | ⛔ Alto risco | Callbacks |
| 2025-2026 | ⛔ Crítico | AI analysis |

---

## 🎯 Lições Aprendidas

1. **Writes Deixam Rastros**: Qualquer modificação na memória é detectável.

2. **Integrity Checks São Essenciais**: Hashes de memória previnem modificações.

3. **Kernel-Level é Necessário**: Operar em ring 0 evita detecções usermode.

4. **Padrões São Analisados**: ACs usam IA para detectar padrões de modificação.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#4]]
- [[Kernel_Memory_Access]]
- [[PTE_Manipulation]]
- [[DMA_Techniques]]

---

*WPM é completamente obsoleto. Todas as técnicas modernas usam kernel-level ou hardware access.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
