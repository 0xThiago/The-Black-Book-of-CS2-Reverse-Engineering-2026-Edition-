# 📖 Técnica 005: VirtualAllocEx

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 005: VirtualAllocEx]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Memória & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**VirtualAllocEx** é uma API do Windows usada para alocar memória em processos externos. Embora legítima, seu uso para injetar código em jogos é facilmente detectável pelos sistemas anti-cheat modernos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
LPVOID AllocateMemory(HANDLE hProcess, SIZE_T size, DWORD protection) {
    return VirtualAllocEx(hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, protection);
}

// Exemplo de uso para DLL injection
HMODULE InjectDLL(HANDLE hProcess, const char* dllPath) {
    // Alocar memória para path da DLL
    LPVOID remotePath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                      MEM_COMMIT, PAGE_READWRITE);
    
    // Escrever path na memória alocada
    WriteProcessMemory(hProcess, remotePath, dllPath, strlen(dllPath) + 1, NULL);
    
    // Alocar memória para código de injeção
    LPVOID remoteCode = VirtualAllocEx(hProcess, NULL, 1024, 
                                      MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    
    // Escrever shellcode
    WriteProcessMemory(hProcess, remoteCode, shellcode, shellcodeSize, NULL);
    
    // Executar
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteCode, 
                      remotePath, 0, NULL);
}
```

### Por que é Detectado

> [!WARNING]
> **VirtualAllocEx deixa rastros na Virtual Address Space**

#### 1. Memory Allocation Tracking
```cpp
// Sistema rastreia todas as alocações
void TrackAllocations() {
    // Hook em VirtualAllocEx
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)OriginalVirtualAllocEx, HookedVirtualAllocEx);
    DetourTransactionCommit();
}

LPVOID WINAPI HookedVirtualAllocEx(
    HANDLE hProcess,
    LPVOID lpAddress,
    SIZE_T dwSize,
    DWORD flAllocationType,
    DWORD flProtect
) {
    // Log da alocação
    LogMemoryAllocation(hProcess, lpAddress, dwSize, flProtect);
    
    // Verificar se é suspeito
    if (IsSuspiciousAllocation(hProcess, dwSize, flProtect)) {
        ReportSuspiciousActivity();
    }
    
    return OriginalVirtualAllocEx(hProcess, lpAddress, dwSize, 
                                 flAllocationType, flProtect);
}
```

#### 2. Virtual Address Space Analysis
```cpp
// Analisar espaço de endereços virtuais
void AnalyzeVAS(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi = {0};
    uintptr_t address = 0;
    
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Verificar alocações suspeitas
        if (IsSuspiciousRegion(mbi)) {
            LogSuspiciousRegion(address, mbi.RegionSize, mbi.Protect);
        }
        
        address += mbi.RegionSize;
    }
}

bool IsSuspiciousRegion(const MEMORY_BASIC_INFORMATION& mbi) {
    // PAGE_EXECUTE_READWRITE é suspeito
    if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
        return true;
    }
    
    // Grandes regiões alocadas externamente
    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
        if (mbi.RegionSize > SUSPICIOUS_SIZE_THRESHOLD) {
            return true;
        }
    }
    
    return false;
}
```

#### 3. Allocation Pattern Recognition
```cpp
// Reconhecer padrões de injeção
class AllocationPatternAnalyzer {
private:
    std::vector<ALLOCATION_EVENT> recentAllocations;
    
public:
    void OnAllocation(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD protect) {
        ALLOCATION_EVENT event = {hProcess, address, size, protect, GetTickCount()};
        recentAllocations.push_back(event);
        
        // Analisar padrões
        AnalyzePatterns();
    }
    
    void AnalyzePatterns() {
        // Padrão típico: alloc + write + create thread
        if (HasInjectionPattern()) {
            ReportDLLInjection();
        }
        
        // Padrão de shellcode: small executable allocation
        if (HasShellcodePattern()) {
            ReportCodeInjection();
        }
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Allocation hooks | Imediato | 95% |
| VAC Live | VAS analysis | < 5 min | 100% |
| BattlEye | Pattern recognition | < 30s | 98% |
| Faceit AC | Memory scanning | < 1 min | 90% |

---

## 🔄 Alternativas Seguras

### 1. Kernel Memory Allocation
```cpp
// ✅ Ring 0 memory allocation
PVOID KernelAllocateMemory(PEPROCESS targetProcess, SIZE_T size) {
    // Usar kernel APIs para alocar memória
    return ZwAllocateVirtualMemory(
        targetProcess,
        &address,
        0,
        &size,
        MEM_COMMIT,
        PAGE_EXECUTE_READWRITE
    );
}
```

### 2. APC Injection
```cpp
// ✅ Asynchronous Procedure Call injection
NTSTATUS InjectViaAPC(HANDLE threadHandle, PVOID shellcode, SIZE_T size) {
    // Alocar memória no kernel
    PVOID kernelBuffer = ExAllocatePool(NonPagedPool, size);
    memcpy(kernelBuffer, shellcode, size);
    
    // Queue APC
    KeInitializeApc(&apc, (PKTHREAD)threadHandle, OriginalApcEnvironment,
                   KernelRoutine, NULL, (PKNORMAL_ROUTINE)kernelBuffer, UserMode, NULL);
    
    KeInsertQueueApc(&apc, NULL, NULL, 0);
    
    return STATUS_SUCCESS;
}
```

### 3. Direct System Call
```cpp
// ✅ Syscall hooking bypass
class SyscallInjector {
public:
    NTSTATUS AllocateAndInject(HANDLE hProcess, PVOID buffer, SIZE_T size) {
        // Usar syscall diretamente
        return NtAllocateVirtualMemory(
            hProcess,
            &address,
            0,
            &size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Allocation Monitor
```cpp
// VAC memory allocation monitoring
class VAC_AllocationMonitor {
private:
    std::vector<MEMORY_ALLOCATION> allocations;
    
public:
    void Initialize() {
        // Hook VirtualAllocEx
        InstallHook("kernel32.dll", "VirtualAllocEx", HookedVirtualAllocEx);
        
        // Hook NtAllocateVirtualMemory
        InstallHook("ntdll.dll", "NtAllocateVirtualMemory", HookedNtAllocate);
    }
    
    LPVOID HookedVirtualAllocEx(HANDLE hProcess, LPVOID addr, SIZE_T size, 
                               DWORD type, DWORD protect) {
        // Verificar se processo alvo é jogo
        if (IsGameProcess(hProcess)) {
            // Log suspicious allocation
            LogSuspiciousAllocation(hProcess, size, protect);
            
            // Verificar padrões
            if (IsInjectionPattern(size, protect)) {
                ReportCheatDetected();
            }
        }
        
        return OriginalVirtualAllocEx(hProcess, addr, size, type, protect);
    }
};
```

### BattlEye Memory Scanner
```cpp
// BE memory region analysis
void BE_ScanMemoryRegions() {
    // Enumerate all processes
    EnumProcesses(pids, sizeof(pids), &bytesReturned);
    
    for (DWORD i = 0; i < bytesReturned / sizeof(DWORD); i++) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 
                                     FALSE, pids[i]);
        
        if (hProcess) {
            ScanProcessMemory(hProcess);
            CloseHandle(hProcess);
        }
    }
}

void ScanProcessMemory(HANDLE hProcess) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = 0;
    
    while (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi))) {
        // Check for suspicious regions
        if (IsSuspiciousMemoryRegion(mbi)) {
            ReportSuspiciousMemory(hProcess, addr, mbi.RegionSize);
        }
        
        addr += mbi.RegionSize;
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
| 2020-2024 | ⛔ Alto risco | Patterns |
| 2025-2026 | ⛔ Crítico | AI analysis |

---

## 🎯 Lições Aprendidas

1. **Alocações São Rastreadas**: Toda alocação externa deixa rastros.

2. **Padrões São Analisados**: Sequências típicas de injeção são reconhecidas.

3. **VAS é Auditado**: Espaço de endereços virtuais é completamente mapeado.

4. **Kernel-Level é Essencial**: Operar em ring 0 evita hooks usermode.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#5]]
- [[APC_Injection]]
- [[Syscall_Hooking]]
- [[Kernel_Memory_Allocation]]

---

*VirtualAllocEx é obsoleto desde 2020. Use técnicas kernel-level para alocação de memória.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
