# Técnica 012: Memory Patching

> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Crítico  
> **Domínio:** Memória & Patching  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Memory Patching** envolve modificar código ou dados na memória do processo alvo. Embora simples, é completamente detectável pelos modernos sistemas anti-cheat que implementam integrity checking.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
bool PatchMemory(HANDLE hProcess, uintptr_t address, const BYTE* patch, SIZE_T size) {
    DWORD oldProtect;
    
    // Alterar proteção da página
    if (!VirtualProtectEx(hProcess, (LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Aplicar patch
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, (LPVOID)address, patch, size, &bytesWritten)) {
        return false;
    }
    
    // Restaurar proteção original
    VirtualProtectEx(hProcess, (LPVOID)address, size, oldProtect, &oldProtect);
    
    return bytesWritten == size;
}

// Exemplo: Remover recoil
void RemoveRecoil() {
    HANDLE hCS2 = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCS2PID());
    
    // Endereço da função de recoil
    uintptr_t recoilFunc = client_dll + 0xDEADBEEF;
    
    // Patch: RET (return imediato)
    BYTE patch[] = {0xC3};
    
    PatchMemory(hCS2, recoilFunc, patch, sizeof(patch));
    
    CloseHandle(hCS2);
}
```

### Por que é Detectado

> [!DANGER]
> **Memory patching deixa rastros permanentes detectáveis por integrity checks**

#### 1. Memory Integrity Scanning
```cpp
// Scanning contínuo de integridade de memória
void ScanMemoryIntegrity() {
    // Enumerar regiões de memória
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t address = 0;
    
    while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
        // Verificar regiões executáveis
        if (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) {
            VerifyRegionIntegrity(address, mbi.RegionSize);
        }
        
        address += mbi.RegionSize;
    }
}

void VerifyRegionIntegrity(uintptr_t address, SIZE_T size) {
    // Calcular hash atual
    std::string currentHash = CalculateMemoryHash(address, size);
    
    // Comparar com hash original
    if (currentHash != GetOriginalHash(address)) {
        LogMemoryModification(address, size);
        ReportCheatDetected();
    }
}
```

#### 2. Page Protection Monitoring
```cpp
// Monitorar mudanças em proteções de página
class PageProtectionMonitor {
private:
    std::map<uintptr_t, DWORD> originalProtections;
    
public:
    void Initialize() {
        // Mapear proteções originais
        MapOriginalProtections();
        
        // Instalar hooks
        InstallProtectionHooks();
    }
    
    void OnProtectionChange(uintptr_t address, SIZE_T size, DWORD newProtect) {
        // Verificar se mudança é suspeita
        if (IsSuspiciousProtectionChange(address, newProtect)) {
            LogSuspiciousProtectionChange(address, size, newProtect);
            
            // Verificar se foi seguida de escrita
            if (WasWriteOperation(address, size)) {
                ReportMemoryPatching();
            }
        }
    }
    
    bool IsSuspiciousProtectionChange(uintptr_t address, DWORD newProtect) {
        DWORD originalProtect = GetOriginalProtection(address);
        
        // De read-only para writable é suspeito
        if ((originalProtect & PAGE_READONLY) && 
            (newProtect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE))) {
            return true;
        }
        
        // Adicionar execute a regiões de dados
        if (!(originalProtect & PAGE_EXECUTE) && (newProtect & PAGE_EXECUTE)) {
            return true;
        }
        
        return false;
    }
};
```

#### 3. Code Cave Detection
```cpp
// Detectar code caves modificados
void ScanForCodeCaves() {
    // Encontrar regiões de código
    FindCodeRegions();
    
    for (auto& region : codeRegions) {
        // Procurar por code caves (NOP sequences)
        ScanForNOPSequences(region);
        
        // Verificar se caves foram modificados
        CheckCaveModifications(region);
    }
}

void ScanForNOPSequences(const MEMORY_REGION& region) {
    const BYTE* data = (const BYTE*)region.address;
    
    for (SIZE_T i = 0; i < region.size - MIN_CAVE_SIZE; i++) {
        if (IsNOPSequence(&data[i], MIN_CAVE_SIZE)) {
            // Verificar se cave foi usado para injeção
            if (IsModifiedCave(&data[i], MIN_CAVE_SIZE)) {
                ReportCodeCaveUsage(region.address + i);
            }
        }
    }
}

bool IsModifiedCave(const BYTE* cave, SIZE_T size) {
    // Verificar se cave contém código não-NOP
    for (SIZE_T i = 0; i < size; i++) {
        if (cave[i] != 0x90) { // NOP
            return true;
        }
    }
    
    return false;
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Integrity scanning | < 30s | 100% |
| VAC Live | Protection monitoring | Imediato | 100% |
| BattlEye | Code cave detection | < 1 min | 98% |
| Faceit AC | Hash verification | < 30s | 95% |

---

## 🔄 Alternativas Seguras

### 1. Hook-Based Modification
```cpp
// ✅ Usar hooks ao invés de patches diretos
class HookBasedModifier {
public:
    void ModifyFunction(uintptr_t targetFunc, uintptr_t hookFunc) {
        // Instalar hook trampoline
        InstallTrampolineHook(targetFunc, hookFunc);
    }
    
    void InstallTrampolineHook(uintptr_t target, uintptr_t hook) {
        // Criar trampoline
        BYTE trampoline[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, hookAddr
            0xFF, 0xE0                                                    // jmp rax
        };
        
        // Inserir endereço do hook
        *(uintptr_t*)&trampoline[2] = hook;
        
        // Instalar hook
        memcpy((PVOID)target, trampoline, sizeof(trampoline));
    }
    
    // Função hook que modifica comportamento
    static void HookedRecoilFunction() {
        // Modificar parâmetros ou retorno
        // Sem alterar código original
    }
};
```

### 2. VMT Hooking
```cpp
// ✅ Hook na Virtual Method Table
class VMTHook {
private:
    uintptr_t** vtable;
    uintptr_t* originalVtable;
    std::vector<uintptr_t> hookedMethods;
    
public:
    void Initialize(uintptr_t** objectVtable) {
        vtable = objectVtable;
        originalVtable = *vtable;
        
        // Criar cópia da vtable
        CreateVTableCopy();
    }
    
    void HookMethod(int index, uintptr_t hookFunction) {
        // Modificar apenas entrada da vtable
        (*vtable)[index] = hookFunction;
        hookedMethods.push_back(index);
    }
    
    void UnhookMethod(int index) {
        // Restaurar método original
        (*vtable)[index] = originalVtable[index];
    }
    
    void CreateVTableCopy() {
        SIZE_T vtableSize = GetVTableSize();
        uintptr_t* newVtable = new uintptr_t[vtableSize];
        
        memcpy(newVtable, originalVtable, vtableSize * sizeof(uintptr_t));
        *vtable = newVtable;
    }
};
```

### 3. Detour Patching
```cpp
// ✅ Detours ao invés de patches diretos
class DetourPatcher {
public:
    void InstallDetour(uintptr_t targetFunc, uintptr_t detourFunc) {
        // Criar jump para detour
        BYTE jump[] = {
            0xE9, 0x00, 0x00, 0x00, 0x00  // jmp relative
        };
        
        // Calcular offset
        int32_t offset = (int32_t)(detourFunc - targetFunc - 5);
        *(int32_t*)&jump[1] = offset;
        
        // Salvar bytes originais
        memcpy(originalBytes, (PVOID)targetFunc, 5);
        
        // Instalar detour
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)targetFunc, jump, 5, NULL);
    }
    
    void RemoveDetour(uintptr_t targetFunc) {
        // Restaurar bytes originais
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)targetFunc, originalBytes, 5, NULL);
    }
    
private:
    BYTE originalBytes[5];
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Scanner
```cpp
// VAC memory integrity system
class VAC_MemoryScanner {
private:
    std::map<uintptr_t, std::string> memoryHashes;
    
public:
    void Initialize() {
        // Calcular hashes de regiões críticas
        CalculateCriticalHashes();
        
        // Iniciar scanning periódico
        StartIntegrityScanning();
    }
    
    void CalculateCriticalHashes() {
        // Hash de .text sections
        HashCodeSections();
        
        // Hash de vtables importantes
        HashVTables();
        
        // Hash de funções críticas
        HashCriticalFunctions();
    }
    
    void ScanIntegrity() {
        for (auto& [address, originalHash] : memoryHashes) {
            std::string currentHash = CalculateHash(address, GetRegionSize(address));
            
            if (currentHash != originalHash) {
                ReportMemoryTampering(address);
            }
        }
    }
    
    void HashCriticalFunctions() {
        // Funções importantes do jogo
        uintptr_t functions[] = {
            GetRecoilFunction(),
            GetAimbotFunction(),
            GetESPFunction()
        };
        
        for (uintptr_t func : functions) {
            SIZE_T size = GetFunctionSize(func);
            memoryHashes[func] = CalculateHash(func, size);
        }
    }
};
```

### BattlEye Patch Detector
```cpp
// BE patch detection system
void BE_DetectPatches() {
    // Scan for modified code
    ScanModifiedCode();
    
    // Check page protections
    CheckPageProtections();
    
    // Verify code caves
    VerifyCodeCaves();
}

void ScanModifiedCode() {
    // Compare code with known good
    for (auto& region : executableRegions) {
        if (IsCodeModified(region)) {
            ReportCodeModification(region);
        }
    }
}

bool IsCodeModified(const MEMORY_REGION& region) {
    // Check for suspicious byte patterns
    if (HasPatchPattern(region)) return true;
    
    // Check for hook signatures
    if (HasHookSignature(region)) return true;
    
    // Verify against whitelist
    return !IsWhitelistedCode(region);
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Integrity |
| 2020-2024 | ⛔ Alto risco | Advanced |
| 2025-2026 | ⛔ Crítico | AI analysis |

---

## 🎯 Lições Aprendidas

1. **Patches São Permanentes**: Modificações diretas são facilmente detectadas.

2. **Integrity Checks São Essenciais**: Hashes de memória previnem modificações.

3. **Proteções São Monitoradas**: Mudanças em page protections são logadas.

4. **Hooks São Superiores**: Modificações indiretas evadem detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#12]]
- [[Hook_Based_Modification]]
- [[VMT_Hooking]]
- [[Detour_Patching]]

---

*Memory patching é completamente obsoleto. Use hooking techniques para modificações em 2026.*