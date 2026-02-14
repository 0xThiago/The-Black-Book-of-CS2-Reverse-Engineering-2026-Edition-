# 📖 Técnica 016: VMT Hooking

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 016: VMT Hooking]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Hooks & VTables  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**VMT (Virtual Method Table) Hooking** intercepta chamadas de métodos virtuais modificando ponteiros na tabela virtual de objetos C++. É uma técnica stealth para hooking de funções de jogo.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO COM RISCO MODERADO
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
        SIZE_T vtableSize = GetVTableSize();
        uintptr_t* newVtable = new uintptr_t[vtableSize];
        
        memcpy(newVtable, originalVtable, vtableSize * sizeof(uintptr_t));
        *vtable = newVtable;
    }
    
    void HookMethod(int index, uintptr_t hookFunction) {
        if (index >= hookedMethods.size()) {
            hookedMethods.resize(index + 1);
        }
        
        hookedMethods[index] = (*vtable)[index];
        (*vtable)[index] = hookFunction;
    }
    
    void UnhookMethod(int index) {
        if (index < hookedMethods.size() && hookedMethods[index]) {
            (*vtable)[index] = hookedMethods[index];
        }
    }
    
    uintptr_t GetOriginalMethod(int index) {
        return hookedMethods[index];
    }
    
private:
    SIZE_T GetVTableSize() {
        SIZE_T size = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQuery((LPCVOID)(originalVtable + size), &mbi, sizeof(mbi))) {
            if (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ)) {
                uintptr_t* ptr = originalVtable + size;
                if (!IsValidPointer(*ptr)) {
                    break;
                }
                size++;
            } else {
                break;
            }
        }
        
        return size;
    }
    
    bool IsValidPointer(uintptr_t ptr) {
        MEMORY_BASIC_INFORMATION mbi;
        return VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi)) && 
               (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE));
    }
};

// Exemplo de uso: Hook no EndScene do Direct3D
class D3D9EndSceneHook {
private:
    VMTHook* vmtHook;
    uintptr_t originalEndScene;
    
public:
    void Initialize() {
        // Obter dispositivo D3D9
        IDirect3DDevice9* device = GetD3D9Device();
        
        // Hook EndScene (índice 42)
        vmtHook = new VMTHook();
        vmtHook->Initialize((uintptr_t**)device);
        vmtHook->HookMethod(42, (uintptr_t)HookedEndScene);
        
        originalEndScene = vmtHook->GetOriginalMethod(42);
    }
    
    static HRESULT __stdcall HookedEndScene(IDirect3DDevice9* device) {
        // Renderizar ESP
        DrawESP();
        
        // Chamar original
        return ((EndScene_t)originalEndScene)(device);
    }
    
    void Shutdown() {
        vmtHook->UnhookMethod(42);
        delete vmtHook;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **VMT hooking é detectável por vtable scanning e integrity checks**

#### 1. VTable Integrity Scanning
```cpp
// Scanning de integridade da vtable
void ScanVTableIntegrity() {
    // Enumerar objetos com vtables
    EnumObjectsWithVTables();
    
    for (auto& object : vtableObjects) {
        // Verificar integridade da vtable
        if (!VerifyVTableIntegrity(object)) {
            LogVTableTampering(object);
        }
    }
}

bool VerifyVTableIntegrity(uintptr_t object) {
    uintptr_t* vtable = *(uintptr_t**)object;
    
    // Verificar se vtable aponta para código válido
    for (int i = 0; i < MAX_VTABLE_SIZE; i++) {
        if (!IsValidCodePointer(vtable[i])) {
            return false;
        }
        
        // Verificar se método não foi hookado
        if (IsHookedMethod(vtable[i])) {
            return false;
        }
    }
    
    return true;
}

bool IsHookedMethod(uintptr_t methodAddr) {
    // Verificar se método está em região suspeita
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery((LPCVOID)methodAddr, &mbi, sizeof(mbi));
    
    // Se método não está em DLL do sistema/jogo, suspeito
    return !IsTrustedModule(mbi.AllocationBase);
}
```

#### 2. VTable Copy Detection
```cpp
// Detectar cópias de vtable
void DetectVTableCopies() {
    // Enumerar todas as vtables no processo
    EnumVTables();
    
    for (auto& vtable : vtables) {
        // Verificar se vtable é cópia
        if (IsVTableCopy(vtable)) {
            LogVTableHook(vtable);
        }
    }
}

bool IsVTableCopy(uintptr_t* vtable) {
    // Verificar se vtable está em heap (não em .rdata)
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(vtable, &mbi, sizeof(mbi));
    
    if (!(mbi.Protect & PAGE_READONLY)) {
        return true; // VTable modificável = suspeita
    }
    
    // Verificar se múltiplos objetos apontam para mesma vtable modificada
    int objectCount = CountObjectsWithVTable(vtable);
    return objectCount > 1;
}

int CountObjectsWithVTable(uintptr_t* targetVtable) {
    int count = 0;
    
    // Scan memory for objects pointing to this vtable
    uintptr_t address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    
    while (VirtualQueryEx(GetCurrentProcess(), (LPCVOID)address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Protect & PAGE_READWRITE) {
            // Scan region for vtable pointers
            ScanRegionForVTablePointers(address, mbi.RegionSize, targetVtable, count);
        }
        
        address += mbi.RegionSize;
    }
    
    return count;
}
```

#### 3. Hook Pattern Recognition
```cpp
// Reconhecer padrões de hooks
class HookPatternAnalyzer {
private:
    std::map<uintptr_t, HOOK_INFO> knownHooks;
    
public:
    void AnalyzeHookPatterns() {
        // Enumerar hooks ativos
        EnumActiveHooks();
        
        // Analisar padrões
        for (auto& hook : activeHooks) {
            if (HasSuspiciousPattern(hook)) {
                ReportSuspiciousHook(hook);
            }
        }
    }
    
    bool HasSuspiciousPattern(const HOOK_INFO& hook) {
        // Padrão 1: Hook em função crítica
        if (IsCriticalFunction(hook.originalFunction)) {
            return true;
        }
        
        // Padrão 2: Hook redireciona para heap
        if (IsHeapRedirection(hook.hookFunction)) {
            return true;
        }
        
        // Padrão 3: Múltiplos hooks na mesma vtable
        if (HasMultipleHooks(hook.vtable)) {
            return true;
        }
        
        return false;
    }
    
    bool IsCriticalFunction(uintptr_t function) {
        // Funções importantes do jogo
        static std::set<uintptr_t> criticalFunctions = {
            GetEndSceneAddress(),
            GetPresentAddress(),
            GetDrawIndexedPrimitiveAddress()
        };
        
        return criticalFunctions.count(function) > 0;
    }
    
    bool IsHeapRedirection(uintptr_t hookFunc) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((LPCVOID)hookFunc, &mbi, sizeof(mbi));
        
        return mbi.Type == MEM_PRIVATE; // Alocado dinamicamente
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | VTable scanning | < 30s | 80% |
| VAC Live | Integrity checks | Imediato | 85% |
| BattlEye | Pattern analysis | < 1 min | 75% |
| Faceit AC | Copy detection | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. IAT Hooking
```cpp
// ✅ Hook na Import Address Table
class IATHook {
private:
    HMODULE targetModule;
    std::map<std::string, uintptr_t> originalFunctions;
    
public:
    void Initialize(HMODULE module) {
        targetModule = module;
        
        // Parse IAT
        ParseIAT();
    }
    
    void HookFunction(const char* functionName, uintptr_t hookFunction) {
        // Encontrar entrada na IAT
        uintptr_t* iatEntry = FindIATEntry(functionName);
        
        if (iatEntry) {
            // Salvar original
            originalFunctions[functionName] = *iatEntry;
            
            // Aplicar hook
            *iatEntry = hookFunction;
        }
    }
    
    void UnhookFunction(const char* functionName) {
        auto it = originalFunctions.find(functionName);
        if (it != originalFunctions.end()) {
            uintptr_t* iatEntry = FindIATEntry(functionName);
            if (iatEntry) {
                *iatEntry = it->second;
            }
        }
    }
    
private:
    void ParseIAT() {
        // Parse PE file para encontrar IAT
        // Similar ao manual mapping
    }
    
    uintptr_t* FindIATEntry(const char* functionName) {
        // Encontrar entrada na IAT por nome
        // Retornar ponteiro para modificar
    }
};
```

### 2. EAT Hooking
```cpp
// ✅ Hook na Export Address Table
class EATHook {
private:
    HMODULE targetModule;
    
public:
    void Initialize(HMODULE module) {
        targetModule = module;
    }
    
    void HookExport(const char* exportName, uintptr_t hookFunction) {
        // Modificar EAT do módulo
        ModifyEATEntry(exportName, hookFunction);
    }
    
private:
    void ModifyEATEntry(const char* exportName, uintptr_t hookFunction) {
        // Parse EAT e modificar entrada
        // Mais stealth que IAT hooking
    }
};
```

### 3. Inline Hooking
```cpp
// ✅ Hook inline (detour)
class InlineHook {
private:
    uintptr_t targetFunction;
    BYTE originalBytes[HOOK_SIZE];
    BYTE hookBytes[HOOK_SIZE];
    
public:
    void InstallHook(uintptr_t target, uintptr_t hook) {
        targetFunction = target;
        
        // Salvar bytes originais
        memcpy(originalBytes, (void*)target, HOOK_SIZE);
        
        // Criar jump para hook
        CreateJump(hookBytes, hook);
        
        // Aplicar hook
        WriteMemory(target, hookBytes, HOOK_SIZE);
    }
    
    void RemoveHook() {
        // Restaurar bytes originais
        WriteMemory(targetFunction, originalBytes, HOOK_SIZE);
    }
    
private:
    void CreateJump(BYTE* buffer, uintptr_t destination) {
        // JMP rel32
        buffer[0] = 0xE9;
        *(int32_t*)&buffer[1] = (int32_t)(destination - targetFunction - 5);
    }
    
    void WriteMemory(uintptr_t address, BYTE* data, SIZE_T size) {
        DWORD oldProtect;
        VirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect);
        memcpy((void*)address, data, size);
        VirtualProtect((LPVOID)address, size, oldProtect, &oldProtect);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC VTable Scanner
```cpp
// VAC vtable tampering detection
class VAC_VTableScanner {
private:
    std::vector<VTABLE_INFO> knownVTables;
    
public:
    void Initialize() {
        // Snapshot de vtables originais
        SnapshotOriginalVTables();
        
        // Iniciar monitoring
        StartVTableMonitoring();
    }
    
    void CheckVTableIntegrity() {
        for (auto& vtableInfo : knownVTables) {
            if (IsVTableModified(vtableInfo)) {
                ReportVTableTampering(vtableInfo);
            }
        }
    }
    
    bool IsVTableModified(const VTABLE_INFO& vtableInfo) {
        uintptr_t* currentVtable = (uintptr_t*)vtableInfo.address;
        
        // Comparar com original
        for (size_t i = 0; i < vtableInfo.size; i++) {
            if (currentVtable[i] != vtableInfo.originalMethods[i]) {
                return true;
            }
        }
        
        return false;
    }
    
    void SnapshotOriginalVTables() {
        // Enumerar objetos e salvar vtables
        // Executar na inicialização
    }
};
```

### BattlEye Hook Detector
```cpp
// BE hook pattern detection
void BE_DetectHooks() {
    // Scan for vtable modifications
    ScanVTableModifications();
    
    // Check for inline hooks
    ScanInlineHooks();
    
    // Verify IAT integrity
    VerifyIATIntegrity();
}

void ScanVTableModifications() {
    // Look for copied vtables
    // Check for suspicious redirections
}

void ScanInlineHooks() {
    // Scan code sections for hook patterns
    // Look for JMP instructions to heap
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ⚠️ Risco | VTable scanning |
| 2020-2024 | ⚠️ Risco | Integrity checks |
| 2025-2026 | ⚠️ Moderado | Pattern analysis |

---

## 🎯 Lições Aprendadas

1. **VTable Copies São Visíveis**: Cópias da vtable são facilmente detectadas.

2. **Integrity Checks São Essenciais**: Verificações de integridade pegam modificações.

3. **IAT Hooking é Mais Seguro**: Hooks na tabela de imports são menos detectáveis.

4. **Inline Hooks São Diretos**: Detours diretos ainda funcionam mas são arriscados.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#16]]
- [[IAT_Hooking]]
- [[EAT_Hooking]]
- [[Inline_Hooking]]

---

*VMT hooking ainda funciona mas é detectável. Considere IAT hooking para maior stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
