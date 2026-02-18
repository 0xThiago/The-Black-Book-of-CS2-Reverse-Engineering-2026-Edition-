# Técnica 026 - VMT Hooking

> [!WARNING]
> **⚠️ NOTA DUPLICADA** — Esta nota é uma duplicata de [[Técnica 017 - VMT Hooking]].
> Consulte a nota canônica para conteúdo atualizado.

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2 #duplicata

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 017 - VMT Hooking]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Hooking & Interception  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**VMT Hooking** (Virtual Method Table Hooking) intercepta chamadas de métodos virtuais modificando ponteiros na tabela de métodos virtuais. É usado para hooks em engines de jogo como Source Engine.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class VMTHook {
private:
    uintptr_t** vTable;
    uintptr_t* originalVTable;
    std::vector<uintptr_t> hookedMethods;
    
public:
    void Initialize(uintptr_t** ppVTable) {
        vTable = ppVTable;
        originalVTable = *ppVTable;
        
        // Criar cópia da VMT para backup
        SIZE_T vTableSize = GetVTableSize(originalVTable);
        originalVTable = new uintptr_t[vTableSize];
        memcpy(originalVTable, *ppVTable, vTableSize * sizeof(uintptr_t));
    }
    
    void Shutdown() {
        // Restaurar VMT original
        *vTable = originalVTable;
        
        // Limpar hooks
        for (auto& method : hookedMethods) {
            UnhookMethod(method);
        }
        
        delete[] originalVTable;
    }
    
    // Hook método virtual
    template<typename T>
    T HookMethod(int index, T hookFunction) {
        if (index < 0 || !vTable) return nullptr;
        
        // Salvar método original
        T originalMethod = (T)(*vTable)[index];
        
        // Substituir na VMT
        (*vTable)[index] = (uintptr_t)hookFunction;
        
        // Registrar hook
        hookedMethods.push_back(index);
        
        return originalMethod;
    }
    
    // Unhook método específico
    void UnhookMethod(int index) {
        if (index >= 0 && originalVTable) {
            (*vTable)[index] = originalVTable[index];
        }
    }
    
    // Obter método original
    template<typename T>
    T GetOriginalMethod(int index) {
        if (index >= 0 && originalVTable) {
            return (T)originalVTable[index];
        }
        return nullptr;
    }
    
private:
    SIZE_T GetVTableSize(uintptr_t* pVTable) {
        SIZE_T size = 0;
        
        // Contar entradas até encontrar uma inválida
        while (IsValidFunctionPointer(pVTable[size])) {
            size++;
            
            // Limite de segurança
            if (size > 1000) break;
        }
        
        return size;
    }
    
    bool IsValidFunctionPointer(uintptr_t ptr) {
        // Verificações básicas de validade
        if (ptr == 0) return false;
        
        // Verificar se aponta para código executável
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi))) {
            return (mbi.Protect & PAGE_EXECUTE) != 0;
        }
        
        return false;
    }
};

// Exemplo de uso - Hook do CreateMove (Source Engine)
class CreateMoveHook {
private:
    VMTHook vmtHook;
    typedef bool(__thiscall* CreateMove_t)(void*, float, CUserCmd*);
    CreateMove_t originalCreateMove;
    
public:
    void Initialize() {
        // Encontrar ponteiro para CHLClient
        uintptr_t* clientVTable = GetCHLClientVTable();
        if (!clientVTable) return;
        
        // Inicializar hook
        vmtHook.Initialize(&clientVTable);
        
        // Hook CreateMove (índice varia por engine version)
        originalCreateMove = vmtHook.HookMethod<CreateMove_t>(21, &HookedCreateMove);
    }
    
    void Shutdown() {
        vmtHook.Shutdown();
    }
    
private:
    static bool __fastcall HookedCreateMove(void* thisptr, void* edx, float flInputSampleTime, CUserCmd* cmd) {
        // Chamar função original primeiro
        bool result = originalCreateMove(thisptr, flInputSampleTime, cmd);
        
        // Aplicar cheats
        if (cmd && cmd->command_number) {
            // Aimbot
            if (aimbotEnabled) {
                ApplyAimbot(cmd);
            }
            
            // Anti-recoil
            if (noRecoilEnabled) {
                ApplyNoRecoil(cmd);
            }
            
            // Bunny hop
            if (bunnyHopEnabled) {
                ApplyBunnyHop(cmd);
            }
        }
        
        return result;
    }
    
    void ApplyAimbot(CUserCmd* cmd) {
        // Encontrar melhor alvo
        Vector bestTarget = FindBestTarget();
        
        // Calcular ângulos
        Vector angles = CalculateAngles(bestTarget);
        
        // Aplicar smoothing
        angles = SmoothAngles(cmd->viewangles, angles);
        
        // Setar ângulos
        cmd->viewangles = angles;
        
        // Corrigir movimento
        CorrectMovement(cmd);
    }
    
    void ApplyNoRecoil(CUserCmd* cmd) {
        // Obter recoil atual
        Vector punchAngles = GetPunchAngles();
        
        // Compensar
        cmd->viewangles -= punchAngles * 2.0f;
    }
    
    void ApplyBunnyHop(CUserCmd* cmd) {
        // Verificar se está no chão
        if (GetFlags() & FL_ONGROUND) {
            // Pular
            cmd->buttons |= IN_JUMP;
        } else {
            // Remover jump quando no ar
            cmd->buttons &= ~IN_JUMP;
        }
    }
    
    uintptr_t* GetCHLClientVTable() {
        // Encontrar CHLClient via pattern scanning ou interface
        // CHLClient* client = (CHLClient*)GetInterface("client.dll", "VClient017");
        // return *(uintptr_t**)client;
        
        return nullptr; // Placeholder
    }
};

// Hook de PaintTraverse para ESP
class PaintTraverseHook {
private:
    VMTHook vmtHook;
    typedef void(__thiscall* PaintTraverse_t)(void*, VPANEL, bool, bool);
    PaintTraverse_t originalPaintTraverse;
    
public:
    void Initialize() {
        // Encontrar VGUI surface
        uintptr_t* surfaceVTable = GetSurfaceVTable();
        if (!surfaceVTable) return;
        
        vmtHook.Initialize(&surfaceVTable);
        
        // Hook PaintTraverse
        originalPaintTraverse = vmtHook.HookMethod<PaintTraverse_t>(41, &HookedPaintTraverse);
    }
    
private:
    static void __fastcall HookedPaintTraverse(void* thisptr, void* edx, VPANEL vguiPanel, bool forceRepaint, bool allowForce) {
        // Chamar original primeiro
        originalPaintTraverse(thisptr, vguiPanel, forceRepaint, allowForce);
        
        // Verificar se é painel correto (MatSystemTopPanel)
        if (IsMatSystemTopPanel(vguiPanel)) {
            // Desenhar ESP
            DrawESP();
            
            // Desenhar menu
            DrawMenu();
        }
    }
    
    void DrawESP() {
        // Iterar entidades
        for (int i = 1; i <= GetMaxEntities(); i++) {
            // Obter entidade
            Entity* entity = GetEntity(i);
            if (!entity || !entity->IsValid() || entity->IsLocalPlayer()) continue;
            
            // Verificar se é inimigo
            if (!IsEnemy(entity)) continue;
            
            // Converter world to screen
            Vector screenPos;
            if (WorldToScreen(entity->GetOrigin(), screenPos)) {
                // Desenhar box
                DrawBox(screenPos, entity->GetHealth());
                
                // Desenhar health bar
                DrawHealthBar(screenPos, entity->GetHealth());
                
                // Desenhar nome
                DrawName(screenPos, entity->GetName());
            }
        }
    }
    
    void DrawMenu() {
        // Desenhar menu do cheat
        if (menuOpen) {
            DrawMenuBackground();
            DrawMenuItems();
        }
    }
    
    uintptr_t* GetSurfaceVTable() {
        // Encontrar via interface
        // ISurface* surface = (ISurface*)GetInterface("vguimatsurface.dll", "VGUI_Surface030");
        // return *(uintptr_t**)surface;
        
        return nullptr; // Placeholder
    }
    
    bool IsMatSystemTopPanel(VPANEL panel) {
        // Verificar nome do painel
        const char* panelName = GetPanelName(panel);
        return strcmp(panelName, "MatSystemTopPanel") == 0;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **VMT hooking modifica ponteiros de função, deixando rastros na memória**

#### 1. VMT Integrity Checks
```cpp
// Verificação de integridade da VMT
class VMTIntegrityChecker {
private:
    std::map<uintptr_t, VMT_INFO> originalVMTs;
    
public:
    void Initialize() {
        // Enumerar objetos COM/VT com VMT
        EnumerateCOMObjects();
        
        // Salvar VMTs originais
        for (auto& obj : comObjects) {
            SaveOriginalVMT(obj);
        }
    }
    
    void CheckIntegrity() {
        // Verificar todas as VMTs
        for (auto& vmtInfo : originalVMTs) {
            if (IsVMTModified(vmtInfo.first, vmtInfo.second)) {
                ReportVMTModification(vmtInfo.first);
            }
        }
    }
    
    bool IsVMTModified(uintptr_t vmtAddr, const VMT_INFO& info) {
        uintptr_t* currentVMT = (uintptr_t*)vmtAddr;
        
        // Comparar com original
        for (size_t i = 0; i < info.size; i++) {
            if (currentVMT[i] != info.originalMethods[i]) {
                return true;
            }
        }
        
        return false;
    }
    
    void OnVMTAccess(uintptr_t vmtAddr, int methodIndex) {
        // Monitorar acesso a métodos da VMT
        if (IsSuspiciousVMTAccess(vmtAddr, methodIndex)) {
            ReportSuspiciousVMTAccess(vmtAddr, methodIndex);
        }
    }
    
private:
    void EnumerateCOMObjects() {
        // Encontrar objetos COM no processo
        // D3D devices, DirectInput, etc.
    }
    
    void SaveOriginalVMT(uintptr_t objectAddr) {
        uintptr_t* vmt = *(uintptr_t**)objectAddr;
        
        VMT_INFO info;
        info.address = (uintptr_t)vmt;
        info.size = GetVMTSize(vmt);
        info.originalMethods.resize(info.size);
        
        memcpy(info.originalMethods.data(), vmt, info.size * sizeof(uintptr_t));
        
        originalVMTs[(uintptr_t)vmt] = info;
    }
    
    SIZE_T GetVMTSize(uintptr_t* vmt) {
        SIZE_T size = 0;
        
        while (size < 1000) { // Limite de segurança
            if (!IsValidFunctionPointer(vmt[size])) break;
            size++;
        }
        
        return size;
    }
    
    bool IsValidFunctionPointer(uintptr_t ptr) {
        // Mesmo que na classe VMTHook
        return false; // Placeholder
    }
    
    bool IsSuspiciousVMTAccess(uintptr_t vmtAddr, int methodIndex) {
        // Verificar se método é frequentemente hookado
        static std::set<std::pair<uintptr_t, int>> suspiciousMethods = {
            {(uintptr_t)GetD3D9DeviceVMT(), 16}, // Present
            {(uintptr_t)GetD3D9DeviceVMT(), 17}, // Reset
            {(uintptr_t)GetClientVMT(), 21},    // CreateMove
        };
        
        return suspiciousMethods.count({vmtAddr, methodIndex}) > 0;
    }
};
```

#### 2. Memory Page Protection
```cpp
// Proteção de páginas de memória
class MemoryPageProtector {
private:
    std::map<uintptr_t, MEMORY_BASIC_INFORMATION> protectedPages;
    
public:
    void ProtectVMT(uintptr_t vmtAddr) {
        // Obter informações da página
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)vmtAddr, &mbi, sizeof(mbi))) return;
        
        // Proteger página contra escrita
        DWORD oldProtect;
        VirtualProtect((LPVOID)mbi.BaseAddress, mbi.RegionSize, 
                      PAGE_READONLY, &oldProtect);
        
        // Salvar informações
        protectedPages[(uintptr_t)mbi.BaseAddress] = mbi;
        protectedPages[(uintptr_t)mbi.BaseAddress].Protect = oldProtect;
    }
    
    void OnAccessViolation(uintptr_t address) {
        // Verificar se é tentativa de modificar VMT protegida
        auto it = protectedPages.find(address & ~0xFFF); // Alinhar à página
        
        if (it != protectedPages.end()) {
            ReportVMTWriteAttempt(address);
            
            // Temporariamente permitir escrita para hook legítimo?
            // Ou bloquear completamente
        }
    }
    
    void RestoreProtection(uintptr_t vmtAddr) {
        auto it = protectedPages.find(vmtAddr & ~0xFFF);
        
        if (it != protectedPages.end()) {
            VirtualProtect((LPVOID)it->first, it->second.RegionSize,
                          it->second.Protect, &it->second.Protect);
        }
    }
};
```

#### 3. Hook Pattern Detection
```cpp
// Detecção de padrões de hook
class HookPatternDetector {
private:
    std::vector<HOOK_PATTERN> knownPatterns;
    
public:
    void Initialize() {
        // Padrões conhecidos de VMT hooks
        knownPatterns = {
            {
                .description = "VMT pointer modification",
                .pattern = {0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // MOV [addr], value
                .mask = "xx???????"
            },
            
            {
                .description = "VMT array modification",
                .pattern = {0xC7, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00}, // MOV [reg*4+addr], value
                .mask = "xxx?????"
            }
        };
    }
    
    void ScanForHookPatterns() {
        // Escanear memória executável
        ScanExecutableMemory();
        
        // Verificar código carregado
        ScanLoadedModules();
    }
    
    void OnCodeWrite(uintptr_t address, const BYTE* data, SIZE_T size) {
        // Verificar se escrita contém padrão de hook
        for (auto& pattern : knownPatterns) {
            if (MatchesPattern(data, size, pattern)) {
                ReportHookPatternDetected(pattern.description, address);
            }
        }
    }
    
private:
    void ScanExecutableMemory() {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        
        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_EXECUTE) != 0) {
                ScanMemoryRegion((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
            }
            
            address += mbi.RegionSize;
        }
    }
    
    void ScanMemoryRegion(uintptr_t base, SIZE_T size) {
        // Procurar por padrões na região
        // Implementação simplificada
    }
    
    bool MatchesPattern(const BYTE* data, SIZE_T size, const HOOK_PATTERN& pattern) {
        if (size < pattern.pattern.size()) return false;
        
        for (size_t i = 0; i < pattern.pattern.size(); i++) {
            if (pattern.mask[i] != '?' && data[i] != pattern.pattern[i]) {
                return false;
            }
        }
        
        return true;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | VMT integrity | Imediato | 85% |
| VAC Live | Memory protection | < 30s | 80% |
| BattlEye | Hook patterns | < 1 min | 75% |
| Faceit AC | Access monitoring | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. MinHook Library
```cpp
// ✅ Usando MinHook para hooks mais seguros
class SafeHookManager {
private:
    std::map<uintptr_t, HOOK_INFO> activeHooks;
    
public:
    void Initialize() {
        // Inicializar MinHook
        MH_Initialize();
    }
    
    void Shutdown() {
        // Desabilitar todos os hooks
        for (auto& hook : activeHooks) {
            MH_DisableHook((LPVOID)hook.first);
        }
        
        MH_Uninitialize();
    }
    
    template<typename T>
    bool InstallHook(uintptr_t target, T detour, T* original) {
        MH_STATUS status = MH_CreateHook((LPVOID)target, (LPVOID)detour, (LPVOID*)original);
        if (status != MH_OK) return false;
        
        status = MH_EnableHook((LPVOID)target);
        if (status != MH_OK) {
            MH_RemoveHook((LPVOID)target);
            return false;
        }
        
        // Registrar hook
        HOOK_INFO info;
        info.target = target;
        info.detour = (uintptr_t)detour;
        activeHooks[target] = info;
        
        return true;
    }
    
    void RemoveHook(uintptr_t target) {
        MH_DisableHook((LPVOID)target);
        MH_RemoveHook((LPVOID)target);
        activeHooks.erase(target);
    }
};

// Exemplo de uso seguro
class SafeCreateMoveHook {
private:
    SafeHookManager hookManager;
    typedef bool(__thiscall* CreateMove_t)(void*, float, CUserCmd*);
    CreateMove_t originalCreateMove;
    
public:
    void Initialize() {
        hookManager.Initialize();
        
        // Encontrar CreateMove
        uintptr_t createMoveAddr = FindCreateMove();
        if (!createMoveAddr) return;
        
        // Instalar hook seguro
        hookManager.InstallHook(createMoveAddr, &HookedCreateMove, &originalCreateMove);
    }
    
    void Shutdown() {
        hookManager.Shutdown();
    }
    
private:
    static bool __fastcall HookedCreateMove(void* thisptr, void* edx, float flInputSampleTime, CUserCmd* cmd) {
        // Mesmo código que antes, mas mais seguro
        bool result = originalCreateMove(thisptr, flInputSampleTime, cmd);
        
        // Aplicar cheats
        ApplyCheats(cmd);
        
        return result;
    }
    
    uintptr_t FindCreateMove() {
        // Encontrar via pattern scanning ou interface
        return 0; // Placeholder
    }
};
```

### 2. Detour Hooks
```cpp
// ✅ Hooks via detours
class DetourHookManager {
private:
    std::map<uintptr_t, DETOUR_INFO> detourHooks;
    
public:
    template<typename T>
    bool InstallDetour(uintptr_t target, T detour, T* original) {
        // Usar Microsoft Detours ou similar
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        *original = (T)target;
        DetourAttach((PVOID*)original, (PVOID)detour);
        
        LONG error = DetourTransactionCommit();
        if (error != NO_ERROR) {
            return false;
        }
        
        // Registrar detour
        DETOUR_INFO info;
        info.target = target;
        info.detour = (uintptr_t)detour;
        info.trampoline = (uintptr_t)*original;
        detourHooks[target] = info;
        
        return true;
    }
    
    void RemoveDetour(uintptr_t target) {
        auto it = detourHooks.find(target);
        if (it == detourHooks.end()) return;
        
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        
        DetourDetach((PVOID*)&it->second.trampoline, (PVOID)it->second.detour);
        
        DetourTransactionCommit();
        
        detourHooks.erase(target);
    }
};
```

### 3. IAT Hooking
```cpp
// ✅ Hook na Import Address Table
class IATHooker {
private:
    std::map<HMODULE, IAT_BACKUP> moduleBackups;
    
public:
    bool HookIATFunction(HMODULE hModule, const char* dllName, const char* functionName, uintptr_t hookFunction) {
        // Encontrar função na IAT
        uintptr_t* iatEntry = FindIATEntry(hModule, dllName, functionName);
        if (!iatEntry) return false;
        
        // Backup do original
        IAT_BACKUP backup;
        backup.module = hModule;
        backup.dllName = dllName;
        backup.functionName = functionName;
        backup.originalAddress = *iatEntry;
        moduleBackups[hModule] = backup;
        
        // Modificar IAT
        DWORD oldProtect;
        VirtualProtect(iatEntry, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect);
        *iatEntry = hookFunction;
        VirtualProtect(iatEntry, sizeof(uintptr_t), oldProtect, &oldProtect);
        
        return true;
    }
    
    void UnhookIATFunction(HMODULE hModule, const char* dllName, const char* functionName) {
        auto it = moduleBackups.find(hModule);
        if (it == moduleBackups.end()) return;
        
        uintptr_t* iatEntry = FindIATEntry(hModule, dllName, functionName);
        if (!iatEntry) return;
        
        // Restaurar original
        DWORD oldProtect;
        VirtualProtect(iatEntry, sizeof(uintptr_t), PAGE_READWRITE, &oldProtect);
        *iatEntry = it->second.originalAddress;
        VirtualProtect(iatEntry, sizeof(uintptr_t), oldProtect, &oldProtect);
        
        moduleBackups.erase(hModule);
    }
    
private:
    uintptr_t* FindIATEntry(HMODULE hModule, const char* dllName, const char* functionName) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)
            ((BYTE*)hModule + ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (importDesc->Name) {
            char* currentDllName = (char*)hModule + importDesc->Name;
            
            if (_stricmp(currentDllName, dllName) == 0) {
                // Encontrar função
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
                
                while (thunk->u1.Function) {
                    // Resolver nome da função
                    if (!(thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)) {
                        PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)
                            ((BYTE*)hModule + thunk->u1.AddressOfData);
                        
                        if (strcmp(importName->Name, functionName) == 0) {
                            return (uintptr_t*)&thunk->u1.Function;
                        }
                    }
                    
                    thunk++;
                }
            }
            
            importDesc++;
        }
        
        return nullptr;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC VMT Protection
```cpp
// VAC VMT hook detection
class VAC_VMTProtector {
private:
    VMTIntegrityChecker integrityChecker;
    MemoryPageProtector pageProtector;
    HookPatternDetector patternDetector;
    
public:
    void Initialize() {
        integrityChecker.Initialize();
        patternDetector.Initialize();
    }
    
    void ProtectCOMObjects() {
        // Proteger VMTs de objetos COM
        EnumerateCOMObjects();
        
        for (uintptr_t objAddr : comObjects) {
            uintptr_t* vmt = *(uintptr_t**)objAddr;
            pageProtector.ProtectVMT((uintptr_t)vmt);
        }
    }
    
    void OnMemoryWrite(uintptr_t address, SIZE_T size) {
        // Verificar se é tentativa de hook
        patternDetector.OnCodeWrite(address, nullptr, size);
        
        // Verificar proteção de página
        pageProtector.OnAccessViolation(address);
    }
    
    void PeriodicIntegrityCheck() {
        integrityChecker.CheckIntegrity();
    }
};
```

### BattlEye Hook Detection
```cpp
// BE hook detection
void BE_DetectVMTHooks() {
    // Scan for VMT modifications
    ScanVMTModifications();
    
    // Check hook libraries
    CheckHookLibraries();
    
    // Monitor VMT access
    MonitorVMTAccess();
}

void ScanVMTModifications() {
    // Compare current VMTs with originals
    // Detect pointer changes
}

void CheckHookLibraries() {
    // Look for MinHook, Detours, etc.
    // Check loaded modules
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Integrity checks |
| 2025-2026 | ⚠️ Alto risco | Pattern detection |

---

## 🎯 Lições Aprendadas

1. **VMTs São Monitoradas**: Modificações nos ponteiros são detectadas.

2. **Páginas São Protegidas**: Tentativas de escrita são bloqueadas.

3. **Padrões São Conhecidos**: Código de hook é identificado.

4. **Libraries Seguras Existem**: MinHook e Detours são mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#26]]
- [[MinHook_Library]]
- [[Detour_Hooks]]
- [[IAT_Hooking]]

---

*VMT hooking tem risco moderado. Use MinHook ou Detours para mais segurança.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
