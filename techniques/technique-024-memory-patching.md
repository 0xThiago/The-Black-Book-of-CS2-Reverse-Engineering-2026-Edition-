# 📖 Técnica 024: Memory Patching

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 024: Memory Patching]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Memory & Code  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Memory Patching** modifica diretamente o código executável na memória para alterar comportamento do jogo. Era usado para remover recoil, spread, ou implementar cheats simples, mas é facilmente detectado.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
class MemoryPatcher {
private:
    HANDLE hProcess;
    uintptr_t moduleBase;
    
public:
    void Initialize(HANDLE process, uintptr_t base) {
        hProcess = process;
        moduleBase = base;
    }
    
    // Patch básico - NOP out instructions
    bool ApplyNopPatch(uintptr_t offset, SIZE_T instructionSize) {
        std::vector<BYTE> nopBytes(instructionSize, 0x90); // NOP
        return WriteMemory(offset, nopBytes.data(), instructionSize);
    }
    
    // Patch condicional - modificar jump
    bool ApplyJumpPatch(uintptr_t offset, uintptr_t targetAddress) {
        // Calcular offset relativo
        ptrdiff_t relativeOffset = targetAddress - (offset + 5);
        
        // JMP rel32
        BYTE jumpBytes[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        *(DWORD*)&jumpBytes[1] = (DWORD)relativeOffset;
        
        return WriteMemory(offset, jumpBytes, 5);
    }
    
    // Patch de recoil removal
    bool RemoveRecoil() {
        // Encontrar função de recoil
        uintptr_t recoilFunc = FindRecoilFunction();
        if (!recoilFunc) return false;
        
        // NOP out a aplicação do recoil
        return ApplyNopPatch(recoilFunc + RECOIL_OFFSET, RECOIL_INSTRUCTION_SIZE);
    }
    
    // Patch de spread removal
    bool RemoveSpread() {
        uintptr_t spreadFunc = FindSpreadFunction();
        if (!spreadFunc) return false;
        
        // Modificar cálculo de spread para sempre retornar 0
        BYTE zeroSpread[] = {0xB8, 0x00, 0x00, 0x00, 0x00}; // MOV EAX, 0
        return WriteMemory(spreadFunc + SPREAD_OFFSET, zeroSpread, 5);
    }
    
    // Patch de wallhack
    bool ApplyWallhack() {
        uintptr_t renderFunc = FindRenderFunction();
        if (!renderFunc) return false;
        
        // Modificar função de render para ignorar walls
        BYTE wallhackCode[] = {
            0xB0, 0x01, // MOV AL, 1 (sempre visível)
            0xC3        // RET
        };
        
        return WriteMemory(renderFunc + VISIBILITY_OFFSET, wallhackCode, 3);
    }
    
    // Patch de speedhack
    bool ApplySpeedhack(float multiplier) {
        uintptr_t speedFunc = FindSpeedFunction();
        if (!speedFunc) return false;
        
        // Modificar multiplicador de velocidade
        return WriteMemory(speedFunc + SPEED_OFFSET, &multiplier, sizeof(float));
    }
    
    // Patch avançado com hook
    bool ApplyAdvancedPatch(uintptr_t targetAddress, BYTE* originalBytes, 
                           BYTE* patchedBytes, SIZE_T patchSize) {
        // Salvar bytes originais
        if (!ReadMemory(targetAddress, originalBytes, patchSize)) {
            return false;
        }
        
        // Aplicar patch
        if (!WriteMemory(targetAddress, patchedBytes, patchSize)) {
            return false;
        }
        
        // Instalar trampoline hook para chamadas legítimas
        return InstallTrampolineHook(targetAddress, originalBytes, patchSize);
    }
    
    // Reverter patch
    bool RevertPatch(uintptr_t targetAddress, BYTE* originalBytes, SIZE_T patchSize) {
        return WriteMemory(targetAddress, originalBytes, patchSize);
    }
    
private:
    bool WriteMemory(uintptr_t address, BYTE* buffer, SIZE_T size) {
        DWORD oldProtect;
        
        // Alterar proteção da memória
        if (!VirtualProtectEx(hProcess, (LPVOID)address, size, 
                            PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        // Escrever
        SIZE_T bytesWritten;
        bool result = WriteProcessMemory(hProcess, (LPVOID)address, buffer, 
                                       size, &bytesWritten) && bytesWritten == size;
        
        // Restaurar proteção
        VirtualProtectEx(hProcess, (LPVOID)address, size, oldProtect, &oldProtect);
        
        return result;
    }
    
    bool ReadMemory(uintptr_t address, BYTE* buffer, SIZE_T size) {
        SIZE_T bytesRead;
        return ReadProcessMemory(hProcess, (LPCVOID)address, buffer, 
                               size, &bytesRead) && bytesRead == size;
    }
    
    uintptr_t FindRecoilFunction() {
        // Usar pattern scanning para encontrar função
        // Exemplo: procurar por código relacionado a recoil
        BYTE recoilPattern[] = {0xF3, 0x0F, 0x11, 0x45, 0xFC}; // MOVSS [EBP-4], XMM0
        return FindPattern(recoilPattern, sizeof(recoilPattern));
    }
    
    uintptr_t FindSpreadFunction() {
        // Procurar função de spread
        BYTE spreadPattern[] = {0x8B, 0x45, 0x08, 0xD9, 0x00}; // MOV EAX, [EBP+8]; FLD DWORD PTR [EAX]
        return FindPattern(spreadPattern, sizeof(spreadPattern));
    }
    
    uintptr_t FindRenderFunction() {
        // Procurar função de render
        BYTE renderPattern[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF0}; // PUSH EBP; MOV EBP, ESP; AND ESP, -16
        return FindPattern(renderPattern, sizeof(renderPattern));
    }
    
    uintptr_t FindSpeedFunction() {
        // Procurar função de velocidade
        BYTE speedPattern[] = {0xF3, 0x0F, 0x59, 0x05}; // MULSS XMM0, [address]
        return FindPattern(speedPattern, sizeof(speedPattern));
    }
    
    uintptr_t FindPattern(BYTE* pattern, SIZE_T patternSize) {
        const SIZE_T bufferSize = 0x10000;
        BYTE buffer[bufferSize];
        
        // Escanear módulo
        for (uintptr_t address = moduleBase; 
             address < moduleBase + 0x1000000; // 16MB
             address += bufferSize - patternSize) {
            
            if (ReadMemory(address, buffer, bufferSize)) {
                for (SIZE_T i = 0; i < bufferSize - patternSize; i++) {
                    if (memcmp(&buffer[i], pattern, patternSize) == 0) {
                        return address + i;
                    }
                }
            }
        }
        
        return 0;
    }
    
    bool InstallTrampolineHook(uintptr_t targetAddress, BYTE* originalBytes, SIZE_T patchSize) {
        // Alocar memória para trampoline
        uintptr_t trampolineAddr = (uintptr_t)VirtualAllocEx(hProcess, NULL, 
                                                           patchSize + 5, 
                                                           MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!trampolineAddr) return false;
        
        // Escrever código original no trampoline
        if (!WriteMemory(trampolineAddr, originalBytes, patchSize)) return false;
        
        // Adicionar JMP de volta
        ptrdiff_t backJump = targetAddress - (trampolineAddr + patchSize);
        BYTE jumpBack[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        *(DWORD*)&jumpBack[1] = (DWORD)backJump;
        
        if (!WriteMemory(trampolineAddr + patchSize, jumpBack, 5)) return false;
        
        // Modificar patch para JMP para trampoline
        ptrdiff_t hookJump = trampolineAddr - (targetAddress + 5);
        BYTE hookCode[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        *(DWORD*)&hookCode[1] = (DWORD)hookJump;
        
        return WriteMemory(targetAddress, hookCode, 5);
    }
};
```

### Por que é Detectado

> [!DANGER]
> **Memory patching deixa modificações óbvias no código executável**

#### 1. Memory Integrity Checks
```cpp
// Verificação de integridade da memória
class MemoryIntegrityChecker {
private:
    std::map<uintptr_t, MEMORY_REGION> protectedRegions;
    
public:
    void Initialize() {
        // Mapear regiões críticas
        MapCriticalRegions();
        
        // Calcular hashes originais
        CalculateOriginalHashes();
    }
    
    void CheckIntegrity() {
        // Verificar todas as regiões protegidas
        for (auto& region : protectedRegions) {
            if (!VerifyRegionIntegrity(region.first, region.second)) {
                ReportMemoryModification();
            }
        }
    }
    
    bool VerifyRegionIntegrity(uintptr_t address, const MEMORY_REGION& region) {
        // Calcular hash atual
        std::string currentHash = CalculateHash(address, region.size);
        
        // Comparar com hash original
        return currentHash == region.originalHash;
    }
    
    void OnMemoryWrite(uintptr_t address, SIZE_T size) {
        // Verificar se escrita é em região protegida
        if (IsProtectedRegion(address)) {
            ReportMemoryWrite(address, size);
        }
        
        // Atualizar hash se necessário
        UpdateRegionHash(address);
    }
    
private:
    void MapCriticalRegions() {
        // Mapear .text sections, imports, etc.
        EnumerateModules();
        
        for (auto& module : loadedModules) {
            // Adicionar .text section
            MEMORY_REGION textRegion;
            textRegion.address = module.textStart;
            textRegion.size = module.textSize;
            textRegion.originalHash = CalculateHash(textRegion.address, textRegion.size);
            
            protectedRegions[textRegion.address] = textRegion;
            
            // Adicionar IAT
            MEMORY_REGION iatRegion;
            iatRegion.address = module.iatStart;
            iatRegion.size = module.iatSize;
            iatRegion.originalHash = CalculateHash(iatRegion.address, iatRegion.size);
            
            protectedRegions[iatRegion.address] = iatRegion;
        }
    }
    
    std::string CalculateHash(uintptr_t address, SIZE_T size) {
        // Calcular SHA256 do conteúdo da memória
        BYTE* buffer = new BYTE[size];
        
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, buffer, size, NULL)) {
            // Calcular hash
            // Retornar string do hash
        }
        
        delete[] buffer;
        return "";
    }
    
    bool IsProtectedRegion(uintptr_t address) {
        for (auto& region : protectedRegions) {
            if (address >= region.second.address && 
                address < region.second.address + region.second.size) {
                return true;
            }
        }
        return false;
    }
    
    void UpdateRegionHash(uintptr_t address) {
        // Encontrar região afetada
        for (auto& region : protectedRegions) {
            if (address >= region.second.address && 
                address < region.second.address + region.second.size) {
                
                // Recalcular hash
                region.second.originalHash = CalculateHash(region.second.address, 
                                                         region.second.size);
                break;
            }
        }
    }
};
```

#### 2. Code Pattern Analysis
```cpp
// Análise de padrões no código
class CodePatternAnalyzer {
private:
    std::vector<CODE_PATTERN> knownPatches;
    
public:
    void Initialize() {
        // Padrões conhecidos de patches
        knownPatches = {
            {
                .description = "Recoil removal NOP patch",
                .pattern = {0x90, 0x90, 0x90, 0x90, 0x90}, // NOP sled
                .mask = "xxxxx"
            },
            
            {
                .description = "Speed multiplier patch",
                .pattern = {0xF3, 0x0F, 0x59, 0x05, 0x00, 0x00, 0x00, 0x00}, // MULSS XMM0, [addr]
                .mask = "xxxx????" // addr modificado
            },
            
            {
                .description = "Wallhack visibility patch",
                .pattern = {0xB0, 0x01, 0xC3}, // MOV AL, 1; RET
                .mask = "xxx"
            }
        };
    }
    
    void ScanForPatches() {
        // Escanear memória executável
        ScanExecutableMemory();
        
        // Verificar se padrões suspeitos foram encontrados
        for (auto& patch : knownPatches) {
            if (FindPattern(patch.pattern, patch.mask)) {
                ReportKnownPatch(patch.description);
            }
        }
    }
    
    void OnCodeExecution(uintptr_t address) {
        // Verificar se código executado é suspeito
        if (IsSuspiciousCode(address)) {
            ReportSuspiciousExecution();
        }
    }
    
private:
    void ScanExecutableMemory() {
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        
        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE) != 0) {
                
                // Escanear região
                ScanMemoryRegion((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
            }
            
            address += mbi.RegionSize;
        }
    }
    
    void ScanMemoryRegion(uintptr_t base, SIZE_T size) {
        // Procurar por padrões conhecidos
        // Implementação simplificada
    }
    
    bool FindPattern(const std::vector<BYTE>& pattern, const std::string& mask) {
        // Implementar pattern matching
        return false;
    }
    
    bool IsSuspiciousCode(uintptr_t address) {
        // Verificar se endereço está em região writable
        // Código executado de regiões writable é suspeito
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi));
        
        return (mbi.Protect & PAGE_EXECUTE_READWRITE) != 0;
    }
};
```

#### 3. Runtime Code Verification
```cpp
// Verificação de código em runtime
class RuntimeCodeVerifier {
private:
    std::map<uintptr_t, CODE_SIGNATURE> functionSignatures;
    
public:
    void Initialize() {
        // Coletar signatures de funções críticas
        CollectFunctionSignatures();
    }
    
    void VerifyFunction(uintptr_t functionAddr) {
        auto it = functionSignatures.find(functionAddr);
        if (it != functionSignatures.end()) {
            if (!VerifySignature(functionAddr, it->second)) {
                ReportFunctionModification();
            }
        }
    }
    
    void OnFunctionCall(uintptr_t caller, uintptr_t target) {
        // Verificar se chamada é legítima
        if (!IsLegitimateCall(caller, target)) {
            ReportSuspiciousCall();
        }
        
        // Verificar função alvo
        VerifyFunction(target);
    }
    
private:
    void CollectFunctionSignatures() {
        // Coletar signatures de funções importantes
        // Usar hashing ou pattern matching
        
        // Exemplo: função de recoil
        uintptr_t recoilFunc = FindRecoilFunction();
        if (recoilFunc) {
            CODE_SIGNATURE sig;
            sig.address = recoilFunc;
            sig.hash = CalculateFunctionHash(recoilFunc);
            sig.size = GetFunctionSize(recoilFunc);
            
            functionSignatures[recoilFunc] = sig;
        }
    }
    
    bool VerifySignature(uintptr_t address, const CODE_SIGNATURE& sig) {
        // Verificar hash da função
        std::string currentHash = CalculateFunctionHash(address);
        return currentHash == sig.hash;
    }
    
    std::string CalculateFunctionHash(uintptr_t address) {
        // Calcular hash da função
        // Encontrar limites da função primeiro
        SIZE_T funcSize = GetFunctionSize(address);
        
        BYTE* buffer = new BYTE[funcSize];
        ReadProcessMemory(GetCurrentProcess(), (LPCVOID)address, buffer, funcSize, NULL);
        
        // Calcular SHA256
        // Retornar hash
        
        delete[] buffer;
        return "";
    }
    
    SIZE_T GetFunctionSize(uintptr_t address) {
        // Estimar tamanho da função
        // Analisar até RET ou JMP
        return 0x100; // Placeholder
    }
    
    bool IsLegitimateCall(uintptr_t caller, uintptr_t target) {
        // Verificar se chamada está na tabela de imports
        // Ou se é chamada interna legítima
        return true; // Placeholder
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory integrity | Imediato | 95% |
| VAC Live | Code patterns | < 30s | 90% |
| BattlEye | Runtime verification | < 1 min | 85% |
| Faceit AC | Function signatures | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Hook-Based Modifications
```cpp
// ✅ Modificações baseadas em hooks
class HookBasedModifier {
private:
    std::map<uintptr_t, HOOK_INFO> installedHooks;
    
public:
    bool InstallRecoilHook() {
        uintptr_t recoilFunc = FindRecoilFunction();
        if (!recoilFunc) return false;
        
        // Instalar hook
        return InstallHook(recoilFunc, &RecoilHook, &originalRecoil);
    }
    
    bool InstallSpreadHook() {
        uintptr_t spreadFunc = FindSpreadFunction();
        if (!spreadFunc) return false;
        
        return InstallHook(spreadFunc, &SpreadHook, &originalSpread);
    }
    
private:
    static void __fastcall RecoilHook(void* thisptr, void* edx) {
        // Modificar parâmetros ou retorno
        // Ou simplesmente não chamar função original
        
        if (!noRecoilEnabled) {
            // Chamar função original
            originalRecoil(thisptr);
        }
    }
    
    static float __fastcall SpreadHook(void* thisptr, void* edx) {
        if (noSpreadEnabled) {
            return 0.0f; // Sem spread
        } else {
            // Chamar função original
            return originalSpread(thisptr);
        }
    }
    
    bool InstallHook(uintptr_t target, void* hookFunc, void** originalFunc) {
        // Usar MinHook ou similar
        MH_STATUS status = MH_CreateHook((LPVOID)target, hookFunc, originalFunc);
        if (status != MH_OK) return false;
        
        status = MH_EnableHook((LPVOID)target);
        return status == MH_OK;
    }
};
```

### 2. Proxy DLL
```cpp
// ✅ Proxy DLL
// d3d9.dll (proxy)
#pragma comment(lib, "d3d9.lib")

HMODULE hOriginalDLL = NULL;

FARPROC GetOriginalFunction(const char* functionName) {
    if (!hOriginalDLL) {
        // Carregar DLL real
        char systemPath[MAX_PATH];
        GetSystemDirectoryA(systemPath, MAX_PATH);
        strcat(systemPath, "\\d3d9.dll");
        
        hOriginalDLL = LoadLibraryA(systemPath);
    }
    
    return GetProcAddress(hOriginalDLL, functionName);
}

// Proxy functions
IDirect3D9* WINAPI Direct3DCreate9(UINT SDKVersion) {
    static auto original = (decltype(&Direct3DCreate9))GetOriginalFunction("Direct3DCreate9");
    return original(SDKVersion);
}

HRESULT WINAPI D3DPERF_BeginEvent(D3DCOLOR col, LPCWSTR wszName) {
    static auto original = (decltype(&D3DPERF_BeginEvent))GetOriginalFunction("D3DPERF_BeginEvent");
    
    // Modificar comportamento aqui
    if (wallhackEnabled) {
        // Aplicar wallhack
        ModifyRenderState();
    }
    
    return original(col, wszName);
}

// Modificar render state para wallhack
void ModifyRenderState() {
    // Hook em EndScene ou Present
    // Modificar render state para transparência
}
```

### 3. Code Injection
```cpp
// ✅ Injeção de código
class CodeInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectRecoilCode() {
        // Criar código de recoil removal
        BYTE recoilCode[] = {
            0x55,                    // PUSH EBP
            0x8B, 0xEC,             // MOV EBP, ESP
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, 0 (no recoil)
            0x5D,                    // POP EBP
            0xC3                     // RET
        };
        
        // Alocar memória
        uintptr_t codeAddr = AllocateExecutableMemory(sizeof(recoilCode));
        if (!codeAddr) return false;
        
        // Escrever código
        if (!WriteMemory(codeAddr, recoilCode, sizeof(recoilCode))) return false;
        
        // Hook função original para pular para nosso código
        uintptr_t originalFunc = FindRecoilFunction();
        return InstallJumpHook(originalFunc, codeAddr);
    }
    
    bool InjectAimbotCode() {
        // Código de aimbot
        // Muito complexo para mostrar aqui
        return false;
    }
    
private:
    uintptr_t AllocateExecutableMemory(SIZE_T size) {
        return (uintptr_t)VirtualAllocEx(hProcess, NULL, size, 
                                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    bool InstallJumpHook(uintptr_t originalAddr, uintptr_t hookAddr) {
        // JMP hookAddr
        ptrdiff_t offset = hookAddr - (originalAddr + 5);
        BYTE jumpCode[5] = {0xE9, 0x00, 0x00, 0x00, 0x00};
        *(DWORD*)&jumpCode[1] = (DWORD)offset;
        
        return WriteMemory(originalAddr, jumpCode, 5);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Protection
```cpp
// VAC memory patching detection
class VAC_MemoryProtector {
private:
    MemoryIntegrityChecker integrityChecker;
    CodePatternAnalyzer patternAnalyzer;
    RuntimeCodeVerifier codeVerifier;
    
public:
    void Initialize() {
        integrityChecker.Initialize();
        patternAnalyzer.Initialize();
        codeVerifier.Initialize();
        
        // Instalar hooks de monitoramento
        InstallMemoryHooks();
    }
    
    void OnMemoryWrite(uintptr_t address, SIZE_T size) {
        // Verificar escrita
        integrityChecker.OnMemoryWrite(address, size);
        
        // Verificar padrões
        patternAnalyzer.ScanForPatches();
    }
    
    void OnFunctionCall(uintptr_t caller, uintptr_t target) {
        // Verificar chamada
        codeVerifier.OnFunctionCall(caller, target);
    }
    
    void PeriodicIntegrityCheck() {
        // Verificar integridade
        integrityChecker.CheckIntegrity();
        
        // Verificar código
        codeVerifier.VerifyAllFunctions();
    }
};
```

### BattlEye Code Analysis
```cpp
// BE code modification detection
void BE_DetectCodeModifications() {
    // Scan for modified code
    ScanModifiedCode();
    
    // Check function signatures
    CheckFunctionSignatures();
    
    // Monitor memory writes
    MonitorMemoryWrites();
}

void ScanModifiedCode() {
    // Look for NOP patches, jumps, etc.
    // Compare with original code
}

void CheckFunctionSignatures() {
    // Verify critical function hashes
    // Detect modifications
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Integrity checks |
| 2020-2024 | ⛔ Alto risco | Pattern analysis |
| 2025-2026 | ⛔ Crítico | Runtime verification |

---

## 🎯 Lições Aprendadas

1. **Memória é Monitorada**: Modificações no código executável são detectadas.

2. **Padrões São Conhecidos**: NOP patches e jumps são facilmente identificados.

3. **Signatures São Verificadas**: Hashes de funções são comparados.

4. **Hooks São Mais Seguros**: Modificações via hooks evitam alteração direta do código.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#24]]
- [[Hook_Based_Modifications]]
- [[Proxy_DLL]]
- [[Code_Injection]]

---

*Memory patching é completamente obsoleto. Use hooks ou proxy DLLs.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
