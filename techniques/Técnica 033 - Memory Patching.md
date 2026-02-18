# Técnica 033 - Memory Patching

> [!WARNING]
> **⚠️ NOTA DUPLICADA** — Esta nota é uma duplicata de [[Técnica 024 - Memory Patching]].
> Consulte a nota canônica para conteúdo atualizado.

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2 #duplicata

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 013 - Memory Patching]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Memory & Code  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Memory Patching** modifica código ou dados na memória do processo para alterar comportamento do jogo, como remover recoil, wallhack ou speedhack. É detectado por verificações de integridade.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class MemoryPatcher {
private:
    HANDLE hProcess;
    std::vector<PATCH_INFO> appliedPatches;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool ApplyPatch(const char* moduleName, uintptr_t offset, const std::vector<BYTE>& patchBytes) {
        // Encontrar endereço base do módulo
        uintptr_t moduleBase = GetModuleBaseAddress(moduleName);
        if (!moduleBase) return false;
        
        uintptr_t patchAddress = moduleBase + offset;
        
        // Salvar bytes originais
        std::vector<BYTE> originalBytes = ReadMemory(patchAddress, patchBytes.size());
        
        // Aplicar patch
        if (!WriteMemory(patchAddress, patchBytes)) return false;
        
        // Registrar patch aplicado
        PATCH_INFO patchInfo = {patchAddress, originalBytes, patchBytes};
        appliedPatches.push_back(patchInfo);
        
        return true;
    }
    
    bool RemovePatch(uintptr_t address) {
        // Encontrar patch aplicado
        for (auto it = appliedPatches.begin(); it != appliedPatches.end(); ++it) {
            if (it->address == address) {
                // Restaurar bytes originais
                if (WriteMemory(address, it->originalBytes)) {
                    appliedPatches.erase(it);
                    return true;
                }
                break;
            }
        }
        return false;
    }
    
    bool ApplyRecoilPatch() {
        // Encontrar função de recoil
        uintptr_t recoilFunc = FindRecoilFunction();
        if (!recoilFunc) return false;
        
        // Patch: NOP out recoil application
        std::vector<BYTE> nopPatch = {0x90, 0x90, 0x90, 0x90, 0x90}; // 5 NOPs
        return ApplyPatch("client.dll", recoilFunc - GetModuleBaseAddress("client.dll"), nopPatch);
    }
    
    bool ApplyWallhackPatch() {
        // Encontrar função de renderização
        uintptr_t renderFunc = FindRenderFunction();
        if (!renderFunc) return false;
        
        // Patch: Sempre renderizar jogadores
        std::vector<BYTE> wallhackPatch = {0xB0, 0x01}; // MOV AL, 1 (sempre verdadeiro)
        return ApplyPatch("client.dll", renderFunc - GetModuleBaseAddress("client.dll"), wallhackPatch);
    }
    
    bool ApplySpeedhackPatch() {
        // Encontrar timer do jogo
        uintptr_t timerAddr = FindGameTimer();
        if (!timerAddr) return false;
        
        // Patch: Modificar velocidade do tempo
        float speedMultiplier = 2.0f;
        std::vector<BYTE> speedPatch(sizeof(float));
        memcpy(speedPatch.data(), &speedMultiplier, sizeof(float));
        
        return ApplyPatch("engine.dll", timerAddr - GetModuleBaseAddress("engine.dll"), speedPatch);
    }
    
private:
    uintptr_t GetModuleBaseAddress(const char* moduleName) {
        // Enumerar módulos do processo
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    if (_stricmp(szModName, moduleName) == 0) {
                        return (uintptr_t)hMods[i];
                    }
                }
            }
        }
        return 0;
    }
    
    std::vector<BYTE> ReadMemory(uintptr_t address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead);
        buffer.resize(bytesRead);
        return buffer;
    }
    
    bool WriteMemory(uintptr_t address, const std::vector<BYTE>& data) {
        // Alterar proteção de memória
        DWORD oldProtect;
        if (!VirtualProtectEx(hProcess, (LPVOID)address, data.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
            return false;
        }
        
        // Escrever dados
        SIZE_T bytesWritten;
        bool result = WriteProcessMemory(hProcess, (LPVOID)address, data.data(), data.size(), &bytesWritten);
        
        // Restaurar proteção
        VirtualProtectEx(hProcess, (LPVOID)address, data.size(), oldProtect, &oldProtect);
        
        return result && bytesWritten == data.size();
    }
    
    uintptr_t FindRecoilFunction() {
        // Usar signature scanning para encontrar função de recoil
        const BYTE recoilSig[] = {0xF3, 0x0F, 0x11, 0x45, 0xFC, 0x8B, 0x45, 0xFC}; // Exemplo
        return FindPattern("client.dll", recoilSig, sizeof(recoilSig));
    }
    
    uintptr_t FindRenderFunction() {
        // Signature para função de renderização
        const BYTE renderSig[] = {0x55, 0x8B, 0xEC, 0x83, 0xE4, 0xF8, 0x81, 0xEC}; // Exemplo
        return FindPattern("client.dll", renderSig, sizeof(renderSig));
    }
    
    uintptr_t FindGameTimer() {
        // Signature para timer do jogo
        const BYTE timerSig[] = {0xDD, 0x05, 0xCC, 0xCC, 0xCC, 0xCC, 0xD9, 0xC9}; // Exemplo
        return FindPattern("engine.dll", timerSig, sizeof(timerSig));
    }
    
    uintptr_t FindPattern(const char* moduleName, const BYTE* pattern, SIZE_T patternSize) {
        uintptr_t moduleBase = GetModuleBaseAddress(moduleName);
        if (!moduleBase) return 0;
        
        // Obter tamanho do módulo
        MODULEINFO moduleInfo;
        if (!GetModuleInformation(hProcess, (HMODULE)moduleBase, &moduleInfo, sizeof(moduleInfo))) {
            return 0;
        }
        
        // Escanear memória do módulo
        const SIZE_T scanSize = moduleInfo.SizeOfImage;
        std::vector<BYTE> moduleMemory = ReadMemory(moduleBase, scanSize);
        
        for (SIZE_T i = 0; i < scanSize - patternSize; i++) {
            bool found = true;
            for (SIZE_T j = 0; j < patternSize; j++) {
                if (moduleMemory[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return moduleBase + i;
            }
        }
        
        return 0;
    }
};
```

### Signature Scanning

```cpp
// Signature scanning avançado
class SignatureScanner {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    uintptr_t FindPatternIDA(const char* moduleName, const char* idaSig) {
        // Converter signature IDA para bytes
        std::vector<BYTE> pattern;
        std::vector<bool> mask;
        
        ParseIDASignature(idaSig, pattern, mask);
        
        return FindPattern(moduleName, pattern, mask);
    }
    
    uintptr_t FindPattern(const char* moduleName, const std::vector<BYTE>& pattern, const std::vector<bool>& mask) {
        uintptr_t moduleBase = GetModuleBaseAddress(moduleName);
        if (!moduleBase) return 0;
        
        MODULEINFO moduleInfo;
        GetModuleInformation(hProcess, (HMODULE)moduleBase, &moduleInfo, sizeof(moduleInfo));
        
        std::vector<BYTE> moduleMemory = ReadMemory(moduleBase, moduleInfo.SizeOfImage);
        
        for (SIZE_T i = 0; i < moduleMemory.size() - pattern.size(); i++) {
            bool found = true;
            for (SIZE_T j = 0; j < pattern.size(); j++) {
                if (mask[j] && moduleMemory[i + j] != pattern[j]) {
                    found = false;
                    break;
                }
            }
            if (found) {
                return moduleBase + i;
            }
        }
        
        return 0;
    }
    
private:
    void ParseIDASignature(const char* idaSig, std::vector<BYTE>& pattern, std::vector<bool>& mask) {
        // Parse signature like "55 8B EC ? ? ? 83 E4 F8"
        std::istringstream iss(idaSig);
        std::string token;
        
        while (iss >> token) {
            if (token == "?") {
                pattern.push_back(0);
                mask.push_back(false);
            } else {
                pattern.push_back((BYTE)strtol(token.c_str(), NULL, 16));
                mask.push_back(true);
            }
        }
    }
    
    uintptr_t GetModuleBaseAddress(const char* moduleName) {
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    if (_stricmp(szModName, moduleName) == 0) {
                        return (uintptr_t)hMods[i];
                    }
                }
            }
        }
        return 0;
    }
    
    std::vector<BYTE> ReadMemory(uintptr_t address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        ReadProcessMemory(hProcess, (LPCVOID)address, buffer.data(), size, &bytesRead);
        buffer.resize(bytesRead);
        return buffer;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Memory patching deixa rastros de modificações na memória e mudanças de proteção**

#### 1. Memory Integrity Checking
```cpp
// Verificação de integridade de memória
class MemoryIntegrityChecker {
private:
    std::map<std::string, MODULE_CHECKSUM> moduleChecksums;
    
public:
    void Initialize() {
        // Calcular checksums iniciais dos módulos
        CalculateInitialChecksums();
    }
    
    void CheckIntegrity() {
        // Verificar checksums periodicamente
        for (auto& pair : moduleChecksums) {
            const std::string& moduleName = pair.first;
            MODULE_CHECKSUM& checksum = pair.second;
            
            uint32_t currentChecksum = CalculateModuleChecksum(moduleName);
            if (currentChecksum != checksum.originalChecksum) {
                ReportMemoryModification(moduleName, checksum.address);
            }
        }
    }
    
    void CalculateInitialChecksums() {
        // Enumerar módulos carregados
        HMODULE hMods[1024];
        DWORD cbNeeded;
        
        HANDLE hProcess = GetCurrentProcess();
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char szModName[MAX_PATH];
                if (GetModuleBaseNameA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                    MODULE_CHECKSUM checksum;
                    checksum.address = (uintptr_t)hMods[i];
                    checksum.originalChecksum = CalculateModuleChecksum(szModName);
                    
                    moduleChecksums[szModName] = checksum;
                }
            }
        }
    }
    
    uint32_t CalculateModuleChecksum(const std::string& moduleName) {
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) return 0;
        
        MODULEINFO moduleInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
            return 0;
        }
        
        // Calcular CRC32 da seção .text
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &sectionHeader[i];
            if (strcmp((char*)section->Name, ".text") == 0) {
                BYTE* sectionData = (BYTE*)hModule + section->VirtualAddress;
                return CalculateCRC32(sectionData, section->Misc.VirtualSize);
            }
        }
        
        return 0;
    }
    
    uint32_t CalculateCRC32(const BYTE* data, SIZE_T size) {
        // Implementação CRC32
        uint32_t crc = 0xFFFFFFFF;
        for (SIZE_T i = 0; i < size; i++) {
            crc = crc32_table[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        }
        return crc ^ 0xFFFFFFFF;
    }
};
```

#### 2. Page Protection Monitoring
```cpp
// Monitoramento de proteção de página
class PageProtectionMonitor {
private:
    std::map<uintptr_t, MEMORY_BASIC_INFORMATION> pageProtections;
    
public:
    void Initialize() {
        // Registrar proteções iniciais
        EnumeratePageProtections();
    }
    
    void OnVirtualProtect(uintptr_t address, SIZE_T size, DWORD newProtect) {
        // Verificar mudança suspeita
        if (IsSuspiciousProtectionChange(address, newProtect)) {
            ReportSuspiciousProtectionChange(address, size, newProtect);
        }
        
        // Atualizar registro
        UpdatePageProtection(address, size, newProtect);
    }
    
    bool IsSuspiciousProtectionChange(uintptr_t address, DWORD newProtect) {
        // Verificar se página era executável e foi modificada para RWX
        auto it = pageProtections.find(address);
        if (it != pageProtections.end()) {
            DWORD oldProtect = it->second.Protect;
            
            // De RX para RWX
            if ((oldProtect & PAGE_EXECUTE_READ) && (newProtect & PAGE_EXECUTE_READWRITE)) {
                return true;
            }
            
            // De R para RWX
            if ((oldProtect & PAGE_READONLY) && (newProtect & PAGE_EXECUTE_READWRITE)) {
                return true;
            }
        }
        
        return false;
    }
    
    void EnumeratePageProtections() {
        uintptr_t address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            pageProtections[address] = mbi;
            address += mbi.RegionSize;
        }
    }
    
    void UpdatePageProtection(uintptr_t address, SIZE_T size, DWORD newProtect) {
        // Encontrar páginas afetadas
        for (auto& pair : pageProtections) {
            uintptr_t pageAddr = pair.first;
            MEMORY_BASIC_INFORMATION& mbi = pair.second;
            
            if (address >= pageAddr && address < pageAddr + mbi.RegionSize) {
                mbi.Protect = newProtect;
                break;
            }
        }
    }
};
```

#### 3. Code Cave Detection
```cpp
// Detecção de code caves
class CodeCaveDetector {
private:
    std::set<uintptr_t> knownCodeCaves;
    
public:
    void ScanForCodeCaves(const std::string& moduleName) {
        HMODULE hModule = GetModuleHandleA(moduleName.c_str());
        if (!hModule) return;
        
        MODULEINFO moduleInfo;
        if (!GetModuleInformation(GetCurrentProcess(), hModule, &moduleInfo, sizeof(moduleInfo))) {
            return;
        }
        
        // Escanear seção .text por code caves
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &sectionHeader[i];
            if (strcmp((char*)section->Name, ".text") == 0) {
                ScanSectionForCodeCaves((BYTE*)hModule + section->VirtualAddress, section->Misc.VirtualSize);
                break;
            }
        }
    }
    
    void ScanSectionForCodeCaves(BYTE* sectionData, SIZE_T sectionSize) {
        SIZE_T caveSize = 0;
        uintptr_t caveStart = 0;
        
        for (SIZE_T i = 0; i < sectionSize; i++) {
            if (sectionData[i] == 0xCC || sectionData[i] == 0x00) { // INT3 or NULL
                if (caveSize == 0) {
                    caveStart = (uintptr_t)&sectionData[i];
                }
                caveSize++;
                
                // Cave grande o suficiente?
                if (caveSize >= MIN_CAVE_SIZE) {
                    knownCodeCaves.insert(caveStart);
                }
            } else {
                caveSize = 0;
            }
        }
    }
    
    void OnMemoryWrite(uintptr_t address, const std::vector<BYTE>& data) {
        // Verificar se escrita é em code cave conhecida
        if (knownCodeCaves.count(address)) {
            ReportCodeCaveUsage(address, data.size());
        }
        
        // Verificar se dados escritos parecem código
        if (IsExecutableCode(data)) {
            ReportExecutableCodeInjection(address);
        }
    }
    
    bool IsExecutableCode(const std::vector<BYTE>& data) {
        // Contar opcodes comuns
        int opcodeCount = 0;
        for (size_t i = 0; i < data.size() - 1; i++) {
            BYTE b1 = data[i];
            BYTE b2 = data[i + 1];
            
            if (IsCommonOpcode(b1, b2)) {
                opcodeCount++;
            }
        }
        
        return (float)opcodeCount / data.size() > EXECUTABLE_THRESHOLD;
    }
    
    bool IsCommonOpcode(BYTE b1, BYTE b2) {
        // Verificar opcodes comuns: MOV, PUSH, CALL, JMP, etc.
        return (b1 >= 0x50 && b1 <= 0x57) || // PUSH/POP registers
               (b1 >= 0xB8 && b1 <= 0xBF) || // MOV EAX/ECX/etc, imm
               (b1 == 0xE8 || b1 == 0xE9) || // CALL/JMP
               (b1 == 0xFF && (b2 & 0xF0) == 0xD0); // CALL/JMP register
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory integrity | < 30s | 85% |
| VAC Live | Page protection | Imediato | 80% |
| BattlEye | Code cave detection | < 1 min | 75% |
| Faceit AC | Signature scanning | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. Hook-Based Modification
```cpp
// ✅ Modificação via hooks
class HookBasedModifier {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InstallRecoilHook() {
        // Encontrar função de recoil
        uintptr_t recoilFunc = FindRecoilFunction();
        if (!recoilFunc) return false;
        
        // Instalar hook
        return InstallInlineHook(recoilFunc, &RecoilHook);
    }
    
    bool InstallWallhackHook() {
        // Encontrar função de renderização
        uintptr_t renderFunc = FindRenderFunction();
        if (!renderFunc) return false;
        
        return InstallInlineHook(renderFunc, &RenderHook);
    }
    
private:
    bool InstallInlineHook(uintptr_t targetFunc, void* hookFunc) {
        // Criar trampoline
        std::vector<BYTE> trampoline = CreateTrampoline(targetFunc, hookFunc);
        
        // Alocar memória para trampoline
        LPVOID trampolineAddr = VirtualAllocEx(hProcess, NULL, trampoline.size(),
                                             MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!trampolineAddr) return false;
        
        // Escrever trampoline
        WriteProcessMemory(hProcess, trampolineAddr, trampoline.data(), trampoline.size(), NULL);
        
        // Instalar hook (JMP para hook function)
        std::vector<BYTE> hookJump = CreateJumpInstruction((uintptr_t)hookFunc);
        WriteProcessMemory(hProcess, (LPVOID)targetFunc, hookJump.data(), hookJump.size(), NULL);
        
        return true;
    }
    
    std::vector<BYTE> CreateTrampoline(uintptr_t originalFunc, void* hookFunc) {
        // Salvar bytes originais + JMP de volta
        std::vector<BYTE> trampoline;
        
        // Bytes originais (5 bytes)
        std::vector<BYTE> originalBytes(5);
        ReadProcessMemory(hProcess, (LPCVOID)originalFunc, originalBytes.data(), 5, NULL);
        trampoline.insert(trampoline.end(), originalBytes.begin(), originalBytes.end());
        
        // JMP de volta para originalFunc + 5
        std::vector<BYTE> jumpBack = CreateJumpInstruction(originalFunc + 5);
        trampoline.insert(trampoline.end(), jumpBack.begin(), jumpBack.end());
        
        return trampoline;
    }
    
    std::vector<BYTE> CreateJumpInstruction(uintptr_t targetAddr) {
        std::vector<BYTE> jump = {0xE9}; // JMP rel32
        int32_t relativeAddr = (int32_t)(targetAddr - (uintptr_t)&jump[1] - 4);
        jump.insert(jump.end(), (BYTE*)&relativeAddr, (BYTE*)&relativeAddr + 4);
        return jump;
    }
    
    // Hook functions
    static void __fastcall RecoilHook() {
        // Modificar parâmetros ou retorno
        // ou simplesmente não chamar função original
    }
    
    static void __fastcall RenderHook() {
        // Sempre retornar true para visibilidade
    }
};
```

### 2. VMT Hooking
```cpp
// ✅ VMT hooking para modificação
class VMTHooker {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool HookVirtualFunction(uintptr_t vtableAddr, int functionIndex, void* hookFunc) {
        // Ler endereço da função original
        uintptr_t originalFuncAddr;
        ReadProcessMemory(hProcess, (LPCVOID)(vtableAddr + functionIndex * 8), 
                         &originalFuncAddr, sizeof(uintptr_t), NULL);
        
        // Escrever endereço do hook
        WriteProcessMemory(hProcess, (LPVOID)(vtableAddr + functionIndex * 8), 
                          &hookFunc, sizeof(uintptr_t), NULL);
        
        return true;
    }
    
    bool ApplyRecoilVMT() {
        // Encontrar VMT do jogador
        uintptr_t playerVMT = FindPlayerVMT();
        if (!playerVMT) return false;
        
        // Hook função de recoil (índice específico)
        return HookVirtualFunction(playerVMT, RECOIL_FUNCTION_INDEX, &RecoilVMT);
    }
    
    bool ApplyWallhackVMT() {
        // Encontrar VMT do renderer
        uintptr_t rendererVMT = FindRendererVMT();
        if (!rendererVMT) return false;
        
        return HookVirtualFunction(rendererVMT, RENDER_FUNCTION_INDEX, &RenderVMT);
    }
    
private:
    uintptr_t FindPlayerVMT() {
        // Encontrar ponteiro para jogador local
        // Seguir ponteiros até VMT
        return 0; // Placeholder
    }
    
    uintptr_t FindRendererVMT() {
        // Encontrar VMT do sistema de renderização
        return 0; // Placeholder
    }
    
    // VMT hook functions
    static void RecoilVMT() {
        // Não aplicar recoil
    }
    
    static void RenderVMT() {
        // Sempre renderizar
    }
};
```

### 3. Detour Patching
```cpp
// ✅ Detour patching
class DetourPatcher {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool ApplyDetourPatch(uintptr_t targetFunc, void* detourFunc) {
        // Calcular tamanho do prólogo da função
        SIZE_T prologueSize = CalculatePrologueSize(targetFunc);
        
        // Criar detour
        std::vector<BYTE> detourCode = CreateDetourCode(targetFunc, detourFunc, prologueSize);
        
        // Alocar memória para detour
        LPVOID detourAddr = VirtualAllocEx(hProcess, NULL, detourCode.size(),
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!detourAddr) return false;
        
        // Escrever detour
        WriteProcessMemory(hProcess, detourAddr, detourCode.data(), detourCode.size(), NULL);
        
        // Instalar JMP no início da função original
        std::vector<BYTE> jumpToDetour = CreateJumpInstruction((uintptr_t)detourAddr);
        WriteProcessMemory(hProcess, (LPVOID)targetFunc, jumpToDetour.data(), jumpToDetour.size(), NULL);
        
        return true;
    }
    
private:
    SIZE_T CalculatePrologueSize(uintptr_t functionAddr) {
        // Analisar prólogo da função para encontrar ponto seguro para hook
        std::vector<BYTE> code(20);
        ReadProcessMemory(hProcess, (LPCVOID)functionAddr, code.data(), code.size(), NULL);
        
        // Encontrar primeira instrução completa
        return 5; // Placeholder - normalmente 5 bytes para JMP
    }
    
    std::vector<BYTE> CreateDetourCode(uintptr_t originalFunc, void* detourFunc, SIZE_T prologueSize) {
        std::vector<BYTE> detour;
        
        // Executar prólogo original
        std::vector<BYTE> prologue(prologueSize);
        ReadProcessMemory(hProcess, (LPCVOID)originalFunc, prologue.data(), prologueSize, NULL);
        detour.insert(detour.end(), prologue.begin(), prologue.end());
        
        // JMP para detour function
        std::vector<BYTE> jumpToDetour = CreateJumpInstruction((uintptr_t)detourFunc);
        detour.insert(detour.end(), jumpToDetour.begin(), jumpToDetour.end());
        
        return detour;
    }
    
    std::vector<BYTE> CreateJumpInstruction(uintptr_t targetAddr) {
        std::vector<BYTE> jump = {0xE9}; // JMP rel32
        // Calcular offset relativo
        int32_t offset = (int32_t)(targetAddr - ((uintptr_t)&jump[0] + 5));
        jump.insert(jump.end(), (BYTE*)&offset, (BYTE*)&offset + 4);
        return jump;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Patching Detection
```cpp
// VAC memory patching detection
class VAC_MemoryPatchDetector {
private:
    MemoryIntegrityChecker integrityChecker;
    PageProtectionMonitor protectionMonitor;
    CodeCaveDetector caveDetector;
    
public:
    void Initialize() {
        integrityChecker.Initialize();
        protectionMonitor.Initialize();
        caveDetector.Initialize();
    }
    
    void OnProcessAttach(HANDLE hProcess) {
        // Começar verificações
        StartIntegrityChecks(hProcess);
    }
    
    void OnVirtualProtect(LPVOID address, SIZE_T size, DWORD newProtect) {
        protectionMonitor.OnVirtualProtect((uintptr_t)address, size, newProtect);
    }
    
    void OnMemoryWrite(LPVOID address, SIZE_T size) {
        caveDetector.OnMemoryWrite((uintptr_t)address, size);
    }
    
    void PeriodicIntegrityCheck() {
        integrityChecker.CheckIntegrity();
    }
};
```

### BattlEye Memory Analysis
```cpp
// BE memory patching analysis
void BE_DetectMemoryPatching() {
    // Check memory integrity
    CheckMemoryIntegrity();
    
    // Monitor page protections
    MonitorPageProtections();
    
    // Scan for code caves
    ScanForCodeCaves();
}

void CheckMemoryIntegrity() {
    // Calculate and compare checksums
    // Detect modifications
}

void MonitorPageProtections() {
    // Hook VirtualProtect
    // Detect RWX changes
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Integrity checks |
| 2025-2026 | ⚠️ Alto risco | Advanced analysis |

---

## 🎯 Lições Aprendidas

1. **Integridade é Verificada**: Checksums de módulos são calculados.

2. **Proteções São Monitoradas**: Mudanças RWX são detectadas.

3. **Code Caves São Escaneadas**: Espaços vazios são monitorados.

4. **Hooks São Mais Stealth**: Modificar VMT é menos detectável que patching direto.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#33]]
- [[Hook_Based_Modification]]
- [[VMT_Hooking]]
- [[Detour_Patching]]

---

*Memory patching tem risco moderado. Considere VMT hooking para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
