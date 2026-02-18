# Técnica 027 - Manual DLL Mapping

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 015 - Manual DLL Mapping]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Injection & Loading  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Manual DLL Mapping** carrega uma DLL manualmente na memória sem usar o loader do Windows, mapeando seções, resolvendo imports e aplicando relocations. É mais avançado que reflective injection.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ManualDLLMapper {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool MapDLL(const char* dllPath) {
        // Carregar DLL localmente para análise
        HMODULE hLocalDLL = LoadLibraryA(dllPath);
        if (!hLocalDLL) return false;
        
        // Obter informações da DLL
        DLL_MAPPING_INFO mappingInfo = GetDLLMappingInfo(hLocalDLL);
        
        // Alocar memória no processo remoto
        LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, mappingInfo.sizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Mapear DLL para memória remota
        if (!MapDLLSections(hLocalDLL, mappingInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Aplicar relocations
        if (!ApplyRelocations(hLocalDLL, mappingInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Resolver imports
        if (!ResolveImports(hLocalDLL, mappingInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Proteger seções
        if (!ProtectMemorySections(hLocalDLL, mappingInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Executar TLS callbacks
        ExecuteTLSCallbacks(hLocalDLL, mappingInfo, remoteBase);
        
        // Chamar entry point
        CallEntryPoint(mappingInfo, remoteBase);
        
        FreeLibrary(hLocalDLL);
        return true;
    }
    
private:
    DLL_MAPPING_INFO GetDLLMappingInfo(HMODULE hDLL) {
        DLL_MAPPING_INFO info = {0};
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hDLL + dosHeader->e_lfanew);
        
        info.sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
        info.entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
        info.imageBase = ntHeader->OptionalHeader.ImageBase;
        
        // Encontrar seções
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        info.sections.resize(ntHeader->FileHeader.NumberOfSections);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            SECTION_INFO section;
            section.name = std::string((char*)sectionHeader[i].Name);
            section.virtualAddress = sectionHeader[i].VirtualAddress;
            section.sizeOfRawData = sectionHeader[i].SizeOfRawData;
            section.pointerToRawData = sectionHeader[i].PointerToRawData;
            section.characteristics = sectionHeader[i].Characteristics;
            
            info.sections[i] = section;
        }
        
        return info;
    }
    
    bool MapDLLSections(HMODULE hLocalDLL, const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        
        // Mapear headers
        SIZE_T headersSize = ntHeader->OptionalHeader.SizeOfHeaders;
        if (!WriteProcessMemory(hProcess, remoteBase, hLocalDLL, headersSize, NULL)) {
            return false;
        }
        
        // Mapear seções
        for (const auto& section : info.sections) {
            if (section.sizeOfRawData == 0) continue;
            
            LPVOID sectionBase = (LPVOID)((BYTE*)remoteBase + section.virtualAddress);
            LPVOID sectionData = (LPVOID)((BYTE*)hLocalDLL + section.pointerToRawData);
            
            if (!WriteProcessMemory(hProcess, sectionBase, sectionData, 
                                  section.sizeOfRawData, NULL)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool ApplyRelocations(HMODULE hLocalDLL, const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        
        PIMAGE_DATA_DIRECTORY relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size == 0) return true; // Sem relocations
        
        uintptr_t delta = (uintptr_t)remoteBase - info.imageBase;
        if (delta == 0) return true; // Base correta
        
        PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)hLocalDLL + relocDir->VirtualAddress);
        
        while (relocBlock->VirtualAddress != 0) {
            DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD relocEntries = (PWORD)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
            
            for (DWORD i = 0; i < numEntries; i++) {
                WORD relocEntry = relocEntries[i];
                WORD type = relocEntry >> 12;
                WORD offset = relocEntry & 0xFFF;
                
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    uintptr_t patchAddr = (uintptr_t)remoteBase + relocBlock->VirtualAddress + offset;
                    uintptr_t* targetAddr = (uintptr_t*)patchAddr;
                    
                    // Ler valor atual
                    uintptr_t currentValue;
                    if (!ReadProcessMemory(hProcess, (LPCVOID)patchAddr, &currentValue, sizeof(uintptr_t), NULL)) {
                        return false;
                    }
                    
                    // Aplicar relocation
                    currentValue += delta;
                    
                    // Escrever de volta
                    if (!WriteProcessMemory(hProcess, (LPVOID)patchAddr, &currentValue, sizeof(uintptr_t), NULL)) {
                        return false;
                    }
                }
            }
            
            relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock);
        }
        
        return true;
    }
    
    bool ResolveImports(HMODULE hLocalDLL, const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        
        PIMAGE_DATA_DIRECTORY importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->Size == 0) return true;
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hLocalDLL + importDir->VirtualAddress);
        
        while (importDesc->Name != 0) {
            char* dllName = (char*)hLocalDLL + importDesc->Name;
            
            // Carregar DLL no processo remoto (se necessário)
            HMODULE hRemoteDLL = GetModuleHandleA(dllName); // Assume já carregada
            if (!hRemoteDLL) {
                // Carregar DLL no processo remoto
                hRemoteDLL = LoadLibraryA(dllName);
                if (!hRemoteDLL) return false;
            }
            
            // Resolver imports por nome
            if (importDesc->OriginalFirstThunk != 0) {
                PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hLocalDLL + importDesc->OriginalFirstThunk);
                PIMAGE_THUNK_DATA funcThunk = (PIMAGE_THUNK_DATA)((BYTE*)hLocalDLL + importDesc->FirstThunk);
                
                while (thunk->u1.AddressOfData != 0) {
                    uintptr_t functionAddr = 0;
                    
                    if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                        // Import por ordinal
                        functionAddr = (uintptr_t)GetProcAddress(hRemoteDLL, (char*)(thunk->u1.Ordinal & 0xFFFF));
                    } else {
                        // Import por nome
                        PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)hLocalDLL + thunk->u1.AddressOfData);
                        functionAddr = (uintptr_t)GetProcAddress(hRemoteDLL, importName->Name);
                    }
                    
                    if (!functionAddr) return false;
                    
                    // Escrever endereço na IAT remota
                    uintptr_t remoteIATAddr = (uintptr_t)remoteBase + ((BYTE*)&funcThunk->u1.Function - (BYTE*)hLocalDLL);
                    if (!WriteProcessMemory(hProcess, (LPVOID)remoteIATAddr, &functionAddr, sizeof(uintptr_t), NULL)) {
                        return false;
                    }
                    
                    thunk++;
                    funcThunk++;
                }
            }
            
            importDesc++;
        }
        
        return true;
    }
    
    bool ProtectMemorySections(HMODULE hLocalDLL, const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &sectionHeader[i];
            
            DWORD protect = 0;
            DWORD characteristics = section->Characteristics;
            
            if (characteristics & IMAGE_SCN_MEM_EXECUTE) {
                protect = PAGE_EXECUTE;
            }
            if (characteristics & IMAGE_SCN_MEM_READ) {
                protect |= PAGE_READONLY;
            }
            if (characteristics & IMAGE_SCN_MEM_WRITE) {
                protect |= PAGE_READWRITE;
            }
            
            if (protect != 0) {
                uintptr_t sectionAddr = (uintptr_t)remoteBase + section->VirtualAddress;
                SIZE_T sectionSize = section->Misc.VirtualSize;
                
                DWORD oldProtect;
                if (!VirtualProtectEx(hProcess, (LPVOID)sectionAddr, sectionSize, protect, &oldProtect)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    void ExecuteTLSCallbacks(HMODULE hLocalDLL, const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        
        PIMAGE_DATA_DIRECTORY tlsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        if (tlsDir->Size == 0) return;
        
        PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)((BYTE*)hLocalDLL + tlsDir->VirtualAddress);
        
        if (tlsDirectory->AddressOfCallBacks != 0) {
            PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)((BYTE*)hLocalDLL + tlsDirectory->AddressOfCallBacks);
            
            while (*callbacks != NULL) {
                // Executar callback no contexto remoto
                ExecuteTLSCallback(*callbacks, remoteBase);
                callbacks++;
            }
        }
    }
    
    void ExecuteTLSCallback(LPVOID callbackAddr, LPVOID remoteBase) {
        // Criar thread para executar callback
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                          (LPTHREAD_START_ROUTINE)callbackAddr,
                                          remoteBase, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }
    
    void CallEntryPoint(const DLL_MAPPING_INFO& info, LPVOID remoteBase) {
        uintptr_t entryPointAddr = (uintptr_t)remoteBase + info.entryPoint;
        
        // Chamar DllMain
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)entryPointAddr,
                                          remoteBase, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Manual mapping deixa rastros de alocações grandes e modificações na memória**

#### 1. Memory Allocation Pattern Analysis
```cpp
// Análise de padrões de alocação de memória
class MemoryAllocationAnalyzer {
private:
    std::map<HANDLE, std::vector<ALLOCATION_RECORD>> allocationHistory;
    
public:
    void OnVirtualAlloc(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect) {
        ALLOCATION_RECORD record = {address, size, allocationType, protect, GetTickCount()};
        allocationHistory[hProcess].push_back(record);
        
        // Analisar padrão
        AnalyzeAllocationPattern(hProcess, record);
    }
    
    void AnalyzeAllocationPattern(HANDLE hProcess, const ALLOCATION_RECORD& record) {
        // Verificar tamanho suspeito (múltiplo de 0x1000, tamanho de imagem PE)
        if (IsPESize(record.size)) {
            ReportPESizeAllocation(hProcess, record);
        }
        
        // Verificar proteção RWX
        if ((record.protect & PAGE_EXECUTE_READWRITE) == PAGE_EXECUTE_READWRITE) {
            ReportRWXAllocation(hProcess, record);
        }
        
        // Verificar sequência de alocações
        if (HasDLLMappingPattern(hProcess)) {
            ReportDLLMappingDetected(hProcess);
        }
    }
    
    bool IsPESize(SIZE_T size) {
        // Tamanhos típicos de DLLs (múltiplos de 0x1000)
        return (size >= 0x10000) && (size <= 0x1000000) && ((size & 0xFFF) == 0);
    }
    
    bool HasDLLMappingPattern(HANDLE hProcess) {
        auto& allocations = allocationHistory[hProcess];
        if (allocations.size() < 2) return false;
        
        // Procurar por: alocação grande RWX + pequenas alocações subsequentes
        bool hasLargeRWX = false;
        int smallAllocCount = 0;
        
        for (auto& alloc : allocations) {
            if (alloc.size >= LARGE_ALLOCATION_THRESHOLD && 
                (alloc.protect & PAGE_EXECUTE_READWRITE)) {
                hasLargeRWX = true;
            } else if (alloc.size < SMALL_ALLOCATION_THRESHOLD) {
                smallAllocCount++;
            }
        }
        
        return hasLargeRWX && smallAllocCount >= 2;
    }
    
    void OnVirtualFree(HANDLE hProcess, LPVOID address) {
        // Remover da história
        auto& allocations = allocationHistory[hProcess];
        allocations.erase(
            std::remove_if(allocations.begin(), allocations.end(),
                [address](const ALLOCATION_RECORD& record) {
                    return record.address == address;
                }),
            allocations.end()
        );
    }
};
```

#### 2. PE Header Detection
```cpp
// Detecção de headers PE na memória
class PEHeaderScanner {
private:
    std::set<uintptr_t> scannedRegions;
    
public:
    void ScanMemoryForPEHeaders(HANDLE hProcess) {
        // Escanear regiões de memória alocadas
        EnumerateMemoryRegions(hProcess);
        
        for (uintptr_t region : scannedRegions) {
            if (HasPEHeader(hProcess, region)) {
                ReportPEHeaderFound(hProcess, region);
            }
        }
    }
    
    bool HasPEHeader(HANDLE hProcess, uintptr_t address) {
        // Verificar MZ signature
        WORD mzSignature;
        if (!ReadProcessMemory(hProcess, (LPCVOID)address, &mzSignature, sizeof(WORD), NULL)) {
            return false;
        }
        
        if (mzSignature != IMAGE_DOS_SIGNATURE) return false;
        
        // Verificar PE signature
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)address;
        uintptr_t peOffset = address + dosHeader->e_lfanew;
        
        DWORD peSignature;
        if (!ReadProcessMemory(hProcess, (LPCVOID)peOffset, &peSignature, sizeof(DWORD), NULL)) {
            return false;
        }
        
        return peSignature == IMAGE_NT_SIGNATURE;
    }
    
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size) {
        // Adicionar à lista de regiões para escanear
        scannedRegions.insert((uintptr_t)address);
    }
    
private:
    void EnumerateMemoryRegions(HANDLE hProcess) {
        // Usar VirtualQueryEx para enumerar regiões
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        
        while (VirtualQueryEx(hProcess, (LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
                scannedRegions.insert((uintptr_t)mbi.BaseAddress);
            }
            
            address += mbi.RegionSize;
        }
    }
};
```

#### 3. Import Resolution Monitoring
```cpp
// Monitoramento de resolução de imports
class ImportResolutionMonitor {
private:
    std::map<HANDLE, std::vector<IMPORT_RESOLUTION>> importHistory;
    
public:
    void OnImportResolution(HANDLE hProcess, const char* dllName, const char* functionName, uintptr_t resolvedAddr) {
        IMPORT_RESOLUTION resolution = {dllName, functionName, resolvedAddr, GetTickCount()};
        importHistory[hProcess].push_back(resolution);
        
        // Analisar resolução
        AnalyzeImportResolution(hProcess, resolution);
    }
    
    void AnalyzeImportResolution(HANDLE hProcess, const IMPORT_RESOLUTION& resolution) {
        // Verificar se resolução aponta para memória privada
        if (IsPrivateMemoryAddress(resolution.resolvedAddr)) {
            ReportPrivateMemoryImport(hProcess, resolution);
        }
        
        // Verificar padrão de resoluções
        if (HasManualMappingPattern(hProcess)) {
            ReportManualMappingDetected(hProcess);
        }
    }
    
    bool IsPrivateMemoryAddress(uintptr_t address) {
        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) return false;
        
        return mbi.Type == MEM_PRIVATE;
    }
    
    bool HasManualMappingPattern(HANDLE hProcess) {
        auto& resolutions = importHistory[hProcess];
        if (resolutions.size() < 10) return false;
        
        // Verificar se múltiplas funções do mesmo DLL resolvem para endereços próximos
        std::map<std::string, std::vector<uintptr_t>> dllResolutions;
        
        for (auto& res : resolutions) {
            dllResolutions[res.dllName].push_back(res.resolvedAddr);
        }
        
        for (auto& dll : dllResolutions) {
            if (dll.second.size() >= 5) {
                // Verificar se endereços estão agrupados (manual mapping)
                if (AreAddressesGrouped(dll.second)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool AreAddressesGrouped(const std::vector<uintptr_t>& addresses) {
        if (addresses.size() < 2) return false;
        
        // Calcular range
        uintptr_t minAddr = *std::min_element(addresses.begin(), addresses.end());
        uintptr_t maxAddr = *std::max_element(addresses.begin(), addresses.end());
        
        // Se range é pequeno comparado ao número de endereços, estão agrupados
        return (maxAddr - minAddr) < (addresses.size() * GROUPING_THRESHOLD);
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory patterns | < 30s | 80% |
| VAC Live | PE header scan | Imediato | 85% |
| BattlEye | Import monitoring | < 1 min | 90% |
| Faceit AC | Allocation analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Process Hollowing
```cpp
// ✅ Process hollowing (mais avançado)
class ProcessHollower {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool HollowProcess(const char* targetPath, const char* replacementPath) {
        // Criar processo suspenso
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        if (!CreateProcessA(targetPath, NULL, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }
        
        // Obter contexto da thread principal
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &context);
        
        // Ler imagem do processo
        PVOID imageBase = GetProcessImageBase(pi.hProcess);
        
        // Desmapear imagem original
        if (!UnmapViewOfSection(pi.hProcess, imageBase)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        
        // Mapear nova imagem
        if (!MapNewImage(pi.hProcess, replacementPath, imageBase)) {
            TerminateProcess(pi.hProcess, 0);
            return false;
        }
        
        // Atualizar contexto
        context.Rax = (uintptr_t)imageBase; // Novo entry point
        
        SetThreadContext(pi.hThread, &context);
        
        // Resumir thread
        ResumeThread(pi.hThread);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }
    
private:
    PVOID GetProcessImageBase(HANDLE hProcess) {
        // Ler PEB para encontrar image base
        PROCESS_BASIC_INFORMATION pbi;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
            return NULL;
        }
        
        PEB peb;
        if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), NULL)) {
            return NULL;
        }
        
        return peb.ImageBaseAddress;
    }
    
    bool MapNewImage(HANDLE hProcess, const char* imagePath, PVOID baseAddress) {
        // Carregar imagem
        std::vector<BYTE> imageData = LoadFile(imagePath);
        if (imageData.empty()) return false;
        
        // Parse PE
        PIMAGE_NT_HEADER ntHeader = GetNTHeader(imageData);
        
        // Alocar memória
        PVOID newBase = VirtualAllocEx(hProcess, baseAddress, ntHeader->OptionalHeader.SizeOfImage,
                                     MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newBase) return false;
        
        // Mapear headers
        WriteProcessMemory(hProcess, newBase, imageData.data(), ntHeader->OptionalHeader.SizeOfHeaders, NULL);
        
        // Mapear seções
        MapImageSections(hProcess, imageData, ntHeader, newBase);
        
        // Aplicar relocations
        ApplyImageRelocations(hProcess, imageData, ntHeader, newBase);
        
        // Resolver imports
        ResolveImageImports(hProcess, imageData, ntHeader, newBase);
        
        return true;
    }
};
```

### 2. Atom Bombing
```cpp
// ✅ Atom bombing injection
class AtomBomber {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool AtomBombInject(const char* dllPath) {
        // Criar atom com path da DLL
        ATOM atom = CreateAtomA(dllPath);
        if (!atom) return false;
        
        // Encontrar thread do processo
        DWORD threadId = FindProcessThread();
        if (!threadId) {
            DeleteAtom(atom);
            return false;
        }
        
        // Postar mensagem para thread
        PostThreadMessage(threadId, WM_USER, atom, 0);
        
        // Aguardar processamento
        Sleep(100);
        
        // Limpar
        DeleteAtom(atom);
        
        return true;
    }
    
private:
    DWORD FindProcessThread() {
        // Encontrar thread adequada no processo alvo
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD processId = GetProcessId(hProcess);
        DWORD threadId = 0;
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    threadId = te.th32ThreadID;
                    break;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return threadId;
    }
};
```

### 3. Section Injection
```cpp
// ✅ Injeção em seção existente
class SectionInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectIntoSection(const char* dllPath) {
        // Encontrar seção code (.text) do processo
        MODULEINFO moduleInfo = GetMainModuleInfo();
        
        // Encontrar espaço vazio na seção
        uintptr_t injectionPoint = FindInjectionPoint(moduleInfo);
        if (!injectionPoint) return false;
        
        // Criar shellcode para LoadLibrary
        std::vector<BYTE> shellcode = CreateLoadLibraryShellcode(dllPath);
        
        // Injetar shellcode
        if (!WriteProcessMemory(hProcess, (LPVOID)injectionPoint, 
                              shellcode.data(), shellcode.size(), NULL)) {
            return false;
        }
        
        // Executar shellcode
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0,
                                          (LPTHREAD_START_ROUTINE)injectionPoint,
                                          NULL, 0, NULL);
        
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        
        return true;
    }
    
private:
    MODULEINFO GetMainModuleInfo() {
        // Obter informações do módulo principal
        MODULEINFO info = {0};
        HMODULE hModule = GetModuleHandle(NULL);
        GetModuleInformation(GetCurrentProcess(), hModule, &info, sizeof(info));
        return info;
    }
    
    uintptr_t FindInjectionPoint(const MODULEINFO& moduleInfo) {
        // Encontrar espaço em .text section
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)moduleInfo.lpBaseOfDll;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)moduleInfo.lpBaseOfDll + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        
        // Encontrar .text section
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionHeader[i].Name, ".text") == 0) {
                // Encontrar espaço vazio no final da seção
                uintptr_t sectionEnd = (uintptr_t)moduleInfo.lpBaseOfDll + 
                                     sectionHeader[i].VirtualAddress + 
                                     sectionHeader[i].Misc.VirtualSize;
                
                return sectionEnd - 0x1000; // Espaço antes do final
            }
        }
        
        return 0;
    }
    
    std::vector<BYTE> CreateLoadLibraryShellcode(const char* dllPath) {
        // Shellcode para LoadLibrary
        std::vector<BYTE> shellcode;
        
        // PUSH dllPath
        shellcode.push_back(0x68);
        uintptr_t pathAddr = 0; // Placeholder - seria alocado separadamente
        shellcode.insert(shellcode.end(), (BYTE*)&pathAddr, (BYTE*)&pathAddr + 4);
        
        // MOV EAX, LoadLibraryA
        shellcode.push_back(0xB8);
        uintptr_t loadLibraryAddr = (uintptr_t)LoadLibraryA;
        shellcode.insert(shellcode.end(), (BYTE*)&loadLibraryAddr, (BYTE*)&loadLibraryAddr + 4);
        
        // CALL EAX
        shellcode.push_back(0xFF);
        shellcode.push_back(0xD0);
        
        // RET
        shellcode.push_back(0xC3);
        
        return shellcode;
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Manual Mapping Detection
```cpp
// VAC manual mapping detection
class VAC_MappingDetector {
private:
    MemoryAllocationAnalyzer allocAnalyzer;
    PEHeaderScanner peScanner;
    ImportResolutionMonitor importMonitor;
    
public:
    void Initialize() {
        allocAnalyzer.Initialize();
        peScanner.Initialize();
        importMonitor.Initialize();
    }
    
    void OnProcessAttach(HANDLE hProcess) {
        // Começar monitoramento
        StartMonitoring(hProcess);
    }
    
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD type, DWORD protect) {
        allocAnalyzer.OnVirtualAlloc(hProcess, address, size, type, protect);
        peScanner.OnMemoryAllocation(hProcess, address, size);
    }
    
    void OnImportResolution(HANDLE hProcess, const char* dll, const char* func, uintptr_t addr) {
        importMonitor.OnImportResolution(hProcess, dll, func, addr);
    }
    
    void PeriodicScan(HANDLE hProcess) {
        peScanner.ScanMemoryForPEHeaders(hProcess);
    }
};
```

### BattlEye Memory Analysis
```cpp
// BE memory analysis for manual mapping
void BE_DetectManualMapping() {
    // Scan for PE structures in memory
    ScanForPEInMemory();
    
    // Monitor import resolutions
    MonitorImportResolutions();
    
    // Check allocation patterns
    CheckAllocationPatterns();
}

void ScanForPEInMemory() {
    // Look for MZ and PE signatures
    // Validate PE structures
}

void MonitorImportResolutions() {
    // Track GetProcAddress calls
    // Detect manual IAT building
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Allocation patterns |
| 2025-2026 | ⚠️ Alto risco | PE header detection |

---

## 🎯 Lições Aprendidas

1. **Alocações São Rastreadas**: Grandes alocações RWX são suspeitas.

2. **Headers PE São Detectados**: Estruturas PE na memória são encontradas.

3. **Imports São Monitorados**: Resoluções manuais deixam padrões.

4. **Process Hollowing é Mais Avançado**: Substituir processo inteiro é mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#27]]
- [[Process_Hollowing]]
- [[Atom_Bombing]]
- [[Section_Injection]]

---

*Manual DLL mapping tem risco moderado. Considere process hollowing para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
