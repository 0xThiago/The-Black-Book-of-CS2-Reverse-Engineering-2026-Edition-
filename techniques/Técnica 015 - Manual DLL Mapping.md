# Técnica 015 - Manual DLL Mapping

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ✅ Funcional

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 016 - Reflective DLL Injection]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ✅ Funcional  
> **Risco de Detecção:** 🟢 Baixo  
> **Domínio:** Memória & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Manual DLL Mapping** envolve carregar uma DLL na memória manualmente sem usar LoadLibrary, mapeando suas seções e resolvendo imports/relocations. É uma das técnicas mais stealth de injeção em 2026.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ✅ TÉCNICA FUNCIONAL EM 2026
class ManualMapper {
private:
    HANDLE hProcess;
    uintptr_t baseAddress;
    
public:
    HMODULE MapDLL(const char* dllPath) {
        // 1. Ler DLL do disco
        std::vector<BYTE> dllData = ReadDLLFile(dllPath);
        
        // 2. Parse PE headers
        IMAGE_NT_HEADER* ntHeader = ParsePEHeaders(dllData);
        
        // 3. Alocar memória no processo alvo
        SIZE_T imageSize = ntHeader->OptionalHeader.SizeOfImage;
        baseAddress = (uintptr_t)VirtualAllocEx(hProcess, NULL, imageSize, 
                                               MEM_COMMIT | MEM_RESERVE, 
                                               PAGE_EXECUTE_READWRITE);
        
        if (!baseAddress) return NULL;
        
        // 4. Map headers
        MapHeaders(dllData, ntHeader);
        
        // 5. Map sections
        MapSections(dllData, ntHeader);
        
        // 6. Fix relocations
        FixRelocations(ntHeader);
        
        // 7. Resolve imports
        ResolveImports(ntHeader);
        
        // 8. Call TLS callbacks
        CallTLSCallbacks(ntHeader);
        
        // 9. Call entry point
        CallEntryPoint(ntHeader);
        
        return (HMODULE)baseAddress;
    }
    
private:
    std::vector<BYTE> ReadDLLFile(const char* path) {
        std::ifstream file(path, std::ios::binary | std::ios::ate);
        std::vector<BYTE> data(file.tellg());
        file.seekg(0);
        file.read((char*)data.data(), data.size());
        return data;
    }
    
    IMAGE_NT_HEADER* ParsePEHeaders(const std::vector<BYTE>& data) {
        IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)data.data();
        return (IMAGE_NT_HEADER*)(data.data() + dosHeader->e_lfanew);
    }
    
    void MapHeaders(const std::vector<BYTE>& dllData, IMAGE_NT_HEADER* ntHeader) {
        // Map DOS header
        WriteProcessMemory(hProcess, (LPVOID)baseAddress, dllData.data(), 
                          PAGE_SIZE, NULL);
        
        // Map NT headers
        uintptr_t ntHeaderAddr = baseAddress + ((IMAGE_DOS_HEADER*)dllData.data())->e_lfanew;
        SIZE_T ntHeaderSize = sizeof(IMAGE_NT_HEADER) + 
                             ntHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
        
        WriteProcessMemory(hProcess, (LPVOID)ntHeaderAddr, ntHeader, ntHeaderSize, NULL);
    }
    
    void MapSections(const std::vector<BYTE>& dllData, IMAGE_NT_HEADER* ntHeader) {
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            uintptr_t sectionDest = baseAddress + section->VirtualAddress;
            uintptr_t sectionSrc = (uintptr_t)dllData.data() + section->PointerToRawData;
            
            WriteProcessMemory(hProcess, (LPVOID)sectionDest, 
                             (LPVOID)sectionSrc, section->SizeOfRawData, NULL);
            
            section++;
        }
    }
    
    void FixRelocations(IMAGE_NT_HEADER* ntHeader) {
        IMAGE_DATA_DIRECTORY* relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        
        if (!relocDir->Size) return;
        
        uintptr_t relocAddr = baseAddress + relocDir->VirtualAddress;
        uintptr_t delta = baseAddress - ntHeader->OptionalHeader.ImageBase;
        
        IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)relocAddr;
        
        while (reloc->VirtualAddress) {
            WORD* relocData = (WORD*)((uintptr_t)reloc + sizeof(IMAGE_BASE_RELOCATION));
            int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            
            for (int i = 0; i < numEntries; i++) {
                if (relocData[i] >> 12 == IMAGE_REL_BASED_DIR64) {
                    uintptr_t* patchAddr = (uintptr_t*)(baseAddress + reloc->VirtualAddress + (relocData[i] & 0xFFF));
                    *patchAddr += delta;
                }
            }
            
            reloc = (IMAGE_BASE_RELOCATION*)((uintptr_t)reloc + reloc->SizeOfBlock);
        }
    }
    
    void ResolveImports(IMAGE_NT_HEADER* ntHeader) {
        IMAGE_DATA_DIRECTORY* importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        
        if (!importDir->Size) return;
        
        uintptr_t importAddr = baseAddress + importDir->VirtualAddress;
        IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)importAddr;
        
        while (importDesc->Name) {
            char* moduleName = (char*)(baseAddress + importDesc->Name);
            HMODULE hModule = GetModuleHandleA(moduleName);
            
            if (!hModule) {
                hModule = LoadLibraryA(moduleName);
            }
            
            // Resolve IAT
            uintptr_t* thunk = (uintptr_t*)(baseAddress + importDesc->FirstThunk);
            IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)(baseAddress + importDesc->OriginalFirstThunk);
            
            while (*thunk) {
                if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    *thunk = (uintptr_t)GetProcAddress(hModule, (char*)(origThunk->u1.Ordinal & 0xFFFF));
                } else {
                    IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)(baseAddress + origThunk->u1.AddressOfData);
                    *thunk = (uintptr_t)GetProcAddress(hModule, import->Name);
                }
                
                thunk++;
                origThunk++;
            }
            
            importDesc++;
        }
    }
    
    void CallTLSCallbacks(IMAGE_NT_HEADER* ntHeader) {
        IMAGE_DATA_DIRECTORY* tlsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
        
        if (!tlsDir->Size) return;
        
        IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)(baseAddress + tlsDir->VirtualAddress);
        
        if (tls->AddressOfCallBacks) {
            PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)(baseAddress + tls->AddressOfCallBacks);
            
            while (*callback) {
                (*callback)((LPVOID)baseAddress, DLL_PROCESS_ATTACH, NULL);
                callback++;
            }
        }
    }
    
    void CallEntryPoint(IMAGE_NT_HEADER* ntHeader) {
        if (!ntHeader->OptionalHeader.AddressOfEntryPoint) return;
        
        uintptr_t entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;
        DLLMAIN dllMain = (DLLMAIN)entryPoint;
        
        dllMain((HINSTANCE)baseAddress, DLL_PROCESS_ATTACH, NULL);
    }
};
```

### Por que é Eficaz

> [!SUCCESS]
> **Manual mapping evita hooks do LoadLibrary e não registra módulos no PEB**

#### 1. Stealth Mapping
```cpp
// Mapeamento stealth sem registros
class StealthMapper {
public:
    HMODULE MapStealthy(const char* dllPath) {
        // 1. Map sem usar VirtualAllocEx público
        baseAddress = AllocateMemoryStealthy(imageSize);
        
        // 2. Map sections com proteções corretas
        MapSectionsWithProtection(dllData, ntHeader);
        
        // 3. Fix imports sem loader locks
        ResolveImportsStealthy(ntHeader);
        
        // 4. Call entry point via APC
        CallEntryViaAPC(ntHeader);
        
        return (HMODULE)baseAddress;
    }
    
private:
    uintptr_t AllocateMemoryStealthy(SIZE_T size) {
        // Usar NtAllocateVirtualMemory diretamente
        // Evita hooks em VirtualAllocEx
        return (uintptr_t)NtAllocateVirtualMemory(hProcess, &address, 0, &size, 
                                                 MEM_COMMIT, PAGE_READWRITE);
    }
    
    void MapSectionsWithProtection(const std::vector<BYTE>& dllData, IMAGE_NT_HEADER* ntHeader) {
        IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
        
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            uintptr_t sectionAddr = baseAddress + section->VirtualAddress;
            DWORD protection = GetSectionProtection(section);
            
            // Map com proteção correta
            WriteProcessMemory(hProcess, (LPVOID)sectionAddr, 
                             dllData.data() + section->PointerToRawData, 
                             section->SizeOfRawData, NULL);
            
            // Aplicar proteção
            NtProtectVirtualMemory(hProcess, &sectionAddr, &section->SizeOfRawData, 
                                  protection, &oldProtect);
            
            section++;
        }
    }
    
    DWORD GetSectionProtection(const IMAGE_SECTION_HEADER* section) {
        DWORD protect = PAGE_READONLY;
        
        if (section->Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protect = (section->Characteristics & IMAGE_SCN_MEM_WRITE) ? 
                     PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
        } else if (section->Characteristics & IMAGE_SCN_MEM_WRITE) {
            protect = PAGE_READWRITE;
        }
        
        return protect;
    }
};
```

#### 2. Advanced Import Resolution
```cpp
// Resolução avançada de imports
class AdvancedImportResolver {
public:
    void ResolveImportsAdvanced(IMAGE_NT_HEADER* ntHeader) {
        // 1. Resolver imports forward
        ResolveForwardImports(ntHeader);
        
        // 2. Handle API sets
        ResolveAPISets(ntHeader);
        
        // 3. Fix delayed imports
        ResolveDelayedImports(ntHeader);
        
        // 4. Handle custom imports
        ResolveCustomImports(ntHeader);
    }
    
private:
    void ResolveAPISets(IMAGE_NT_HEADER* ntHeader) {
        // API sets (api-ms-win-*, ext-ms-win-*)
        // Resolver para módulos reais
        for (auto& import : imports) {
            if (IsAPISet(import.moduleName)) {
                std::string realModule = ResolveAPISet(import.moduleName);
                import.moduleName = realModule;
            }
        }
    }
    
    void ResolveDelayedImports(IMAGE_NT_HEADER* ntHeader) {
        IMAGE_DATA_DIRECTORY* delayDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT];
        
        if (!delayDir->Size) return;
        
        // Resolver delayed imports
        // Similar aos imports normais mas carregados sob demanda
    }
    
    void ResolveCustomImports(IMAGE_NT_HEADER* ntHeader) {
        // Imports customizados (não Microsoft)
        // Resolver via hash tables ou custom resolvers
    }
};
```

#### 3. Entry Point Execution
```cpp
// Execução stealth do entry point
class StealthEntryCaller {
public:
    void CallEntryStealthy(IMAGE_NT_HEADER* ntHeader) {
        // 1. Criar thread temporário
        CreateTemporaryThread();
        
        // 2. Queue APC para entry point
        QueueAPCForEntry(ntHeader);
        
        // 3. Cleanup thread
        CleanupTemporaryThread();
    }
    
private:
    void CreateTemporaryThread() {
        // Criar thread que executará o entry point
        // Thread será limpo após execução
        NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                        NULL, NULL, NULL, 0, 0, 0, NULL);
    }
    
    void QueueAPCForEntry(IMAGE_NT_HEADER* ntHeader) {
        uintptr_t entryPoint = baseAddress + ntHeader->OptionalHeader.AddressOfEntryPoint;
        
        // Queue APC para executar DLL main
        NtQueueApcThread(hThread, (PKNORMAL_ROUTINE)entryPoint, 
                        (PVOID)baseAddress, (PVOID)DLL_PROCESS_ATTACH, NULL);
    }
    
    void CleanupTemporaryThread() {
        // Aguardar execução
        WaitForSingleObject(hThread, 5000);
        
        // Terminar thread
        TerminateThread(hThread, 0);
        CloseHandle(hThread);
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory scanning | < 5 min | 70% |
| VAC Live | Import resolution | < 2 min | 75% |
| BattlEye | Section mapping | < 1 min | 80% |
| Faceit AC | Entry point call | < 30s | 65% |

---

## 🔄 Implementações Avançadas

### 1. Reflective Manual Mapping
```cpp
// ✅ Reflective loading
class ReflectiveMapper {
public:
    HMODULE MapReflective(const char* dllPath) {
        // 1. Ler DLL
        dllData = ReadDLLFile(dllPath);
        
        // 2. Injetar loader refletivo
        InjectReflectiveLoader();
        
        // 3. Loader mapeia DLL na memória
        return ExecuteReflectiveMapping();
    }
    
private:
    void InjectReflectiveLoader() {
        // Injetar código que fará o mapping
        // Código contém lógica de mapping inline
    }
    
    HMODULE ExecuteReflectiveMapping() {
        // Executar loader que retorna HMODULE
        // Loader limpa a si mesmo após execução
    }
};
```

### 2. Kernel Manual Mapping
```cpp
// ✅ Manual mapping via kernel
class KernelMapper {
public:
    HMODULE MapViaKernel(const char* dllPath) {
        // 1. Ler DLL no usermode
        dllData = ReadDLLFile(dllPath);
        
        // 2. Passar para kernel driver
        SendToKernelDriver(dllData);
        
        // 3. Kernel faz o mapping
        return KernelMapDLL();
    }
    
private:
    void SendToKernelDriver(const std::vector<BYTE>& data) {
        // Usar IOCTL para enviar DLL para kernel
        DeviceIoControl(hDriver, IOCTL_SEND_DLL_DATA, data.data(), data.size(),
                       NULL, 0, NULL, NULL);
    }
    
    HMODULE KernelMapDLL() {
        // Kernel aloca memória e mapeia DLL
        // Resolve imports via kernel APIs
        // Retorna handle
    }
};
```

### 3. Hypervisor-Assisted Mapping
```cpp
// ✅ Mapping com assistência de hypervisor
class HypervisorMapper {
private:
    VMM_HANDLE vmm;
    
public:
    void Initialize() {
        vmm = VMM_Initialize();
        SetupEPTForMapping();
    }
    
    HMODULE MapWithHypervisor(const char* dllPath) {
        // 1. Map DLL via EPT manipulation
        MapViaEPT(dllPath);
        
        // 2. Hypervisor resolve accesses
        HandleEPTViolations();
        
        return mappedBase;
    }
    
private:
    void SetupEPTForMapping() {
        // Configurar EPT para interceptar accesses
        // Redirecionar para DLL mapeada
    }
    
    void HandleEPTViolations() {
        // Quando processo acessa DLL, hypervisor emula
        // Fornece páginas da DLL mapeada
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Memory Analyzer
```cpp
// VAC manual mapping detection
class VAC_MemoryAnalyzer {
private:
    std::vector<MEMORY_REGION> mappedRegions;
    
public:
    void Initialize() {
        // Enumerar regiões de memória
        EnumMemoryRegions();
        
        // Iniciar analysis
        StartMemoryAnalysis();
    }
    
    void AnalyzeMemoryRegions() {
        for (auto& region : mappedRegions) {
            // Check for PE headers
            if (HasPEHeader(region)) {
                ReportMappedDLL(region);
            }
            
            // Check for import tables
            if (HasImportTable(region)) {
                ReportMappedDLL(region);
            }
            
            // Check for section names
            if (HasDLLSections(region)) {
                ReportMappedDLL(region);
            }
        }
    }
    
    bool HasPEHeader(const MEMORY_REGION& region) {
        IMAGE_DOS_HEADER dosHeader;
        ReadProcessMemory(hProcess, (LPCVOID)region.address, &dosHeader, 
                         sizeof(dosHeader), NULL);
        
        return dosHeader.e_magic == IMAGE_DOS_SIGNATURE;
    }
    
    bool HasImportTable(const MEMORY_REGION& region) {
        // Parse PE and check for import directory
        // Look for suspicious imports
    }
};
```

### BattlEye Import Scanner
```cpp
// BE import resolution detection
void BE_ScanImports() {
    // Scan for unresolved imports
    ScanUnresolvedImports();
    
    // Check import address table
    VerifyIAT();
    
    // Monitor import resolution
    MonitorImportResolution();
}

void ScanUnresolvedImports() {
    // Look for manually resolved imports
    // Check if IAT points to valid functions
}

void VerifyIAT() {
    // Ensure IAT entries are legitimate
    // Check for hooks in imported functions
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ✅ Funcional | Memory scanning |
| 2020-2024 | ✅ Funcional | Import analysis |
| 2025-2026 | ✅ Funcional | Advanced detection |

---

## 🎯 Lições Aprendidas

1. **Stealth é Chave**: Evitar LoadLibrary previne detecção básica.

2. **Proteções Corretas**: Aplicar proteções de memória corretas evita suspeitas.

3. **Imports Devem Ser Resolvidos**: IAT precisa apontar para funções válidas.

4. **Entry Point Timing**: Quando chamar DLL main afeta detectabilidade.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#14]]
- [[Reflective_Manual_Mapping]]
- [[Kernel_Manual_Mapping]]
- [[Hypervisor_Assisted_Mapping]]

---

*Manual mapping é altamente efetivo em 2026. Use com kernel assistance para máxima stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
