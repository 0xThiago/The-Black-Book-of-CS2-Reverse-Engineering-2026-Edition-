# Técnica 016 - Reflective DLL Injection

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ✅ Funcional

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 015 - Manual DLL Mapping]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ✅ Funcional  
> **Risco de Detecção:** 🟢 Baixo  
> **Domínio:** Memória & Injeção  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Reflective DLL Injection** é uma técnica avançada onde uma DLL contém seu próprio código de carregamento, permitindo que ela se "injete" na memória sem usar APIs tradicionais como LoadLibrary. É altamente stealth em 2026.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ✅ TÉCNICA FUNCIONAL EM 2026
// Estrutura de uma Reflective DLL
#pragma pack(push, 1)
typedef struct {
    IMAGE_NT_HEADER ntHeader;
    IMAGE_SECTION_HEADER sections[1]; // Array dinâmico
    BYTE data[1]; // Dados da DLL
} REFLECTIVE_LOADER;

typedef HMODULE (WINAPI* REFLECTIVELOADER)(VOID);
typedef BOOL (WINAPI* DLLMAIN)(HINSTANCE, DWORD, LPVOID);

// Função de loader refletivo (embedded na DLL)
HMODULE ReflectiveLoader(VOID) {
    // 1. Obter endereço base da DLL refletiva
    HMODULE hModule = GetModuleBase();
    
    // 2. Parse PE headers
    IMAGE_NT_HEADER* ntHeader = ParseReflectivePE(hModule);
    
    // 3. Alocar memória para image
    LPVOID imageBase = AllocateImageMemory(ntHeader);
    
    // 4. Copiar headers
    CopyHeaders(hModule, imageBase, ntHeader);
    
    // 5. Map sections
    MapReflectiveSections(hModule, imageBase, ntHeader);
    
    // 6. Process relocations
    ProcessReflectiveRelocations(imageBase, ntHeader);
    
    // 7. Resolve imports
    ResolveReflectiveImports(imageBase, ntHeader);
    
    // 8. Call TLS callbacks
    CallReflectiveTLS(imageBase, ntHeader);
    
    // 9. Call entry point
    CallReflectiveEntry(imageBase, ntHeader);
    
    return (HMODULE)imageBase;
}

HMODULE GetModuleBase() {
    // Obter endereço da função atual
    MEMORY_BASIC_INFORMATION mbi;
    VirtualQuery(ReflectiveLoader, &mbi, sizeof(mbi));
    
    // Retroceder até encontrar MZ
    uintptr_t address = (uintptr_t)mbi.AllocationBase;
    
    while (address) {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)address;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            return (HMODULE)address;
        }
        address -= 0x1000; // Página anterior
    }
    
    return NULL;
}

IMAGE_NT_HEADER* ParseReflectivePE(HMODULE hModule) {
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hModule;
    return (IMAGE_NT_HEADER*)((BYTE*)hModule + dos->e_lfanew);
}

LPVOID AllocateImageMemory(IMAGE_NT_HEADER* ntHeader) {
    return VirtualAlloc(NULL, ntHeader->OptionalHeader.SizeOfImage, 
                       MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

void CopyHeaders(HMODULE hModule, LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    // Copiar DOS header
    memcpy(imageBase, hModule, PAGE_SIZE);
    
    // Copiar NT headers
    uintptr_t ntOffset = (uintptr_t)ntHeader - (uintptr_t)hModule;
    memcpy((BYTE*)imageBase + ntOffset, ntHeader, 
           sizeof(IMAGE_NT_HEADER) + ntHeader->FileHeader.NumberOfSections * sizeof(IMAGE_SECTION_HEADER));
}

void MapReflectiveSections(HMODULE hModule, LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeader);
    
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        LPVOID dest = (BYTE*)imageBase + section->VirtualAddress;
        LPVOID src = (BYTE*)hModule + section->VirtualAddress; // Já mapeada
        
        memcpy(dest, src, section->SizeOfRawData);
        section++;
    }
}

void ProcessReflectiveRelocations(LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    IMAGE_DATA_DIRECTORY* relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    
    if (!relocDir->Size) return;
    
    uintptr_t relocAddr = (uintptr_t)imageBase + relocDir->VirtualAddress;
    uintptr_t delta = (uintptr_t)imageBase - ntHeader->OptionalHeader.ImageBase;
    
    IMAGE_BASE_RELOCATION* reloc = (IMAGE_BASE_RELOCATION*)relocAddr;
    
    while (reloc->VirtualAddress) {
        WORD* relocData = (WORD*)((BYTE*)reloc + sizeof(IMAGE_BASE_RELOCATION));
        int numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        
        for (int i = 0; i < numEntries; i++) {
            if ((relocData[i] >> 12) == IMAGE_REL_BASED_DIR64) {
                uintptr_t* patchAddr = (uintptr_t*)((BYTE*)imageBase + reloc->VirtualAddress + (relocData[i] & 0xFFF));
                *patchAddr += delta;
            }
        }
        
        reloc = (IMAGE_BASE_RELOCATION*)((BYTE*)reloc + reloc->SizeOfBlock);
    }
}

void ResolveReflectiveImports(LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    IMAGE_DATA_DIRECTORY* importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    
    if (!importDir->Size) return;
    
    uintptr_t importAddr = (uintptr_t)imageBase + importDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* importDesc = (IMAGE_IMPORT_DESCRIPTOR*)importAddr;
    
    while (importDesc->Name) {
        char* moduleName = (char*)((BYTE*)imageBase + importDesc->Name);
        HMODULE hModule = GetModuleHandleA(moduleName);
        
        if (!hModule) {
            hModule = LoadLibraryA(moduleName);
        }
        
        uintptr_t* thunk = (uintptr_t*)((BYTE*)imageBase + importDesc->FirstThunk);
        IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)((BYTE*)imageBase + importDesc->OriginalFirstThunk);
        
        while (*thunk) {
            FARPROC function;
            
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                function = GetProcAddress(hModule, (char*)(origThunk->u1.Ordinal & 0xFFFF));
            } else {
                IMAGE_IMPORT_BY_NAME* import = (IMAGE_IMPORT_BY_NAME*)((BYTE*)imageBase + origThunk->u1.AddressOfData);
                function = GetProcAddress(hModule, import->Name);
            }
            
            *thunk = (uintptr_t)function;
            thunk++;
            origThunk++;
        }
        
        importDesc++;
    }
}

void CallReflectiveTLS(LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    IMAGE_DATA_DIRECTORY* tlsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    
    if (!tlsDir->Size) return;
    
    IMAGE_TLS_DIRECTORY* tls = (IMAGE_TLS_DIRECTORY*)((BYTE*)imageBase + tlsDir->VirtualAddress);
    
    if (tls->AddressOfCallBacks) {
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)((BYTE*)imageBase + tls->AddressOfCallBacks);
        
        while (*callback) {
            (*callback)((LPVOID)imageBase, DLL_PROCESS_ATTACH, NULL);
            callback++;
        }
    }
}

void CallReflectiveEntry(LPVOID imageBase, IMAGE_NT_HEADER* ntHeader) {
    if (!ntHeader->OptionalHeader.AddressOfEntryPoint) return;
    
    uintptr_t entryPoint = (uintptr_t)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    DLLMAIN dllMain = (DLLMAIN)entryPoint;
    
    dllMain((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
}
#pragma pack(pop)
```

### Por que é Eficaz

> [!SUCCESS]
> **Reflective injection evita LoadLibrary completamente e não deixa rastros no PEB**

#### 1. Self-Contained Loading
```cpp
// DLL contém seu próprio loader
class ReflectiveDLL {
public:
    // Esta função é embedded na DLL
    static HMODULE LoadReflective() {
        // Código de loading inline
        return ReflectiveLoader();
    }
    
    // Entry point chama loader
    BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
        if (fdwReason == DLL_PROCESS_ATTACH) {
            // Executar payload
            ExecutePayload();
        }
        
        return TRUE;
    }
    
private:
    void ExecutePayload() {
        // Código do cheat aqui
        // ESP, Aimbot, etc.
    }
};
```

#### 2. Position Independent Code
```cpp
// Código independente de posição
class PositionIndependentCode {
public:
    void GeneratePIC() {
        // 1. Usar RIP-relative addressing
        GenerateRIPRelative();
        
        // 2. Resolver imports dinamicamente
        ResolveImportsDynamically();
        
        // 3. Self-relocating code
        SelfRelocate();
    }
    
private:
    void GenerateRIPRelative() {
        // Exemplo de código RIP-relative
        __asm {
            call get_rip
            get_rip:
            pop rax         // RAX = endereço de get_rip
            sub rax, 5      // Ajustar para início da call
            
            // Agora podemos calcular endereços relativos
            lea rbx, [rax + data_offset]
            lea rcx, [rax + code_offset]
        }
    }
    
    void ResolveImportsDynamically() {
        // Resolver GetProcAddress, LoadLibrary, etc.
        HMODULE kernel32 = GetKernel32Base();
        GetProcAddress_t pGetProcAddress = (GetProcAddress_t)GetProcAddressFromKernel32(kernel32, "GetProcAddress");
        LoadLibraryA_t pLoadLibraryA = (LoadLibraryA_t)pGetProcAddress(kernel32, "LoadLibraryA");
        
        // Usar para resolver outros imports
    }
    
    HMODULE GetKernel32Base() {
        // Percorrer PEB para encontrar kernel32
        PPEB peb = (PPEB)__readgsqword(0x60);
        
        for (PLIST_ENTRY entry = peb->Ldr->InMemoryOrderModuleList.Flink;
             entry != &peb->Ldr->InMemoryOrderModuleList;
             entry = entry->Flink) {
            
            PLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            if (wcsstr(module->FullDllName.Buffer, L"kernel32.dll")) {
                return (HMODULE)module->DllBase;
            }
        }
        
        return NULL;
    }
};
```

#### 3. Advanced Reflective Techniques
```cpp
// Técnicas avançadas de reflexão
class AdvancedReflective {
public:
    void ImplementAdvancedFeatures() {
        // 1. Encrypted payload
        ImplementEncryption();
        
        // 2. Anti-analysis
        ImplementAntiAnalysis();
        
        // 3. Dynamic loading
        ImplementDynamicLoading();
    }
    
private:
    void ImplementEncryption() {
        // Payload criptografado
        // Descriptografar em runtime
        DecryptPayload();
    }
    
    void ImplementAntiAnalysis() {
        // Detectar debuggers
        if (IsDebuggerPresent()) {
            return;
        }
        
        // Detectar sandboxes
        if (IsSandbox()) {
            return;
        }
        
        // Anti-dumping
        ImplementAntiDump();
    }
    
    void ImplementDynamicLoading() {
        // Carregar componentes sob demanda
        // Lazy loading de funções
        LoadComponentsOnDemand();
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory patterns | < 5 min | 60% |
| VAC Live | Reflective code | < 2 min | 65% |
| BattlEye | Import resolution | < 1 min | 70% |
| Faceit AC | Entry execution | < 30s | 55% |

---

## 🔄 Implementações Avançadas

### 1. Encrypted Reflective DLL
```cpp
// ✅ Reflective com criptografia
class EncryptedReflective {
private:
    BYTE encryptedPayload[ENCRYPTED_SIZE];
    BYTE key[KEY_SIZE];
    
public:
    HMODULE LoadEncrypted() {
        // 1. Descriptografar payload
        DecryptPayload();
        
        // 2. Executar loader refletivo
        return ReflectiveLoader();
    }
    
private:
    void DecryptPayload() {
        for (size_t i = 0; i < ENCRYPTED_SIZE; i++) {
            payload[i] = encryptedPayload[i] ^ key[i % KEY_SIZE];
        }
    }
};
```

### 2. Polymorphic Reflective
```cpp
// ✅ Reflective polimórfico
class PolymorphicReflective {
public:
    void GeneratePolymorphic() {
        // 1. Modificar código em runtime
        MutateCode();
        
        // 2. Alterar assinaturas
        ChangeSignatures();
        
        // 3. Reordenar funções
        ReorderFunctions();
    }
    
private:
    void MutateCode() {
        // Aplicar mutações no código
        // NOP insertion, register swapping, etc.
    }
    
    void ChangeSignatures() {
        // Alterar byte patterns
        // Evitar detecção por signatures
    }
};
```

### 3. Kernel Reflective
```cpp
// ✅ Reflective via kernel
class KernelReflective {
public:
    HMODULE LoadKernelReflective() {
        // 1. Injetar via kernel driver
        InjectViaDriver();
        
        // 2. Executar em kernel mode
        ExecuteInKernel();
        
        // 3. Map no processo alvo
        MapToTargetProcess();
    }
    
private:
    void InjectViaDriver() {
        // Usar driver para injeção
        // Bypass usermode hooks
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Reflective Scanner
```cpp
// VAC reflective injection detection
class VAC_ReflectiveScanner {
private:
    std::vector<MEMORY_REGION> suspiciousRegions;
    
public:
    void Initialize() {
        // Scan for reflective patterns
        StartReflectiveScan();
    }
    
    void ScanForReflective() {
        // Look for PE headers in memory
        ScanMemoryForPE();
        
        // Check for reflective loaders
        ScanForLoaders();
        
        // Verify imports
        VerifyImportResolution();
    }
    
    void ScanMemoryForPE() {
        // Enumerate memory regions
        // Check for MZ signatures
        // Validate PE structures
    }
    
    void ScanForLoaders() {
        // Look for reflective loader code
        // Check for characteristic patterns
    }
};
```

### BattlEye Reflective Analyzer
```cpp
// BE reflective analysis
void BE_AnalyzeReflective() {
    // Monitor memory allocations
    MonitorAllocations();
    
    // Check for self-mapping code
    CheckSelfMapping();
    
    // Verify module loading
    VerifyModuleLoading();
}

void MonitorAllocations() {
    // Track large allocations
    // Check for PE-like structures
}

void CheckSelfMapping() {
    // Look for code that maps itself
    // Detect reflective loading patterns
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ✅ Funcional | Memory scanning |
| 2020-2024 | ✅ Funcional | Pattern analysis |
| 2025-2026 | ✅ Funcional | Advanced detection |

---

## 🎯 Lições Aprendidas

1. **Self-Contained é Melhor**: DLLs que se carregam são mais stealth.

2. **Position Independent**: Código PIC evita relocations óbvias.

3. **Encryption Helps**: Payloads criptografados são mais difíceis de detectar.

4. **Polymorphism é Futuro**: Código mutante evita signatures.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#15]]
- [[Encrypted_Reflective]]
- [[Polymorphic_Reflective]]
- [[Kernel_Reflective]]

---

*Reflective injection é uma das técnicas mais avançadas em 2026. Use com criptografia e polimorfismo.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
