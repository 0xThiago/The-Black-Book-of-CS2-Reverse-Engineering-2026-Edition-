# 📖 Técnica 025: Reflective DLL Injection

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 025: Reflective DLL Injection]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Injection & Loading  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Reflective DLL Injection** carrega uma DLL diretamente na memória do processo sem usar o loader do Windows. É mais stealth que injeção tradicional, mas ainda detectável por anti-cheats avançados.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ReflectiveInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectReflectiveDLL(const char* dllPath) {
        // Carregar DLL localmente
        HMODULE hLocalDLL = LoadLibraryA(dllPath);
        if (!hLocalDLL) return false;
        
        // Obter informações da DLL
        DLL_INFO dllInfo = GetDLLInfo(hLocalDLL);
        
        // Alocar memória no processo remoto
        LPVOID remoteBase = VirtualAllocEx(hProcess, NULL, dllInfo.sizeOfImage,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!remoteBase) {
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Mapear DLL para memória remota
        if (!MapDLLToRemoteProcess(hLocalDLL, dllInfo, remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        // Executar reflective loader
        if (!ExecuteReflectiveLoader(remoteBase)) {
            VirtualFreeEx(hProcess, remoteBase, 0, MEM_RELEASE);
            FreeLibrary(hLocalDLL);
            return false;
        }
        
        FreeLibrary(hLocalDLL);
        return true;
    }
    
private:
    DLL_INFO GetDLLInfo(HMODULE hDLL) {
        DLL_INFO info = {0};
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hDLL + dosHeader->e_lfanew);
        
        info.sizeOfImage = ntHeader->OptionalHeader.SizeOfImage;
        info.entryPoint = ntHeader->OptionalHeader.AddressOfEntryPoint;
        info.imageBase = ntHeader->OptionalHeader.ImageBase;
        
        // Encontrar seções
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sectionHeader[i].Name, ".refl") == 0) {
                info.reflectiveLoader = (BYTE*)hDLL + sectionHeader[i].VirtualAddress;
                info.reflectiveLoaderSize = sectionHeader[i].Misc.VirtualSize;
                break;
            }
        }
        
        return info;
    }
    
    bool MapDLLToRemoteProcess(HMODULE hLocalDLL, const DLL_INFO& dllInfo, LPVOID remoteBase) {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hLocalDLL;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hLocalDLL + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
        
        // Mapear headers
        SIZE_T headersSize = ntHeader->OptionalHeader.SizeOfHeaders;
        if (!WriteProcessMemory(hProcess, remoteBase, hLocalDLL, headersSize, NULL)) {
            return false;
        }
        
        // Mapear seções
        for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
            PIMAGE_SECTION_HEADER section = &sectionHeader[i];
            
            if (section->SizeOfRawData == 0) continue;
            
            LPVOID sectionBase = (LPVOID)((BYTE*)remoteBase + section->VirtualAddress);
            LPVOID sectionData = (LPVOID)((BYTE*)hLocalDLL + section->PointerToRawData);
            
            if (!WriteProcessMemory(hProcess, sectionBase, sectionData, 
                                  section->SizeOfRawData, NULL)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool ExecuteReflectiveLoader(LPVOID remoteBase) {
        // Encontrar função reflective loader na DLL
        uintptr_t loaderAddr = FindReflectiveLoader(remoteBase);
        if (!loaderAddr) return false;
        
        // Criar thread para executar loader
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                          (LPTHREAD_START_ROUTINE)loaderAddr,
                                          remoteBase, 0, NULL);
        
        if (!hThread) return false;
        
        // Aguardar conclusão
        WaitForSingleObject(hThread, INFINITE);
        
        // Verificar se foi bem-sucedido
        DWORD exitCode;
        GetExitCodeThread(hThread, &exitCode);
        
        CloseHandle(hThread);
        return exitCode == 0;
    }
    
    uintptr_t FindReflectiveLoader(LPVOID remoteBase) {
        // Procurar por função especial na seção .refl
        // Ou usar export específico
        
        // Simples: assumir que entry point é o loader
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)remoteBase;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)remoteBase + dosHeader->e_lfanew);
        
        return (uintptr_t)remoteBase + ntHeader->OptionalHeader.AddressOfEntryPoint;
    }
};

// DLL Reflectiva (código dentro da DLL)
extern "C" __declspec(dllexport) DWORD ReflectiveLoader(LPVOID imageBase) {
    // Obter informações da imagem
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)imageBase + dosHeader->e_lfanew);
    
    // Aplicar relocations se necessário
    if (!ApplyRelocations(imageBase, ntHeader)) {
        return 1; // Falha
    }
    
    // Resolver imports
    if (!ResolveImports(imageBase, ntHeader)) {
        return 2; // Falha
    }
    
    // Proteger seções
    if (!ProtectSections(imageBase, ntHeader)) {
        return 3; // Falha
    }
    
    // Executar TLS callbacks
    ExecuteTLSCallbacks(imageBase, ntHeader);
    
    // Chamar entry point da DLL
    DLLMAIN entryPoint = (DLLMAIN)((BYTE*)imageBase + ntHeader->OptionalHeader.AddressOfEntryPoint);
    return entryPoint((HINSTANCE)imageBase, DLL_PROCESS_ATTACH, NULL);
}

bool ApplyRelocations(LPVOID imageBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_DATA_DIRECTORY relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return true; // Sem relocations
    
    uintptr_t delta = (uintptr_t)imageBase - ntHeader->OptionalHeader.ImageBase;
    if (delta == 0) return true; // Base correta
    
    PIMAGE_BASE_RELOCATION relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)imageBase + relocDir->VirtualAddress);
    
    while (relocBlock->VirtualAddress != 0) {
        DWORD numEntries = (relocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        PWORD relocEntries = (PWORD)((BYTE*)relocBlock + sizeof(IMAGE_BASE_RELOCATION));
        
        for (DWORD i = 0; i < numEntries; i++) {
            WORD relocEntry = relocEntries[i];
            WORD type = relocEntry >> 12;
            WORD offset = relocEntry & 0xFFF;
            
            if (type == IMAGE_REL_BASED_HIGHLOW) {
                uintptr_t* patchAddr = (uintptr_t*)((BYTE*)imageBase + relocBlock->VirtualAddress + offset);
                *patchAddr += delta;
            }
        }
        
        relocBlock = (PIMAGE_BASE_RELOCATION)((BYTE*)relocBlock + relocBlock->SizeOfBlock);
    }
    
    return true;
}

bool ResolveImports(LPVOID imageBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_DATA_DIRECTORY importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir->Size == 0) return true;
    
    PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)imageBase + importDir->VirtualAddress);
    
    while (importDesc->Name != 0) {
        char* dllName = (char*)imageBase + importDesc->Name;
        HMODULE hModule = LoadLibraryA(dllName);
        if (!hModule) return false;
        
        // Resolver imports por nome
        if (importDesc->OriginalFirstThunk != 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->OriginalFirstThunk);
            PIMAGE_THUNK_DATA funcThunk = (PIMAGE_THUNK_DATA)((BYTE*)imageBase + importDesc->FirstThunk);
            
            while (thunk->u1.AddressOfData != 0) {
                if (thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import por ordinal
                    funcThunk->u1.Function = (uintptr_t)GetProcAddress(hModule, (char*)(thunk->u1.Ordinal & 0xFFFF));
                } else {
                    // Import por nome
                    PIMAGE_IMPORT_BY_NAME importName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)imageBase + thunk->u1.AddressOfData);
                    funcThunk->u1.Function = (uintptr_t)GetProcAddress(hModule, importName->Name);
                }
                
                thunk++;
                funcThunk++;
            }
        }
        
        importDesc++;
    }
    
    return true;
}

bool ProtectSections(LPVOID imageBase, PIMAGE_NT_HEADER ntHeader) {
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
            DWORD oldProtect;
            VirtualProtect((LPVOID)((BYTE*)imageBase + section->VirtualAddress), 
                          section->Misc.VirtualSize, protect, &oldProtect);
        }
    }
    
    return true;
}

void ExecuteTLSCallbacks(LPVOID imageBase, PIMAGE_NT_HEADER ntHeader) {
    PIMAGE_DATA_DIRECTORY tlsDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
    if (tlsDir->Size == 0) return;
    
    PIMAGE_TLS_DIRECTORY tlsDirectory = (PIMAGE_TLS_DIRECTORY)((BYTE*)imageBase + tlsDir->VirtualAddress);
    
    if (tlsDirectory->AddressOfCallBacks != 0) {
        PIMAGE_TLS_CALLBACK* callbacks = (PIMAGE_TLS_CALLBACK*)tlsDirectory->AddressOfCallBacks;
        
        while (*callbacks != NULL) {
            (*callbacks)((LPVOID)imageBase, DLL_PROCESS_ATTACH, NULL);
            callbacks++;
        }
    }
}
```

### Por que é Detectado

> [!WARNING]
> **Reflective injection cria alocações de memória suspeitas e modificações na IAT**

#### 1. Memory Allocation Monitoring
```cpp
// Monitoramento de alocações de memória
class MemoryAllocationMonitor {
private:
    std::map<HANDLE, std::vector<ALLOCATION_INFO>> processAllocations;
    
public:
    void OnVirtualAlloc(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD allocationType, DWORD protect) {
        ALLOCATION_INFO info = {address, size, allocationType, protect, GetTickCount()};
        processAllocations[hProcess].push_back(info);
        
        // Analisar alocação
        AnalyzeAllocation(hProcess, info);
    }
    
    void AnalyzeAllocation(HANDLE hProcess, const ALLOCATION_INFO& info) {
        // Verificar tamanho suspeito
        if (info.size > SUSPICIOUS_ALLOCATION_SIZE) {
            ReportLargeAllocation(hProcess, info);
        }
        
        // Verificar proteção executável
        if ((info.protect & PAGE_EXECUTE) != 0 && (info.protect & PAGE_EXECUTE_READWRITE) != 0) {
            ReportExecutableAllocation(hProcess, info);
        }
        
        // Verificar padrão de alocações
        if (HasInjectionPattern(hProcess)) {
            ReportInjectionPattern(hProcess);
        }
    }
    
    bool HasInjectionPattern(HANDLE hProcess) {
        auto& allocations = processAllocations[hProcess];
        if (allocations.size() < 3) return false;
        
        // Procurar por padrão: alocação grande + pequenas alocações sequenciais
        bool hasLargeAlloc = false;
        int smallAllocCount = 0;
        
        for (auto& alloc : allocations) {
            if (alloc.size > LARGE_ALLOCATION_THRESHOLD) {
                hasLargeAlloc = true;
            } else if (alloc.size < SMALL_ALLOCATION_THRESHOLD) {
                smallAllocCount++;
            }
        }
        
        return hasLargeAlloc && smallAllocCount >= 2;
    }
    
    void OnVirtualFree(HANDLE hProcess, LPVOID address) {
        // Remover da lista de alocações
        auto& allocations = processAllocations[hProcess];
        allocations.erase(
            std::remove_if(allocations.begin(), allocations.end(),
                [address](const ALLOCATION_INFO& info) {
                    return info.address == address;
                }),
            allocations.end()
        );
    }
};
```

#### 2. Import Address Table Monitoring
```cpp
// Monitoramento da IAT
class IATMonitor {
private:
    std::map<HMODULE, IAT_INFO> moduleIATs;
    
public:
    void OnModuleLoad(HMODULE hModule) {
        // Salvar estado original da IAT
        IAT_INFO info;
        info.originalIAT = CaptureIAT(hModule);
        info.currentIAT = info.originalIAT;
        
        moduleIATs[hModule] = info;
    }
    
    void CheckIATIntegrity(HMODULE hModule) {
        auto it = moduleIATs.find(hModule);
        if (it == moduleIATs.end()) return;
        
        std::vector<uintptr_t> currentIAT = CaptureIAT(hModule);
        
        if (currentIAT != it->second.originalIAT) {
            ReportIATModification(hModule);
        }
        
        it->second.currentIAT = currentIAT;
    }
    
    void OnImportResolution(HMODULE hModule, const char* functionName, uintptr_t resolvedAddress) {
        // Verificar se resolução é suspeita
        if (IsSuspiciousResolution(hModule, functionName, resolvedAddress)) {
            ReportSuspiciousImport(hModule, functionName);
        }
    }
    
private:
    std::vector<uintptr_t> CaptureIAT(HMODULE hModule) {
        std::vector<uintptr_t> iat;
        
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADER ntHeader = (PIMAGE_NT_HEADER)((BYTE*)hModule + dosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY importDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        
        if (importDir->Size == 0) return iat;
        
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + importDir->VirtualAddress);
        
        while (importDesc->Name != 0) {
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            
            while (thunk->u1.Function != 0) {
                iat.push_back(thunk->u1.Function);
                thunk++;
            }
            
            importDesc++;
        }
        
        return iat;
    }
    
    bool IsSuspiciousResolution(HMODULE hModule, const char* functionName, uintptr_t resolvedAddress) {
        // Verificar se endereço resolvido está em módulo suspeito
        HMODULE resolvedModule = GetModuleFromAddress(resolvedAddress);
        
        if (resolvedModule != GetSystemModule(functionName)) {
            return true; // Resolução de função do sistema aponta para módulo não-sistema
        }
        
        return false;
    }
};
```

#### 3. Thread Creation Analysis
```cpp
// Análise de criação de threads
class ThreadCreationAnalyzer {
private:
    std::map<HANDLE, std::vector<THREAD_INFO>> processThreads;
    
public:
    void OnThreadCreate(HANDLE hProcess, HANDLE hThread, LPTHREAD_START_ROUTINE startAddress, LPVOID parameter) {
        THREAD_INFO info = {hThread, startAddress, parameter, GetTickCount()};
        processThreads[hProcess].push_back(info);
        
        // Analisar criação
        AnalyzeThreadCreation(hProcess, info);
    }
    
    void AnalyzeThreadCreation(HANDLE hProcess, const THREAD_INFO& info) {
        // Verificar se start address está em memória alocada dinamicamente
        if (IsDynamicMemoryAddress(info.startAddress)) {
            ReportDynamicThread(hProcess, info);
        }
        
        // Verificar parâmetro suspeito
        if (IsSuspiciousParameter(info.parameter)) {
            ReportSuspiciousThreadParameter(hProcess, info);
        }
        
        // Verificar frequência de criação
        if (HasHighThreadCreationRate(hProcess)) {
            ReportThreadSpam(hProcess);
        }
    }
    
    bool IsDynamicMemoryAddress(LPTHREAD_START_ROUTINE address) {
        MEMORY_BASIC_INFORMATION mbi;
        VirtualQuery(address, &mbi, sizeof(mbi));
        
        // Verificar se é MEM_COMMIT e não mapeamento de arquivo
        return mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE;
    }
    
    bool IsSuspiciousParameter(LPVOID parameter) {
        // Parâmetros que parecem ponteiros para estruturas DLL
        uintptr_t param = (uintptr_t)parameter;
        
        // Verificar se aponta para MZ header
        WORD mz;
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)param, &mz, sizeof(mz), NULL)) {
            if (mz == IMAGE_DOS_SIGNATURE) {
                return true; // Parece base de DLL
            }
        }
        
        return false;
    }
    
    bool HasHighThreadCreationRate(HANDLE hProcess) {
        auto& threads = processThreads[hProcess];
        if (threads.size() < 5) return false;
        
        DWORD currentTime = GetTickCount();
        DWORD timeWindow = 10000; // 10 segundos
        
        int recentThreads = 0;
        for (auto& thread : threads) {
            if (currentTime - thread.creationTime < timeWindow) {
                recentThreads++;
            }
        }
        
        return recentThreads > MAX_THREADS_PER_WINDOW;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory allocation | < 30s | 80% |
| VAC Live | IAT monitoring | Imediato | 85% |
| BattlEye | Thread analysis | < 1 min | 90% |
| Faceit AC | Import resolution | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. APC Injection
```cpp
// ✅ Injeção via APC (mais stealth)
class APCInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectViaAPC(const char* dllPath) {
        // Suspender threads do processo
        std::vector<HANDLE> threads = GetProcessThreads();
        for (HANDLE hThread : threads) {
            SuspendThread(hThread);
        }
        
        // Alocar memória para DLL path
        LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                          MEM_COMMIT, PAGE_READWRITE);
        if (!dllPathAddr) return false;
        
        // Escrever DLL path
        WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL);
        
        // Queue APC para LoadLibrary
        for (HANDLE hThread : threads) {
            QueueUserAPC((PAPCFUNC)LoadLibraryA, hThread, (ULONG_PTR)dllPathAddr);
        }
        
        // Resumir threads
        for (HANDLE hThread : threads) {
            ResumeThread(hThread);
            CloseHandle(hThread);
        }
        
        // Aguardar APC ser executada
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        
        return true;
    }
    
private:
    std::vector<HANDLE> GetProcessThreads() {
        std::vector<HANDLE> threads;
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return threads;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(THREADENTRY32);
        
        DWORD processId = GetProcessId(hProcess);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                    if (hThread) threads.push_back(hThread);
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return threads;
    }
};
```

### 2. Early Bird Injection
```cpp
// ✅ Early Bird APC Injection
class EarlyBirdInjector {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool InjectEarlyBird(const char* dllPath) {
        // Criar processo suspenso
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        if (!CreateProcessA(NULL, "notepad.exe", NULL, NULL, FALSE, 
                          CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            return false;
        }
        
        // Injetar antes do processo executar
        if (!InjectIntoSuspendedProcess(pi.hProcess, dllPath)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Resumir processo
        ResumeThread(pi.hThread);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }
    
private:
    bool InjectIntoSuspendedProcess(HANDLE hProcess, const char* dllPath) {
        // Alocar memória
        LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                          MEM_COMMIT, PAGE_READWRITE);
        if (!dllPathAddr) return false;
        
        // Escrever DLL path
        WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL);
        
        // Queue APC na thread principal
        QueueUserAPC((PAPCFUNC)LoadLibraryA, GetMainThread(hProcess), (ULONG_PTR)dllPathAddr);
        
        return true;
    }
    
    HANDLE GetMainThread(HANDLE hProcess) {
        // Encontrar thread principal do processo
        // Implementação simplificada
        return NULL; // Placeholder
    }
};
```

### 3. Thread Hijacking
```cpp
// ✅ Thread hijacking
class ThreadHijacker {
private:
    HANDLE hProcess;
    
public:
    void Initialize(DWORD processId) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    }
    
    bool HijackThread(const char* dllPath) {
        // Encontrar thread do processo alvo
        HANDLE hThread = FindTargetThread();
        if (!hThread) return false;
        
        // Suspender thread
        SuspendThread(hThread);
        
        // Salvar contexto
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        GetThreadContext(hThread, &context);
        
        // Alocar memória para código shell
        LPVOID shellCodeAddr = VirtualAllocEx(hProcess, NULL, SHELLCODE_SIZE,
                                            MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!shellCodeAddr) {
            ResumeThread(hThread);
            return false;
        }
        
        // Criar shellcode para LoadLibrary
        BYTE shellCode[] = {
            0x68, 0x00, 0x00, 0x00, 0x00, // PUSH dllPathAddr
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV EAX, LoadLibraryAddr
            0xFF, 0xD0,                    // CALL EAX
            0xCC                           // INT 3 (breakpoint para debug)
        };
        
        // Preencher endereços
        LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1,
                                          MEM_COMMIT, PAGE_READWRITE);
        WriteProcessMemory(hProcess, dllPathAddr, dllPath, strlen(dllPath) + 1, NULL);
        
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        uintptr_t loadLibraryAddr = (uintptr_t)GetProcAddress(hKernel32, "LoadLibraryA");
        
        *(DWORD*)&shellCode[1] = (DWORD)dllPathAddr;
        *(DWORD*)&shellCode[6] = (DWORD)loadLibraryAddr;
        
        // Escrever shellcode
        WriteProcessMemory(hProcess, shellCodeAddr, shellCode, sizeof(shellCode), NULL);
        
        // Modificar RIP/EIP para apontar para shellcode
#ifdef _WIN64
        context.Rip = (uintptr_t)shellCodeAddr;
#else
        context.Eip = (uintptr_t)shellCodeAddr;
#endif
        
        // Salvar endereço de retorno
        LPVOID returnAddr = VirtualAllocEx(hProcess, NULL, sizeof(uintptr_t),
                                         MEM_COMMIT, PAGE_READWRITE);
        *(uintptr_t*)returnAddr = context.Rip; // Endereço original
        
        // Executar shellcode
        SetThreadContext(hThread, &context);
        ResumeThread(hThread);
        
        // Aguardar execução
        Sleep(100);
        
        // Limpar
        VirtualFreeEx(hProcess, shellCodeAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        VirtualFreeEx(hProcess, returnAddr, 0, MEM_RELEASE);
        
        return true;
    }
    
private:
    HANDLE FindTargetThread() {
        // Encontrar thread adequada para hijacking
        // Preferencialmente thread idle
        return NULL; // Placeholder
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Injection Detection
```cpp
// VAC reflective injection detection
class VAC_InjectionDetector {
private:
    MemoryAllocationMonitor allocMonitor;
    IATMonitor iatMonitor;
    ThreadCreationAnalyzer threadAnalyzer;
    
public:
    void Initialize() {
        allocMonitor.Initialize();
        iatMonitor.Initialize();
        threadAnalyzer.Initialize();
    }
    
    void OnMemoryAllocation(HANDLE hProcess, LPVOID address, SIZE_T size, DWORD type, DWORD protect) {
        allocMonitor.OnVirtualAlloc(hProcess, address, size, type, protect);
    }
    
    void OnThreadCreate(HANDLE hProcess, HANDLE hThread, LPTHREAD_START_ROUTINE startAddr, LPVOID param) {
        threadAnalyzer.OnThreadCreate(hProcess, hThread, startAddr, param);
    }
    
    void OnModuleLoad(HANDLE hProcess, HMODULE hModule) {
        iatMonitor.OnModuleLoad(hModule);
    }
    
    void PeriodicInjectionCheck(HANDLE hProcess) {
        // Verificar IAT de módulos carregados
        EnumerateModules(hProcess);
        
        for (HMODULE hModule : loadedModules) {
            iatMonitor.CheckIATIntegrity(hModule);
        }
    }
};
```

### BattlEye Memory Analysis
```cpp
// BE memory injection detection
void BE_DetectMemoryInjections() {
    // Monitor all memory allocations
    MonitorMemoryAllocations();
    
    // Check for reflective loading patterns
    CheckReflectivePatterns();
    
    // Analyze thread behavior
    AnalyzeThreadBehavior();
}

void MonitorMemoryAllocations() {
    // Hook VirtualAlloc, VirtualAllocEx
    // Track suspicious allocations
}

void CheckReflectivePatterns() {
    // Look for DLL-like structures in memory
    // Check for relocation application
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Básica |
| 2020-2024 | ⚠️ Médio risco | Allocation monitoring |
| 2025-2026 | ⚠️ Alto risco | IAT analysis |

---

## 🎯 Lições Aprendidas

1. **Alocações São Monitoradas**: Grandes alocações executáveis são suspeitas.

2. **IAT é Verificada**: Modificações na tabela de imports são detectadas.

3. **Threads São Analisadas**: Criação de threads em memória dinâmica é rastreada.

4. **APC Injection é Mais Stealth**: Injeção via APC evita alguns detections.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#25]]
- [[APC_Injection]]
- [[Early_Bird_Injection]]
- [[Thread_Hijacking]]

---

*Reflective DLL injection tem risco moderado. Considere APC injection para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
