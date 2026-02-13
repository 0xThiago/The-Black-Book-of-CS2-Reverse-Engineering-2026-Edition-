# Técnica 038: Process Hollowing

> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Process & Memory  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Process Hollowing** cria um processo legítimo e substitui seu código por código malicioso, ocultando a execução. É usado para executar cheats sem criar processos suspeitos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class ProcessHollower {
private:
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    
public:
    void Initialize() {
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
    }
    
    bool HollowProcess(const char* targetPath, const char* payloadPath) {
        // Criar processo suspenso
        if (!CreateSuspendedProcess(targetPath)) {
            return false;
        }
        
        // Obter contexto do thread principal
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) {
            Cleanup();
            return false;
        }
        
        // Ler imagem do payload
        std::vector<BYTE> payloadImage;
        if (!ReadPayloadImage(payloadPath, payloadImage)) {
            Cleanup();
            return false;
        }
        
        // Hollow o processo
        if (!PerformHollowing(ctx, payloadImage)) {
            Cleanup();
            return false;
        }
        
        // Retomar thread
        ResumeThread(pi.hThread);
        
        return true;
    }
    
    void Cleanup() {
        if (pi.hProcess) CloseHandle(pi.hProcess);
        if (pi.hThread) CloseHandle(pi.hThread);
    }
    
private:
    bool CreateSuspendedProcess(const char* targetPath) {
        return CreateProcessA(
            targetPath,           // Executável legítimo (ex: notepad.exe)
            NULL,                 // Linha de comando
            NULL,                 // Atributos de processo
            NULL,                 // Atributos de thread
            FALSE,                // Herdar handles
            CREATE_SUSPENDED,     // Criar suspenso
            NULL,                 // Ambiente
            NULL,                 // Diretório atual
            &si,                  // Startup info
            &pi                   // Process info
        );
    }
    
    bool ReadPayloadImage(const char* payloadPath, std::vector<BYTE>& image) {
        HANDLE hFile = CreateFileA(payloadPath, GENERIC_READ, FILE_SHARE_READ, 
                                 NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            return false;
        }
        
        DWORD fileSize = GetFileSize(hFile, NULL);
        image.resize(fileSize);
        
        DWORD bytesRead;
        if (!ReadFile(hFile, image.data(), fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
            CloseHandle(hFile);
            return false;
        }
        
        CloseHandle(hFile);
        return true;
    }
    
    bool PerformHollowing(CONTEXT& ctx, const std::vector<BYTE>& payloadImage) {
        // Obter base da imagem no processo alvo
        PVOID imageBase = GetProcessImageBase(pi.hProcess);
        if (!imageBase) {
            return false;
        }
        
        // Desmapear imagem original
        if (!UnmapOriginalImage(pi.hProcess, imageBase)) {
            return false;
        }
        
        // Alocar memória para payload
        PVOID newImageBase = AllocateMemoryForPayload(pi.hProcess, payloadImage.size());
        if (!newImageBase) {
            return false;
        }
        
        // Escrever headers do payload
        if (!WritePayloadHeaders(pi.hProcess, newImageBase, payloadImage)) {
            return false;
        }
        
        // Escrever seções do payload
        if (!WritePayloadSections(pi.hProcess, newImageBase, payloadImage)) {
            return false;
        }
        
        // Aplicar relocações
        if (!ApplyRelocations(pi.hProcess, newImageBase, payloadImage)) {
            return false;
        }
        
        // Resolver imports
        if (!ResolveImports(pi.hProcess, newImageBase, payloadImage)) {
            return false;
        }
        
        // Atualizar contexto do thread
        UpdateThreadContext(ctx, newImageBase);
        
        // Definir contexto atualizado
        return SetThreadContext(pi.hThread, &ctx);
    }
    
    PVOID GetProcessImageBase(HANDLE hProcess) {
        // Ler PEB do processo
        PROCESS_BASIC_INFORMATION pbi;
        if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
            return NULL;
        }
        
        // Ler base da imagem do PEB
        PVOID imageBase;
        if (!ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, 
                             &imageBase, sizeof(imageBase), NULL)) {
            return NULL;
        }
        
        return imageBase;
    }
    
    bool UnmapOriginalImage(HANDLE hProcess, PVOID imageBase) {
        // Usar NtUnmapViewOfSection para desmapear
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        if (!hNtdll) return false;
        
        typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE, PVOID);
        NtUnmapViewOfSection_t pNtUnmapViewOfSection = 
            (NtUnmapViewOfSection_t)GetProcAddress(hNtdll, "NtUnmapViewOfSection");
        
        if (!pNtUnmapViewOfSection) return false;
        
        return pNtUnmapViewOfSection(hProcess, imageBase) == 0;
    }
    
    PVOID AllocateMemoryForPayload(HANDLE hProcess, SIZE_T payloadSize) {
        // Alocar memória no processo alvo
        return VirtualAllocEx(hProcess, NULL, payloadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    }
    
    bool WritePayloadHeaders(HANDLE hProcess, PVOID newImageBase, const std::vector<BYTE>& payloadImage) {
        // Parsear headers PE
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadImage.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payloadImage.data() + pDosHeader->e_lfanew);
        
        // Escrever headers
        SIZE_T headerSize = pNtHeaders->OptionalHeader.SizeOfHeaders;
        return WriteProcessMemory(hProcess, newImageBase, payloadImage.data(), headerSize, NULL);
    }
    
    bool WritePayloadSections(HANDLE hProcess, PVOID newImageBase, const std::vector<BYTE>& payloadImage) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadImage.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payloadImage.data() + pDosHeader->e_lfanew);
        
        PIMAGE_SECTION_HEADER pSectionHeader = IMAGE_FIRST_SECTION(pNtHeaders);
        
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            // Calcular RVA para VA
            PVOID sectionVA = (PBYTE)newImageBase + pSectionHeader[i].VirtualAddress;
            PVOID sectionData = (PBYTE)payloadImage.data() + pSectionHeader[i].PointerToRawData;
            
            // Escrever seção
            if (!WriteProcessMemory(hProcess, sectionVA, sectionData, 
                                  pSectionHeader[i].SizeOfRawData, NULL)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool ApplyRelocations(HANDLE hProcess, PVOID newImageBase, const std::vector<BYTE>& payloadImage) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadImage.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payloadImage.data() + pDosHeader->e_lfanew);
        
        // Calcular delta de relocação
        uintptr_t delta = (uintptr_t)newImageBase - pNtHeaders->OptionalHeader.ImageBase;
        
        if (delta == 0) return true; // Não precisa relocar
        
        // Encontrar diretório de relocações
        PIMAGE_DATA_DIRECTORY relocDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        if (relocDir->Size == 0) return true;
        
        PIMAGE_BASE_RELOCATION pReloc = (PIMAGE_BASE_RELOCATION)(payloadImage.data() + relocDir->VirtualAddress);
        
        while (pReloc->VirtualAddress != 0) {
            PWORD pRelocData = (PWORD)((PBYTE)pReloc + sizeof(IMAGE_BASE_RELOCATION));
            DWORD numEntries = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            
            for (DWORD i = 0; i < numEntries; i++) {
                if (pRelocData[i] != 0) {
                    WORD type = pRelocData[i] >> 12;
                    WORD offset = pRelocData[i] & 0xFFF;
                    
                    if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                        PVOID relocAddr = (PBYTE)newImageBase + pReloc->VirtualAddress + offset;
                        
                        uintptr_t value;
                        if (!ReadProcessMemory(hProcess, relocAddr, &value, sizeof(value), NULL)) {
                            return false;
                        }
                        
                        value += delta;
                        
                        if (!WriteProcessMemory(hProcess, relocAddr, &value, sizeof(value), NULL)) {
                            return false;
                        }
                    }
                }
            }
            
            pReloc = (PIMAGE_BASE_RELOCATION)((PBYTE)pReloc + pReloc->SizeOfBlock);
        }
        
        return true;
    }
    
    bool ResolveImports(HANDLE hProcess, PVOID newImageBase, const std::vector<BYTE>& payloadImage) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadImage.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payloadImage.data() + pDosHeader->e_lfanew);
        
        // Encontrar diretório de imports
        PIMAGE_DATA_DIRECTORY importDir = &pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir->Size == 0) return true;
        
        PIMAGE_IMPORT_DESCRIPTOR pImportDesc = (PIMAGE_IMPORT_DESCRIPTOR)(payloadImage.data() + importDir->VirtualAddress);
        
        for (; pImportDesc->Name != 0; pImportDesc++) {
            // Obter nome da DLL
            PSTR dllName = (PSTR)(payloadImage.data() + pImportDesc->Name);
            
            // Carregar DLL no processo alvo
            HMODULE hModule = LoadLibraryA(dllName);
            if (!hModule) {
                // Tentar carregar no contexto do processo alvo
                hModule = GetModuleHandleInProcess(hProcess, dllName);
                if (!hModule) continue;
            }
            
            // Resolver imports
            if (!ResolveImportTable(hProcess, newImageBase, pImportDesc, payloadImage, hModule)) {
                return false;
            }
        }
        
        return true;
    }
    
    bool ResolveImportTable(HANDLE hProcess, PVOID newImageBase, PIMAGE_IMPORT_DESCRIPTOR pImportDesc,
                          const std::vector<BYTE>& payloadImage, HMODULE hModule) {
        PIMAGE_THUNK_DATA pThunk = (PIMAGE_THUNK_DATA)(payloadImage.data() + pImportDesc->OriginalFirstThunk);
        PIMAGE_THUNK_DATA pFuncThunk = (PIMAGE_THUNK_DATA)((PBYTE)newImageBase + pImportDesc->FirstThunk);
        
        for (; pThunk->u1.AddressOfData != 0; pThunk++, pFuncThunk++) {
            if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                // Import by ordinal
                DWORD ordinal = IMAGE_ORDINAL(pThunk->u1.Ordinal);
                PVOID funcAddr = GetProcAddress(hModule, (LPCSTR)ordinal);
                
                if (!WriteProcessMemory(hProcess, &pFuncThunk->u1.Function, &funcAddr, sizeof(funcAddr), NULL)) {
                    return false;
                }
            } else {
                // Import by name
                PIMAGE_IMPORT_BY_NAME pImport = (PIMAGE_IMPORT_BY_NAME)(payloadImage.data() + pThunk->u1.AddressOfData);
                PVOID funcAddr = GetProcAddress(hModule, pImport->Name);
                
                if (!WriteProcessMemory(hProcess, &pFuncThunk->u1.Function, &funcAddr, sizeof(funcAddr), NULL)) {
                    return false;
                }
            }
        }
        
        return true;
    }
    
    void UpdateThreadContext(CONTEXT& ctx, PVOID newImageBase) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)payloadImage.data();
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)(payloadImage.data() + pDosHeader->e_lfanew);
        
        // Atualizar entry point
        ctx.Rcx = (uintptr_t)newImageBase + pNtHeaders->OptionalHeader.AddressOfEntryPoint;
        
        // Atualizar image base
        ctx.Rdx = (uintptr_t)newImageBase;
    }
    
    HMODULE GetModuleHandleInProcess(HANDLE hProcess, const char* moduleName) {
        // Enumerar módulos no processo alvo
        // Usar CreateToolhelp32Snapshot ou NtQueryInformationProcess
        
        return NULL; // Placeholder
    }
};
```

### Advanced Process Hollowing

```cpp
// Hollowing avançado com múltiplas seções
class AdvancedProcessHollower : public ProcessHollower {
private:
    std::vector<MEMORY_REGION> preservedRegions;
    
public:
    bool AdvancedHollowProcess(const char* targetPath, const std::vector<std::string>& payloads) {
        // Criar processo suspenso
        if (!CreateSuspendedProcess(targetPath)) {
            return false;
        }
        
        // Preservar regiões importantes
        PreserveImportantRegions();
        
        // Hollow com múltiplos payloads
        for (const std::string& payload : payloads) {
            if (!InjectPayload(payload)) {
                return false;
            }
        }
        
        // Restaurar regiões preservadas
        RestorePreservedRegions();
        
        // Retomar thread
        ResumeThread(pi.hThread);
        
        return true;
    }
    
private:
    void PreserveImportantRegions() {
        // Preservar .data section
        // Preservar heap inicial
        // Preservar TEB/PEB
        
        // ... código para preservar regiões ...
    }
    
    bool InjectPayload(const std::string& payloadPath) {
        // Injetar payload adicional
        // Criar nova seção ou usar memória existente
        
        return true; // Placeholder
    }
    
    void RestorePreservedRegions() {
        // Restaurar regiões preservadas
        // ... código para restaurar ...
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Process hollowing deixa rastros através de diferenças na imagem de memória e comportamento suspeito**

#### 1. Memory Image Analysis
```cpp
// Análise de imagem de memória
class ProcessMemoryAnalyzer {
private:
    std::map<DWORD, PROCESS_SIGNATURE> processSignatures;
    
public:
    void Initialize() {
        // Registrar assinaturas de processos legítimos
        RegisterProcessSignatures();
    }
    
    void AnalyzeProcessMemory(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) return;
        
        // Verificar assinatura da imagem
        if (!VerifyProcessSignature(hProcess, processId)) {
            ReportHollowedProcess(processId);
        }
        
        // Verificar regiões de memória suspeitas
        CheckMemoryRegions(hProcess);
        
        CloseHandle(hProcess);
    }
    
    void RegisterProcessSignatures() {
        // Registrar hash das imagens originais
        // notepad.exe, calc.exe, etc.
        
        // ... código para registrar ...
    }
    
    bool VerifyProcessSignature(HANDLE hProcess, DWORD processId) {
        // Obter caminho do executável
        char exePath[MAX_PATH];
        if (!GetProcessImageFileNameA(hProcess, exePath, MAX_PATH)) {
            return false;
        }
        
        // Calcular hash da imagem em memória
        UCHAR memoryHash[32];
        if (!CalculateMemoryImageHash(hProcess, memoryHash)) {
            return false;
        }
        
        // Comparar com hash esperado
        UCHAR expectedHash[32];
        if (!GetExpectedImageHash(exePath, expectedHash)) {
            return false; // Não temos assinatura
        }
        
        return memcmp(memoryHash, expectedHash, 32) == 0;
    }
    
    bool CalculateMemoryImageHash(HANDLE hProcess, UCHAR* hash) {
        // Obter base da imagem
        PVOID imageBase = GetProcessImageBase(hProcess);
        if (!imageBase) return false;
        
        // Ler headers
        IMAGE_DOS_HEADER dosHeader;
        if (!ReadProcessMemory(hProcess, imageBase, &dosHeader, sizeof(dosHeader), NULL)) {
            return false;
        }
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) return false;
        
        IMAGE_NT_HEADERS ntHeaders;
        if (!ReadProcessMemory(hProcess, (PBYTE)imageBase + dosHeader.e_lfanew, 
                             &ntHeaders, sizeof(ntHeaders), NULL)) {
            return false;
        }
        
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return false;
        
        // Calcular hash da imagem
        SIZE_T imageSize = ntHeaders.OptionalHeader.SizeOfImage;
        std::vector<BYTE> imageData(imageSize);
        
        if (!ReadProcessMemory(hProcess, imageBase, imageData.data(), imageSize, NULL)) {
            return false;
        }
        
        // Usar SHA256
        CalculateSHA256(imageData.data(), imageSize, hash);
        
        return true;
    }
    
    bool GetExpectedImageHash(const char* exePath, UCHAR* hash) {
        // Obter hash esperado do arquivo em disco
        HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return false;
        
        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> fileData(fileSize);
        
        DWORD bytesRead;
        ReadFile(hFile, fileData.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        
        if (bytesRead != fileSize) return false;
        
        CalculateSHA256(fileData.data(), fileSize, hash);
        return true;
    }
    
    void CheckMemoryRegions(HANDLE hProcess) {
        // Enumerar regiões de memória
        MEMORY_BASIC_INFORMATION mbi;
        PVOID address = NULL;
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            // Verificar regiões suspeitas
            if (IsSuspiciousMemoryRegion(mbi)) {
                ReportSuspiciousMemoryRegion(address, mbi.RegionSize);
            }
            
            address = (PBYTE)address + mbi.RegionSize;
        }
    }
    
    bool IsSuspiciousMemoryRegion(const MEMORY_BASIC_INFORMATION& mbi) {
        // Regiões executáveis grandes
        if ((mbi.Protect & PAGE_EXECUTE_READWRITE) && mbi.RegionSize > 0x100000) {
            return true;
        }
        
        // Regiões com proteção suspeita
        if (mbi.Protect & PAGE_GUARD) {
            return true;
        }
        
        return false;
    }
    
    void CalculateSHA256(const BYTE* data, SIZE_T size, UCHAR* hash) {
        // Implementar SHA256
        // Usar BCrypt ou similar
        
        // Placeholder: usar CRC32 simples
        *(uint32_t*)hash = RtlComputeCrc32(0, data, size);
    }
};
```

#### 2. Thread Context Analysis
```cpp
// Análise de contexto de thread
class ThreadContextAnalyzer {
private:
    std::map<DWORD, THREAD_CONTEXT_INFO> threadContexts;
    
public:
    void AnalyzeThreadContext(DWORD processId, DWORD threadId) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, threadId);
        if (!hThread) return;
        
        // Suspender thread
        SuspendThread(hThread);
        
        // Obter contexto
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(hThread, &ctx)) {
            // Analisar contexto
            if (IsSuspiciousThreadContext(ctx)) {
                ReportSuspiciousThreadContext(processId, threadId);
            }
            
            // Verificar se entry point foi modificado
            if (IsModifiedEntryPoint(ctx, processId)) {
                ReportModifiedEntryPoint(processId, threadId);
            }
        }
        
        // Retomar thread
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
    
    bool IsSuspiciousThreadContext(const CONTEXT& ctx) {
        // Verificar registros suspeitos
        // RCX/RDX modificados para apontar para memória alocada
        
        // Verificar se RIP está em região suspeita
        if (IsAddressInAllocatedMemory(ctx.Rip)) {
            return true;
        }
        
        return false;
    }
    
    bool IsModifiedEntryPoint(const CONTEXT& ctx, DWORD processId) {
        // Obter entry point esperado
        PVOID expectedEntryPoint = GetExpectedEntryPoint(processId);
        
        // Comparar com RIP atual
        return ctx.Rip != (uintptr_t)expectedEntryPoint;
    }
    
    PVOID GetExpectedEntryPoint(DWORD processId) {
        // Obter caminho do executável
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) return NULL;
        
        char exePath[MAX_PATH];
        GetProcessImageFileNameA(hProcess, exePath, MAX_PATH);
        CloseHandle(hProcess);
        
        // Ler entry point do arquivo
        HANDLE hFile = CreateFileA(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return NULL;
        
        IMAGE_DOS_HEADER dosHeader;
        DWORD bytesRead;
        ReadFile(hFile, &dosHeader, sizeof(dosHeader), &bytesRead, NULL);
        
        if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
            CloseHandle(hFile);
            return NULL;
        }
        
        IMAGE_NT_HEADERS ntHeaders;
        SetFilePointer(hFile, dosHeader.e_lfanew, NULL, FILE_BEGIN);
        ReadFile(hFile, &ntHeaders, sizeof(ntHeaders), &bytesRead, NULL);
        CloseHandle(hFile);
        
        if (ntHeaders.Signature != IMAGE_NT_SIGNATURE) return NULL;
        
        // Calcular endereço virtual do entry point
        return (PVOID)(ntHeaders.OptionalHeader.ImageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint);
    }
    
    bool IsAddressInAllocatedMemory(uintptr_t address) {
        // Verificar se endereço está em memória alocada dinamicamente
        // Comparar com regiões de memória do processo
        
        return false; // Placeholder
    }
};
```

#### 3. Behavioral Analysis
```cpp
// Análise comportamental
class ProcessBehaviorAnalyzer {
private:
    std::map<DWORD, PROCESS_BEHAVIOR> processBehaviors;
    
public:
    void MonitorProcessBehavior(DWORD processId) {
        // Registrar comportamento inicial
        RegisterInitialBehavior(processId);
        
        // Monitorar mudanças
        StartBehaviorMonitoring(processId);
    }
    
    void RegisterInitialBehavior(DWORD processId) {
        PROCESS_BEHAVIOR behavior;
        
        // Registrar módulos carregados
        EnumerateLoadedModules(processId, behavior.loadedModules);
        
        // Registrar threads
        EnumerateProcessThreads(processId, behavior.threads);
        
        // Registrar handles
        EnumerateProcessHandles(processId, behavior.handles);
        
        processBehaviors[processId] = behavior;
    }
    
    void StartBehaviorMonitoring(DWORD processId) {
        // Monitorar em thread separado
        std::thread([this, processId]() {
            while (true) {
                CheckBehaviorChanges(processId);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }).detach();
    }
    
    void CheckBehaviorChanges(DWORD processId) {
        if (processBehaviors.find(processId) == processBehaviors.end()) return;
        
        PROCESS_BEHAVIOR& behavior = processBehaviors[processId];
        
        // Verificar mudanças nos módulos
        std::vector<HMODULE> currentModules;
        EnumerateLoadedModules(processId, currentModules);
        
        if (currentModules != behavior.loadedModules) {
            ReportModuleChanges(processId);
        }
        
        // Verificar mudanças nos threads
        std::vector<DWORD> currentThreads;
        EnumerateProcessThreads(processId, currentThreads);
        
        if (currentThreads != behavior.threads) {
            ReportThreadChanges(processId);
        }
        
        // Verificar uso de memória
        if (IsAbnormalMemoryUsage(processId)) {
            ReportAbnormalMemoryUsage(processId);
        }
    }
    
    void EnumerateLoadedModules(DWORD processId, std::vector<HMODULE>& modules) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, processId);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        MODULEENTRY32 me;
        me.dwSize = sizeof(me);
        
        if (Module32First(hSnapshot, &me)) {
            do {
                modules.push_back(me.hModule);
            } while (Module32Next(hSnapshot, &me));
        }
        
        CloseHandle(hSnapshot);
    }
    
    void EnumerateProcessThreads(DWORD processId, std::vector<DWORD>& threads) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    threads.push_back(te.th32ThreadID);
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
    }
    
    void EnumerateProcessHandles(DWORD processId, std::vector<HANDLE>& handles) {
        // Usar NtQueryInformationProcess com ProcessHandleInformation
        // ... código para enumerar handles ...
    }
    
    bool IsAbnormalMemoryUsage(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
        if (!hProcess) return false;
        
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc))) {
            // Verificar uso de memória anormal
            if (pmc.WorkingSetSize > 500 * 1024 * 1024) { // 500MB
                CloseHandle(hProcess);
                return true;
            }
        }
        
        CloseHandle(hProcess);
        return false;
    }
    
    void ReportModuleChanges(DWORD processId) {
        // Reportar mudanças nos módulos carregados
    }
    
    void ReportThreadChanges(DWORD processId) {
        // Reportar mudanças nos threads
    }
    
    void ReportAbnormalMemoryUsage(DWORD processId) {
        // Reportar uso anormal de memória
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory image analysis | < 30s | 85% |
| VAC Live | Thread context check | Imediato | 80% |
| BattlEye | Behavioral analysis | < 1 min | 90% |
| Faceit AC | Module enumeration | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. DLL Injection
```cpp
// ✅ DLL injection (mais simples e detectável)
class DLLInjector {
public:
    bool InjectDLL(DWORD processId, const char* dllPath) {
        // Abrir processo
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        // Alocar memória para caminho da DLL
        LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, 
                                       MEM_COMMIT, PAGE_READWRITE);
        if (!pDllPath) {
            CloseHandle(hProcess);
            return false;
        }
        
        // Escrever caminho da DLL
        if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL)) {
            VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Criar thread remoto para carregar DLL
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                          (LPTHREAD_START_ROUTINE)LoadLibraryA, 
                                          pDllPath, 0, NULL);
        
        if (hThread) {
            // Aguardar thread terminar
            WaitForSingleObject(hThread, 5000);
            CloseHandle(hThread);
        }
        
        // Limpar
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        
        return hThread != NULL;
    }
};
```

### 2. APC Injection
```cpp
// ✅ APC injection (mais stealth)
class APCInjector {
public:
    bool InjectViaAPC(DWORD processId, const char* dllPath) {
        // Obter handle do processo
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        // Alocar memória para DLL
        std::vector<BYTE> dllData = ReadFileToMemory(dllPath);
        if (dllData.empty()) {
            CloseHandle(hProcess);
            return false;
        }
        
        LPVOID pRemoteDll = VirtualAllocEx(hProcess, NULL, dllData.size(), 
                                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteDll) {
            CloseHandle(hProcess);
            return false;
        }
        
        // Escrever DLL na memória
        if (!WriteProcessMemory(hProcess, pRemoteDll, dllData.data(), dllData.size(), NULL)) {
            VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Encontrar thread no processo alvo
        DWORD threadId = FindThreadInProcess(processId);
        if (!threadId) {
            VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Abrir thread
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, threadId);
        if (!hThread) {
            VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Queue APC
        if (QueueUserAPC((PAPCFUNC)pRemoteDll, hThread, NULL)) {
            // Aguardar APC executar
            Sleep(100);
        }
        
        CloseHandle(hThread);
        CloseHandle(hProcess);
        
        return true;
    }
    
private:
    DWORD FindThreadInProcess(DWORD processId) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
        
        THREADENTRY32 te;
        te.dwSize = sizeof(te);
        
        if (Thread32First(hSnapshot, &te)) {
            do {
                if (te.th32OwnerProcessID == processId) {
                    CloseHandle(hSnapshot);
                    return te.th32ThreadID;
                }
            } while (Thread32Next(hSnapshot, &te));
        }
        
        CloseHandle(hSnapshot);
        return 0;
    }
    
    std::vector<BYTE> ReadFileToMemory(const char* filePath) {
        HANDLE hFile = CreateFileA(filePath, GENERIC_READ, FILE_SHARE_READ, NULL, 
                                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile == INVALID_HANDLE_VALUE) return {};
        
        DWORD fileSize = GetFileSize(hFile, NULL);
        std::vector<BYTE> data(fileSize);
        
        DWORD bytesRead;
        ReadFile(hFile, data.data(), fileSize, &bytesRead, NULL);
        CloseHandle(hFile);
        
        if (bytesRead != fileSize) return {};
        return data;
    }
};
```

### 3. Reflective DLL Injection
```cpp
// ✅ Reflective DLL injection (mais avançado)
class ReflectiveInjector {
public:
    bool ReflectiveInject(DWORD processId, const char* dllPath) {
        // Ler DLL
        std::vector<BYTE> dllData = ReadFileToMemory(dllPath);
        if (dllData.empty()) return false;
        
        // Obter handle do processo
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
        if (!hProcess) return false;
        
        // Alocar memória para DLL
        LPVOID pRemoteDll = VirtualAllocEx(hProcess, NULL, dllData.size(), 
                                         MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!pRemoteDll) {
            CloseHandle(hProcess);
            return false;
        }
        
        // Escrever DLL
        if (!WriteProcessMemory(hProcess, pRemoteDll, dllData.data(), dllData.size(), NULL)) {
            VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Executar reflective loader
        if (!ExecuteReflectiveLoader(hProcess, pRemoteDll)) {
            VirtualFreeEx(hProcess, pRemoteDll, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        CloseHandle(hProcess);
        return true;
    }
    
private:
    bool ExecuteReflectiveLoader(HANDLE hProcess, LPVOID pRemoteDll) {
        // Encontrar função de reflective loading na DLL
        // Executar através de thread remoto
        
        // ... código para reflective loading ...
        
        return true; // Placeholder
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Memory analysis |
| 2020-2024 | ⚠️ Médio risco | Behavioral analysis |
| 2025-2026 | ⚠️ Alto risco | Advanced detection |

---

## 🎯 Lições Aprendidas

1. **Imagem de Memória é Verificada**: Hash da imagem em memória é comparado com arquivo em disco.

2. **Contexto de Thread é Analisado**: Entry point e registros são verificados.

3. **Comportamento é Monitorado**: Mudanças em módulos e threads são rastreadas.

4. **DLL Injection é Mais Simples**: Métodos mais diretos são preferíveis quando funcionam.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#38]]
- [[DLL_Injection]]
- [[APC_Injection]]
- [[Reflective_DLL_Injection]]

---

*Process hollowing tem risco moderado. Considere DLL injection para mais simplicidade.*