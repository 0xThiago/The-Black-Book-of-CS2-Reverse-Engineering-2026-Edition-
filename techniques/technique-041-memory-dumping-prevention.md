# Técnica 041: Memory Dumping Prevention

> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Memory Dumping Prevention** impede que ferramentas de análise façam dump da memória do processo, protegendo código e dados sensíveis contra engenharia reversa.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class MemoryDumpProtector {
private:
    std::vector<MEMORY_REGION> protectedRegions;
    std::vector<DUMP_PREVENTION_TECHNIQUE> techniques;
    HANDLE hProcess;
    
public:
    MemoryDumpProtector() {
        hProcess = GetCurrentProcess();
        InitializeTechniques();
    }
    
    void InitializeTechniques() {
        // Técnicas de prevenção de dump
        techniques.push_back({TECHNIQUE_PAGE_PROTECTION, "PAGE_GUARD protection"});
        techniques.push_back({TECHNIQUE_ENCRYPTED_MEMORY, "Memory encryption"});
        techniques.push_back({TECHNIQUE_HOOKED_APIS, "API hooking"});
        techniques.push_back({TECHNIQUE_INTEGRITY_CHECKS, "Memory integrity checks"});
        techniques.push_back({TECHNIQUE_TIME_BOMBS, "Time-based corruption"});
    }
    
    void ProtectMemoryRegions() {
        // Proteger regiões críticas
        ProtectCodeSections();
        ProtectDataSections();
        ProtectHeapAllocations();
        ProtectStackRegions();
    }
    
    void ProtectCodeSections() {
        // Proteger seções de código
        PVOID imageBase = GetModuleHandle(NULL);
        
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
                // Seção executável - aplicar proteção
                ProtectRegion((PBYTE)imageBase + pSection[i].VirtualAddress, 
                            pSection[i].Misc.VirtualSize, &pSection[i]);
            }
        }
    }
    
    void ProtectDataSections() {
        // Proteger seções de dados
        PVOID imageBase = GetModuleHandle(NULL);
        
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pDosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if ((pSection[i].Characteristics & IMAGE_SCN_MEM_READ) &&
                !(pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
                // Seção de dados - aplicar proteção
                ProtectRegion((PBYTE)imageBase + pSection[i].VirtualAddress, 
                            pSection[i].Misc.VirtualSize, &pSection[i]);
            }
        }
    }
    
    void ProtectHeapAllocations() {
        // Proteger alocações do heap
        // Hook RtlAllocateHeap e RtlFreeHeap
        HookHeapAPIs();
    }
    
    void ProtectStackRegions() {
        // Proteger regiões da stack
        // Usar fiber local storage ou similar
    }
    
    void ProtectRegion(PVOID address, SIZE_T size, PIMAGE_SECTION_HEADER pSection) {
        MEMORY_REGION region;
        region.address = address;
        region.size = size;
        region.originalProtection = 0;
        region.pSection = pSection;
        
        // Obter proteção atual
        VirtualQuery(address, &region.mbi, sizeof(region.mbi));
        
        // Aplicar técnicas de proteção
        for (const DUMP_PREVENTION_TECHNIQUE& tech : techniques) {
            ApplyProtectionTechnique(region, tech);
        }
        
        protectedRegions.push_back(region);
    }
    
    void ApplyProtectionTechnique(MEMORY_REGION& region, const DUMP_PREVENTION_TECHNIQUE& tech) {
        switch (tech.type) {
            case TECHNIQUE_PAGE_PROTECTION:
                ApplyPageGuardProtection(region);
                break;
            case TECHNIQUE_ENCRYPTED_MEMORY:
                ApplyMemoryEncryption(region);
                break;
            case TECHNIQUE_HOOKED_APIS:
                ApplyAPIHooking(region);
                break;
            case TECHNIQUE_INTEGRITY_CHECKS:
                ApplyIntegrityChecks(region);
                break;
            case TECHNIQUE_TIME_BOMBS:
                ApplyTimeBombs(region);
                break;
        }
    }
    
    void ApplyPageGuardProtection(MEMORY_REGION& region) {
        // Aplicar PAGE_GUARD
        DWORD oldProtect;
        VirtualProtect(region.address, region.size, 
                      region.mbi.Protect | PAGE_GUARD, &oldProtect);
        
        region.originalProtection = oldProtect;
    }
    
    void ApplyMemoryEncryption(MEMORY_REGION& region) {
        // Encriptar conteúdo da memória
        std::vector<BYTE> data((BYTE*)region.address, (BYTE*)region.address + region.size);
        
        // Gerar chave única para esta região
        std::string key = GenerateRegionKey(region);
        
        // Encriptar dados
        EncryptMemoryRegion(data, key);
        
        // Escrever dados encriptados de volta
        memcpy(region.address, data.data(), data.size());
        
        // Registrar para decriptação posterior
        region.isEncrypted = true;
        region.encryptionKey = key;
    }
    
    void ApplyAPIHooking(MEMORY_REGION& region) {
        // Hook APIs relacionadas a dump
        HookMiniDumpWriteDump();
        HookReadProcessMemory();
        HookVirtualQuery();
    }
    
    void ApplyIntegrityChecks(MEMORY_REGION& region) {
        // Calcular hash da região
        region.integrityHash = CalculateRegionHash(region);
        
        // Registrar para verificações periódicas
        StartIntegrityMonitoring(region);
    }
    
    void ApplyTimeBombs(MEMORY_REGION& region) {
        // Adicionar código que corrompe memória após tempo
        region.timeBombSet = true;
        region.timeBombTimer = GetTickCount() + (rand() % 300000) + 60000; // 1-6 minutos
    }
    
    void HookHeapAPIs() {
        // Hook RtlAllocateHeap
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        PVOID pRtlAllocateHeap = GetProcAddress(hNtdll, "RtlAllocateHeap");
        
        MH_CreateHook(pRtlAllocateHeap, &HkRtlAllocateHeap, &oRtlAllocateHeap);
        MH_EnableHook(pRtlAllocateHeap);
        
        // Hook RtlFreeHeap
        PVOID pRtlFreeHeap = GetProcAddress(hNtdll, "RtlFreeHeap");
        MH_CreateHook(pRtlFreeHeap, &HkRtlFreeHeap, &oRtlFreeHeap);
        MH_EnableHook(pRtlFreeHeap);
    }
    
    void HookMiniDumpWriteDump() {
        // Hook MiniDumpWriteDump (dbghelp.dll)
        HMODULE hDbghelp = LoadLibraryA("dbghelp.dll");
        if (hDbghelp) {
            PVOID pMiniDumpWriteDump = GetProcAddress(hDbghelp, "MiniDumpWriteDump");
            if (pMiniDumpWriteDump) {
                MH_CreateHook(pMiniDumpWriteDump, &HkMiniDumpWriteDump, &oMiniDumpWriteDump);
                MH_EnableHook(pMiniDumpWriteDump);
            }
        }
    }
    
    void HookReadProcessMemory() {
        // Hook ReadProcessMemory
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pReadProcessMemory = GetProcAddress(hKernel32, "ReadProcessMemory");
        
        MH_CreateHook(pReadProcessMemory, &HkReadProcessMemory, &oReadProcessMemory);
        MH_EnableHook(pReadProcessMemory);
    }
    
    void HookVirtualQuery() {
        // Hook VirtualQuery
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pVirtualQuery = GetProcAddress(hKernel32, "VirtualQuery");
        
        MH_CreateHook(pVirtualQuery, &HkVirtualQuery, &oVirtualQuery);
        MH_EnableHook(pVirtualQuery);
    }
    
    void StartIntegrityMonitoring(const MEMORY_REGION& region) {
        // Thread para verificar integridade
        std::thread([this, region]() {
            while (true) {
                if (CheckRegionIntegrity(region)) {
                    // Integridade OK
                } else {
                    // Integridade comprometida - ação
                    OnIntegrityViolation(region);
                }
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }).detach();
    }
    
    bool CheckRegionIntegrity(const MEMORY_REGION& region) {
        std::string currentHash = CalculateRegionHash(region);
        return currentHash == region.integrityHash;
    }
    
    void OnIntegrityViolation(const MEMORY_REGION& region) {
        // Memória foi modificada - possível dump attempt
        CorruptMemoryRegion(region);
        LogDumpAttempt();
    }
    
    void CorruptMemoryRegion(const MEMORY_REGION& region) {
        // Corromper região de memória
        memset(region.address, 0xCC, region.size);
    }
    
    void LogDumpAttempt() {
        // Log tentativa de dump
        std::ofstream log("dump_attempts.log", std::ios::app);
        log << "Memory dump attempt detected at " << std::time(nullptr) << std::endl;
        log.close();
    }
    
    std::string GenerateRegionKey(const MEMORY_REGION& region) {
        // Gerar chave baseada no endereço da região
        std::stringstream ss;
        ss << (uintptr_t)region.address << rand();
        return ss.str();
    }
    
    void EncryptMemoryRegion(std::vector<BYTE>& data, const std::string& key) {
        // Encriptação simples XOR para exemplo
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= key[i % key.size()];
        }
    }
    
    std::string CalculateRegionHash(const MEMORY_REGION& region) {
        // Calcular hash SHA256 da região
        // Usar Crypto++ ou similar
        return "dummy_hash"; // Placeholder
    }
    
    // Hooks
    static PVOID WINAPI HkRtlAllocateHeap(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes) {
        // Hook para RtlAllocateHeap
        PVOID result = oRtlAllocateHeap(hHeap, dwFlags, dwBytes);
        
        if (result && dwBytes > 1024) { // Alocações grandes
            // Proteger nova alocação
            ProtectNewAllocation(result, dwBytes);
        }
        
        return result;
    }
    
    static BOOLEAN WINAPI HkRtlFreeHeap(HANDLE hHeap, DWORD dwFlags, PVOID lpMem) {
        // Hook para RtlFreeHeap
        // Verificar se era uma região protegida
        UnprotectAllocation(lpMem);
        
        return oRtlFreeHeap(hHeap, dwFlags, lpMem);
    }
    
    static BOOL WINAPI HkMiniDumpWriteDump(HANDLE hProcess, DWORD ProcessId,
                                         HANDLE hFile, MINIDUMP_TYPE DumpType,
                                         PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
                                         PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
                                         PMINIDUMP_CALLBACK_INFORMATION CallbackParam) {
        // Impedir dumps
        SetLastError(ERROR_ACCESS_DENIED);
        return FALSE;
    }
    
    static BOOL WINAPI HkReadProcessMemory(HANDLE hProcess, LPCVOID lpBaseAddress,
                                         LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) {
        // Verificar se está tentando ler regiões protegidas
        if (IsProtectedRegion(lpBaseAddress, nSize)) {
            // Retornar dados falsos ou erro
            memset(lpBuffer, 0x00, nSize);
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = nSize;
            return TRUE; // Sucesso mas dados falsos
        }
        
        return oReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }
    
    static SIZE_T WINAPI HkVirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
        // Modificar informações de regiões protegidas
        SIZE_T result = oVirtualQuery(lpAddress, lpBuffer, dwLength);
        
        if (result && IsProtectedRegion(lpAddress, 1)) {
            // Modificar informações para confundir
            lpBuffer->Protect = PAGE_NOACCESS;
            lpBuffer->State = MEM_RESERVE;
        }
        
        return result;
    }
    
    static void ProtectNewAllocation(PVOID address, SIZE_T size) {
        // Adicionar proteção a nova alocação
        MEMORY_REGION region;
        region.address = address;
        region.size = size;
        
        DWORD oldProtect;
        VirtualProtect(address, size, PAGE_READWRITE | PAGE_GUARD, &oldProtect);
        
        // Registrar
        // protectedRegions.push_back(region);
    }
    
    static void UnprotectAllocation(PVOID address) {
        // Remover proteção de alocação sendo liberada
        // ...
    }
    
    static bool IsProtectedRegion(LPCVOID address, SIZE_T size) {
        // Verificar se endereço está em região protegida
        return false; // Placeholder
    }
    
    // Original function pointers
    static decltype(&RtlAllocateHeap) oRtlAllocateHeap;
    static decltype(&RtlFreeHeap) oRtlFreeHeap;
    static decltype(&MiniDumpWriteDump) oMiniDumpWriteDump;
    static decltype(&ReadProcessMemory) oReadProcessMemory;
    static decltype(&VirtualQuery) oVirtualQuery;
};
```

### Advanced Memory Protection

```cpp
// Proteções avançadas de memória
class AdvancedMemoryProtector : public MemoryDumpProtector {
private:
    VEH_HANDLER vehHandler;
    std::vector<MEMORY_TRAP> memoryTraps;
    CRYPTO_CONTEXT cryptoContext;
    
public:
    AdvancedMemoryProtector() {
        InitializeVEH();
        InitializeCrypto();
        SetupMemoryTraps();
    }
    
    void InitializeVEH() {
        // Instalar Vectored Exception Handler
        vehHandler = AddVectoredExceptionHandler(1, VectoredExceptionHandler);
    }
    
    void InitializeCrypto() {
        // Inicializar contexto criptográfico
        cryptoContext.algorithm = CRYPTO_AES256;
        cryptoContext.key = GenerateCryptoKey();
        cryptoContext.iv = GenerateIV();
    }
    
    void SetupMemoryTraps() {
        // Configurar traps de memória
        memoryTraps.push_back({TRAP_PAGE_GUARD, "PAGE_GUARD violations"});
        memoryTraps.push_back({TRAP_ACCESS_VIOLATION, "Access violations"});
        memoryTraps.push_back({TRAP_ILLEGAL_INSTRUCTION, "Illegal instructions"});
    }
    
    void ApplyAdvancedProtections() {
        // Aplicar proteções avançadas
        ProtectWithHardwareBreakpoints();
        ImplementMemoryEncryption();
        SetupIntegrityVerification();
        DeployTimeBasedCorruption();
    }
    
    void ProtectWithHardwareBreakpoints() {
        // Usar hardware breakpoints para proteger regiões críticas
        SetHardwareBreakpoint((PVOID)&MemoryDumpProtector::ProtectMemoryRegions, 0);
        SetHardwareBreakpoint((PVOID)&MemoryDumpProtector::ApplyProtectionTechnique, 1);
    }
    
    void SetHardwareBreakpoint(PVOID address, int index) {
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            switch (index) {
                case 0: ctx.Dr0 = (DWORD64)address; break;
                case 1: ctx.Dr1 = (DWORD64)address; break;
                case 2: ctx.Dr2 = (DWORD64)address; break;
                case 3: ctx.Dr3 = (DWORD64)address; break;
            }
            
            // Ativar breakpoint
            ctx.Dr7 |= (1 << (index * 2)); // Enable local breakpoint
            
            SetThreadContext(GetCurrentThread(), &ctx);
        }
    }
    
    void ImplementMemoryEncryption() {
        // Implementar encriptação de memória com rotação de chaves
        for (MEMORY_REGION& region : protectedRegions) {
            if (!region.isEncrypted) {
                EncryptRegionWithRotation(region);
            }
        }
        
        // Iniciar rotação de chaves
        StartKeyRotation();
    }
    
    void EncryptRegionWithRotation(MEMORY_REGION& region) {
        // Encriptar região com chave atual
        std::vector<BYTE> data((BYTE*)region.address, (BYTE*)region.address + region.size);
        EncryptAES256(data, cryptoContext.key, cryptoContext.iv);
        memcpy(region.address, data.data(), data.size());
        
        region.isEncrypted = true;
        region.encryptionKey = cryptoContext.key;
        region.lastRotation = GetTickCount();
    }
    
    void StartKeyRotation() {
        // Thread para rotacionar chaves periodicamente
        std::thread([this]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::minutes(5));
                RotateEncryptionKeys();
            }
        }).detach();
    }
    
    void RotateEncryptionKeys() {
        // Gerar nova chave
        cryptoContext.key = GenerateCryptoKey();
        cryptoContext.iv = GenerateIV();
        
        // Re-encriptar regiões com nova chave
        for (MEMORY_REGION& region : protectedRegions) {
            if (region.isEncrypted) {
                // Desencriptar com chave antiga
                std::vector<BYTE> data((BYTE*)region.address, (BYTE*)region.address + region.size);
                DecryptAES256(data, region.encryptionKey, cryptoContext.iv);
                
                // Re-encriptar com nova chave
                EncryptAES256(data, cryptoContext.key, cryptoContext.iv);
                memcpy(region.address, data.data(), data.size());
                
                region.encryptionKey = cryptoContext.key;
                region.lastRotation = GetTickCount();
            }
        }
    }
    
    void SetupIntegrityVerification() {
        // Configurar verificação de integridade avançada
        for (MEMORY_REGION& region : protectedRegions) {
            SetupRegionIntegrity(region);
        }
    }
    
    void SetupRegionIntegrity(MEMORY_REGION& region) {
        // Calcular múltiplos hashes
        region.integrityHash = CalculateSHA256(region);
        region.integrityCRC32 = CalculateCRC32(region);
        region.integrityMD5 = CalculateMD5(region);
        
        // Iniciar monitoramento avançado
        StartAdvancedIntegrityMonitoring(region);
    }
    
    void StartAdvancedIntegrityMonitoring(const MEMORY_REGION& region) {
        std::thread([this, region]() {
            while (true) {
                if (!VerifyAdvancedIntegrity(region)) {
                    OnAdvancedIntegrityViolation(region);
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();
    }
    
    bool VerifyAdvancedIntegrity(const MEMORY_REGION& region) {
        std::string sha256 = CalculateSHA256(region);
        uint32_t crc32 = CalculateCRC32(region);
        std::string md5 = CalculateMD5(region);
        
        return sha256 == region.integrityHash &&
               crc32 == region.integrityCRC32 &&
               md5 == region.integrityMD5;
    }
    
    void OnAdvancedIntegrityViolation(const MEMORY_REGION& region) {
        // Violação avançada detectada
        TriggerAntiDumpResponse();
        LogAdvancedViolation(region);
    }
    
    void DeployTimeBasedCorruption() {
        // Implementar corrupção baseada em tempo
        for (MEMORY_REGION& region : protectedRegions) {
            DeployRegionTimeBomb(region);
        }
    }
    
    void DeployRegionTimeBomb(MEMORY_REGION& region) {
        region.timeBombSet = true;
        region.timeBombTimer = GetTickCount() + GenerateRandomDelay();
        
        // Thread para time bomb
        std::thread([this, region]() mutable {
            DWORD timer = region.timeBombTimer;
            while (GetTickCount() < timer) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            
            // Time bomb ativada
            CorruptRegionWithTimeBomb(region);
        }).detach();
    }
    
    DWORD GenerateRandomDelay() {
        // Delay aleatório entre 30 segundos e 10 minutos
        return (rand() % 570) + 30;
    }
    
    void CorruptRegionWithTimeBomb(MEMORY_REGION& region) {
        // Corromper região de forma irreversível
        for (size_t i = 0; i < region.size; i++) {
            ((BYTE*)region.address)[i] ^= 0xFF; // Inverter bits
        }
        
        // Tornar região inacessível
        DWORD oldProtect;
        VirtualProtect(region.address, region.size, PAGE_NOACCESS, &oldProtect);
    }
    
    static LONG CALLBACK VectoredExceptionHandler(PEXCEPTION_POINTERS ExceptionInfo) {
        // Handler para exceptions relacionadas a proteção de memória
        DWORD exceptionCode = ExceptionInfo->ExceptionRecord->ExceptionCode;
        PVOID exceptionAddress = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        
        switch (exceptionCode) {
            case STATUS_GUARD_PAGE_VIOLATION:
                return HandleGuardPageViolation(ExceptionInfo);
                
            case STATUS_ACCESS_VIOLATION:
                return HandleAccessViolation(ExceptionInfo);
                
            case STATUS_ILLEGAL_INSTRUCTION:
                return HandleIllegalInstruction(ExceptionInfo);
                
            case STATUS_SINGLE_STEP:
                return HandleSingleStep(ExceptionInfo);
                
            default:
                return EXCEPTION_CONTINUE_SEARCH;
        }
    }
    
    static LONG HandleGuardPageViolation(PEXCEPTION_POINTERS ExceptionInfo) {
        PVOID address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        
        // Verificar se é uma região protegida
        if (IsProtectedMemoryAccess(address)) {
            // Acesso a memória protegida detectado
            OnProtectedMemoryAccess(address);
            
            // Reparar proteção
            RepairGuardPageProtection(address);
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    static LONG HandleAccessViolation(PEXCEPTION_POINTERS ExceptionInfo) {
        PVOID address = ExceptionInfo->ExceptionRecord->ExceptionAddress;
        
        if (IsProtectedMemoryAccess(address)) {
            // Tentativa de acesso a memória protegida
            OnProtectedMemoryAccess(address);
            
            // Modificar contexto para continuar execução
            ExceptionInfo->ContextRecord->Rip += 1; // Skip instruction
            
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    static LONG HandleIllegalInstruction(PEXCEPTION_POINTERS ExceptionInfo) {
        // Instrução ilegal - possível tampering
        OnIllegalInstruction();
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    static LONG HandleSingleStep(PEXCEPTION_POINTERS ExceptionInfo) {
        // Single stepping detectado
        OnSingleStepDetected();
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    static bool IsProtectedMemoryAccess(PVOID address) {
        // Verificar se endereço está protegido
        return false; // Placeholder
    }
    
    static void OnProtectedMemoryAccess(PVOID address) {
        // Log acesso não autorizado
        LogUnauthorizedAccess(address);
        
        // Possível resposta anti-dump
        TriggerAntiDumpResponse();
    }
    
    static void RepairGuardPageProtection(PVOID address) {
        // Restaurar PAGE_GUARD
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(address, &mbi, sizeof(mbi))) {
            DWORD oldProtect;
            VirtualProtect(address, mbi.RegionSize, mbi.Protect | PAGE_GUARD, &oldProtect);
        }
    }
    
    static void OnIllegalInstruction() {
        // Resposta a instrução ilegal
        TerminateProcess(GetCurrentProcess(), 0);
    }
    
    static void OnSingleStepDetected() {
        // Resposta a single stepping
        CorruptExecutionFlow();
    }
    
    static void LogUnauthorizedAccess(PVOID address) {
        std::ofstream log("memory_access.log", std::ios::app);
        log << "Unauthorized memory access at: " << address << " time: " << std::time(nullptr) << std::endl;
        log.close();
    }
    
    static void TriggerAntiDumpResponse() {
        // Resposta anti-dump
        // Corromper dados, terminar processo, etc.
    }
    
    static void CorruptExecutionFlow() {
        // Corromper fluxo de execução
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(GetCurrentThread(), &ctx);
        
        // Modificar RIP/RSP
        ctx.Rip = (DWORD64)GetProcAddress(GetModuleHandleA("kernel32.dll"), "ExitProcess");
        ctx.Rsp -= 8; // Espaço para return address
        
        SetThreadContext(GetCurrentThread(), &ctx);
    }
    
    // Implementações criptográficas
    std::string GenerateCryptoKey() { return "dummy_key_32_bytes_long_xxxxxxxxxxxxx"; }
    std::string GenerateIV() { return "dummy_iv_16_bytes"; }
    void EncryptAES256(std::vector<BYTE>& data, const std::string& key, const std::string& iv) { /* AES impl */ }
    void DecryptAES256(std::vector<BYTE>& data, const std::string& key, const std::string& iv) { /* AES impl */ }
    std::string CalculateSHA256(const MEMORY_REGION& region) { return "dummy_sha256"; }
    uint32_t CalculateCRC32(const MEMORY_REGION& region) { return 0; }
    std::string CalculateMD5(const MEMORY_REGION& region) { return "dummy_md5"; }
};
```

### Por que é Detectado

> [!WARNING]
> **Memory protection deixa rastros através de hooks óbvios e comportamento suspeito**

#### 1. Hook Detection
```cpp
// Detecção de hooks
class HookDetector {
private:
    std::vector<HOOKED_API> knownHooks;
    
public:
    void Initialize() {
        // APIs comumente hookadas para anti-dump
        knownHooks.push_back({"kernel32.dll", "ReadProcessMemory"});
        knownHooks.push_back({"kernel32.dll", "VirtualQuery"});
        knownHooks.push_back({"kernel32.dll", "VirtualProtect"});
        knownHooks.push_back({"ntdll.dll", "NtReadVirtualMemory"});
        knownHooks.push_back({"dbghelp.dll", "MiniDumpWriteDump"});
    }
    
    void ScanForHooks() {
        for (const HOOKED_API& api : knownHooks) {
            if (IsAPIHooked(api)) {
                ReportHookDetection(api);
            }
        }
    }
    
    bool IsAPIHooked(const HOOKED_API& api) {
        HMODULE hModule = GetModuleHandleA(api.moduleName.c_str());
        if (!hModule) return false;
        
        PVOID pFunction = GetProcAddress(hModule, api.functionName.c_str());
        if (!pFunction) return false;
        
        // Verificar se função está hookada
        return IsFunctionHooked(pFunction);
    }
    
    bool IsFunctionHooked(PVOID pFunction) {
        // Método 1: Verificar prólogo da função
        if (IsPrologueHooked(pFunction)) return true;
        
        // Método 2: Verificar se aponta para módulo diferente
        if (IsFunctionRedirected(pFunction)) return true;
        
        // Método 3: Verificar integridade da função
        if (!VerifyFunctionIntegrity(pFunction)) return true;
        
        return false;
    }
    
    bool IsPrologueHooked(PVOID pFunction) {
        // Verificar prólogo padrão vs atual
        const BYTE standardPrologue[] = {0x8B, 0xFF, 0x55, 0x8B, 0xEC}; // MOV EDI, EDI; PUSH EBP; MOV EBP, ESP
        
        __try {
            BYTE* pBytes = (BYTE*)pFunction;
            for (size_t i = 0; i < sizeof(standardPrologue); i++) {
                if (pBytes[i] != standardPrologue[i]) {
                    return true;
                }
            }
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // Não conseguiu ler - possível hook
        }
        
        return false;
    }
    
    bool IsFunctionRedirected(PVOID pFunction) {
        // Verificar se função aponta para módulo do processo
        HMODULE hModule = NULL;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, 
                              (LPCTSTR)pFunction, &hModule)) {
            char moduleName[MAX_PATH];
            GetModuleFileNameA(hModule, moduleName, MAX_PATH);
            
            // Se não é kernel32.dll ou ntdll.dll, pode estar hookada
            std::string name = moduleName;
            if (name.find("kernel32.dll") == std::string::npos &&
                name.find("ntdll.dll") == std::string::npos) {
                return true;
            }
        }
        
        return false;
    }
    
    bool VerifyFunctionIntegrity(PVOID pFunction) {
        // Calcular hash da função e comparar com conhecido
        // Usar IAT para obter endereço original
        
        return true; // Placeholder
    }
    
    void ReportHookDetection(const HOOKED_API& api) {
        // Reportar hook detectado
        std::cout << "Hook detected: " << api.moduleName << "!" << api.functionName << std::endl;
    }
};
```

#### 2. Memory Protection Analysis
```cpp
// Análise de proteção de memória
class MemoryProtectionAnalyzer {
private:
    std::map<DWORD, MEMORY_ANALYSIS> processMemory;
    
public:
    void AnalyzeProcessMemory(DWORD processId) {
        // Enumerar regiões de memória
        EnumerateMemoryRegions(processId);
        
        // Analisar proteções suspeitas
        AnalyzeMemoryProtections();
        
        // Verificar anomalias
        CheckForAnomalies();
    }
    
    void EnumerateMemoryRegions(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return;
        
        PVOID address = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            MEMORY_ANALYSIS analysis;
            analysis.address = address;
            analysis.size = mbi.RegionSize;
            analysis.protection = mbi.Protect;
            analysis.state = mbi.State;
            analysis.type = mbi.Type;
            
            // Calcular entropia se possível
            if (mbi.State == MEM_COMMIT && (mbi.Protect & PAGE_READWRITE)) {
                analysis.entropy = CalculateMemoryEntropy(hProcess, address, mbi.RegionSize);
            }
            
            processMemory[(DWORD)(uintptr_t)address] = analysis;
            
            address = (PVOID)((uintptr_t)address + mbi.RegionSize);
        }
        
        CloseHandle(hProcess);
    }
    
    void AnalyzeMemoryProtections() {
        for (const auto& pair : processMemory) {
            const MEMORY_ANALYSIS& analysis = pair.second;
            
            // Verificar proteções suspeitas
            if (HasSuspiciousProtection(analysis)) {
                ReportSuspiciousProtection(analysis);
            }
            
            // Verificar entropia alta
            if (analysis.entropy > 7.0) {
                ReportHighEntropy(analysis);
            }
        }
    }
    
    bool HasSuspiciousProtection(const MEMORY_ANALYSIS& analysis) {
        DWORD protection = analysis.protection;
        
        // PAGE_GUARD é suspeito
        if (protection & PAGE_GUARD) {
            return true;
        }
        
        // Executable + Writeable (sem Read) é suspeito
        if ((protection & PAGE_EXECUTE) && (protection & PAGE_READWRITE) && !(protection & PAGE_READ)) {
            return true;
        }
        
        // PAGE_NOACCESS em regiões normais
        if (protection == PAGE_NOACCESS && analysis.type == MEM_PRIVATE) {
            return true;
        }
        
        return false;
    }
    
    void CheckForAnomalies() {
        // Verificar padrões de anti-dump
        CheckForPAGE_GUARDClusters();
        CheckForEncryptedRegions();
        CheckForIntegrityCheckPatterns();
    }
    
    void CheckForPAGE_GUARDClusters() {
        // Clusters de PAGE_GUARD são suspeitos
        int guardCount = 0;
        PVOID lastGuardAddress = NULL;
        
        for (const auto& pair : processMemory) {
            const MEMORY_ANALYSIS& analysis = pair.second;
            
            if (analysis.protection & PAGE_GUARD) {
                if (lastGuardAddress && 
                    (uintptr_t)analysis.address - (uintptr_t)lastGuardAddress < 0x10000) {
                    guardCount++;
                } else {
                    guardCount = 1;
                }
                
                lastGuardAddress = analysis.address;
                
                if (guardCount > 5) {
                    ReportPAGE_GUARDCluster();
                    break;
                }
            }
        }
    }
    
    void CheckForEncryptedRegions() {
        // Regiões com alta entropia podem estar encriptadas
        for (const auto& pair : processMemory) {
            const MEMORY_ANALYSIS& analysis = pair.second;
            
            if (analysis.entropy > 7.5) {
                ReportEncryptedRegion(analysis);
            }
        }
    }
    
    void CheckForIntegrityCheckPatterns() {
        // Procurar por padrões de verificação de integridade
        // ...
    }
    
    double CalculateMemoryEntropy(HANDLE hProcess, PVOID address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(hProcess, address, buffer.data(), size, &bytesRead)) {
            return CalculateEntropy(buffer);
        }
        
        return 0.0;
    }
    
    double CalculateEntropy(const std::vector<BYTE>& data) {
        std::map<BYTE, int> frequency;
        for (BYTE b : data) {
            frequency[b]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / data.size();
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    void ReportSuspiciousProtection(const MEMORY_ANALYSIS& analysis) {
        std::cout << "Suspicious memory protection at: " << analysis.address << std::endl;
    }
    
    void ReportHighEntropy(const MEMORY_ANALYSIS& analysis) {
        std::cout << "High entropy region at: " << analysis.address << std::endl;
    }
    
    void ReportPAGE_GUARDCluster() {
        std::cout << "PAGE_GUARD cluster detected" << std::endl;
    }
    
    void ReportEncryptedRegion(const MEMORY_ANALYSIS& analysis) {
        std::cout << "Potential encrypted region at: " << analysis.address << std::endl;
    }
};
```

#### 3. Behavioral Analysis
```cpp
// Análise comportamental
class BehavioralAnalyzer {
private:
    std::vector<MEMORY_ACCESS_PATTERN> accessPatterns;
    
public:
    void MonitorMemoryAccess(DWORD processId) {
        // Instalar hooks para monitorar acesso à memória
        InstallMemoryAccessHooks();
        
        // Registrar padrões normais
        RegisterNormalPatterns(processId);
        
        // Monitorar desvios
        StartBehavioralMonitoring();
    }
    
    void InstallMemoryAccessHooks() {
        // Hook VirtualProtect, VirtualQuery, ReadProcessMemory, etc.
    }
    
    void RegisterNormalPatterns(DWORD processId) {
        // Registrar padrões de acesso normais
        // ...
    }
    
    void StartBehavioralMonitoring() {
        // Thread para analisar comportamento
        std::thread([this]() {
            while (true) {
                AnalyzeCurrentBehavior();
                std::this_thread::sleep_for(std::chrono::milliseconds(500));
            }
        }).detach();
    }
    
    void AnalyzeCurrentBehavior() {
        // Analisar padrões atuais vs normais
        if (HasSuspiciousMemoryAccess()) {
            ReportSuspiciousBehavior();
        }
        
        if (HasAntiDumpIndicators()) {
            ReportAntiDumpActivity();
        }
    }
    
    bool HasSuspiciousMemoryAccess() {
        // Verificar acessos suspeitos à memória
        return false; // Placeholder
    }
    
    bool HasAntiDumpIndicators() {
        // Verificar indicadores de anti-dump
        return false; // Placeholder
    }
    
    void ReportSuspiciousBehavior() {
        std::cout << "Suspicious memory access behavior detected" << std::endl;
    }
    
    void ReportAntiDumpActivity() {
        std::cout << "Anti-dump activity detected" << std::endl;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Hook detection | < 30s | 90% |
| VAC Live | Memory protection analysis | Imediato | 85% |
| BattlEye | Behavioral analysis | < 1 min | 95% |
| Faceit AC | Entropy analysis | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Hardware-Assisted Protection
```cpp
// ✅ Proteção assistida por hardware
class HardwareAssistedProtector {
private:
    std::vector<MEMORY_REGION> protectedRegions;
    
public:
    void EnableHardwareProtection() {
        // Usar SMEP/SMAP se disponível
        if (IsSMEPSupported()) {
            EnableSMEP();
        }
        
        if (IsSMAPSupported()) {
            EnableSMAP();
        }
        
        // Usar Memory Protection Keys (MPK)
        if (IsMPKSupported()) {
            SetupMPKProtection();
        }
    }
    
    bool IsSMEPSupported() {
        // Verificar suporte a SMEP
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        return (cpuInfo[3] & (1 << 7)) != 0; // SMEP bit
    }
    
    bool IsSMAPSupported() {
        // Verificar suporte a SMAP
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        return (cpuInfo[3] & (1 << 20)) != 0; // SMAP bit
    }
    
    bool IsMPKSupported() {
        // Verificar suporte a MPK
        int cpuInfo[4];
        __cpuid(cpuInfo, 7);
        return (cpuInfo[1] & (1 << 4)) != 0; // PKU bit
    }
    
    void EnableSMEP() {
        // Habilitar SMEP via CR4
        uintptr_t cr4 = __readcr4();
        cr4 |= (1ULL << 20); // SMEP bit
        __writecr4(cr4);
    }
    
    void EnableSMAP() {
        // Habilitar SMAP via CR4
        uintptr_t cr4 = __readcr4();
        cr4 |= (1ULL << 21); // SMAP bit
        __writecr4(cr4);
    }
    
    void SetupMPKProtection() {
        // Configurar Memory Protection Keys
        for (MEMORY_REGION& region : protectedRegions) {
            // Atribuir protection key à região
            AssignProtectionKey(region);
        }
        
        // Restringir acesso à key
        RestrictProtectionKeyAccess();
    }
    
    void AssignProtectionKey(MEMORY_REGION& region) {
        // Usar pkey_mprotect para atribuir key
        int pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS);
        if (pkey != -1) {
            region.protectionKey = pkey;
            pkey_mprotect(region.address, region.size, PROT_READ | PROT_WRITE, pkey);
        }
    }
    
    void RestrictProtectionKeyAccess() {
        // Restringir acesso à protection key
        // Usar PKRU register
        unsigned int pkru = __rdpkru();
        pkru |= (1 << 1); // Disable access for key 1
        __wrpkru(pkru);
    }
};
```

### 2. Kernel-Mode Protection
```cpp
// ✅ Proteção em kernel-mode
class KernelModeProtector {
private:
    HANDLE hDevice;
    
public:
    KernelModeProtector() {
        // Conectar ao driver
        hDevice = CreateFileA("\\\\.\\MemoryProtector", GENERIC_READ | GENERIC_WRITE, 
                             0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    
    void ProtectMemoryInKernel(PVOID address, SIZE_T size) {
        if (hDevice == INVALID_HANDLE_VALUE) return;
        
        MEMORY_PROTECTION_REQUEST request;
        request.address = address;
        request.size = size;
        request.protectionType = PROTECTION_ANTI_DUMP;
        
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_PROTECT_MEMORY, &request, sizeof(request), 
                       NULL, 0, &bytesReturned, NULL);
    }
    
    void MonitorMemoryAccessInKernel() {
        // Monitorar acessos à memória via kernel
        MEMORY_MONITOR_REQUEST monitorRequest;
        monitorRequest.monitorType = MONITOR_ANTI_DUMP;
        
        DWORD bytesReturned;
        DeviceIoControl(hDevice, IOCTL_START_MONITORING, &monitorRequest, sizeof(monitorRequest),
                       NULL, 0, &bytesReturned, NULL);
    }
    
    ~KernelModeProtector() {
        if (hDevice != INVALID_HANDLE_VALUE) {
            CloseHandle(hDevice);
        }
    }
};
```

### 3. Encrypted Memory Pools
```cpp
// ✅ Pools de memória encriptados
class EncryptedMemoryPool {
private:
    std::vector<ENCRYPTED_BLOCK> memoryBlocks;
    CRYPTO_CONTEXT crypto;
    
public:
    EncryptedMemoryPool() {
        InitializeCrypto();
        CreateMemoryPool();
    }
    
    void InitializeCrypto() {
        crypto.algorithm = CRYPTO_CHACHA20;
        crypto.key = GenerateKey();
        crypto.nonce = GenerateNonce();
    }
    
    void CreateMemoryPool() {
        // Criar pool de memória encriptado
        for (int i = 0; i < 10; i++) {
            CreateEncryptedBlock();
        }
    }
    
    void CreateEncryptedBlock() {
        ENCRYPTED_BLOCK block;
        block.size = 4096; // 4KB
        block.address = VirtualAlloc(NULL, block.size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        
        if (block.address) {
            // Inicializar com dados aleatórios encriptados
            std::vector<BYTE> randomData(block.size);
            for (size_t i = 0; i < block.size; i++) {
                randomData[i] = rand() % 256;
            }
            
            EncryptData(randomData, crypto);
            memcpy(block.address, randomData.data(), block.size);
            
            memoryBlocks.push_back(block);
        }
    }
    
    PVOID AllocateFromPool(SIZE_T size) {
        // Alocar de pool encriptado
        for (ENCRYPTED_BLOCK& block : memoryBlocks) {
            if (!block.allocated && block.size >= size) {
                block.allocated = true;
                block.allocatedSize = size;
                return block.address;
            }
        }
        
        return nullptr;
    }
    
    void FreeFromPool(PVOID address) {
        // Liberar para pool
        for (ENCRYPTED_BLOCK& block : memoryBlocks) {
            if (block.address == address) {
                block.allocated = false;
                block.allocatedSize = 0;
                
                // Re-encriptar com dados aleatórios
                std::vector<BYTE> randomData(block.size);
                for (size_t i = 0; i < block.size; i++) {
                    randomData[i] = rand() % 256;
                }
                
                EncryptData(randomData, crypto);
                memcpy(block.address, randomData.data(), block.size);
                break;
            }
        }
    }
    
    void EncryptData(std::vector<BYTE>& data, const CRYPTO_CONTEXT& ctx) {
        // Encriptar dados com ChaCha20
        // ...
    }
    
    void DecryptData(std::vector<BYTE>& data, const CRYPTO_CONTEXT& ctx) {
        // Decriptar dados
        // ...
    }
    
    std::string GenerateKey() {
        std::string key(32, 0);
        for (char& c : key) c = rand() % 256;
        return key;
    }
    
    std::string GenerateNonce() {
        std::string nonce(12, 0);
        for (char& c : nonce) c = rand() % 256;
        return nonce;
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Hook detection |
| 2020-2024 | ⚠️ Médio risco | Memory analysis |
| 2025-2026 | ⚠️ Alto risco | Advanced behavioral |

---

## 🎯 Lições Aprendidas

1. **Hooks São Detectáveis**: APIs hookadas são facilmente identificadas.

2. **Proteções São Rastreadas**: PAGE_GUARD e outras proteções são monitoradas.

3. **Comportamento é Analisado**: Padrões suspeitos são detectados.

4. **Hardware Protection é Melhor**: Usar recursos de hardware para proteção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#41]]
- [[Hook_Detection]]
- [[Memory_Encryption]]
- [[Hardware_Assisted_Protection]]

---

*Memory dump prevention tem risco moderado. Considere hardware-assisted protection para mais stealth.*