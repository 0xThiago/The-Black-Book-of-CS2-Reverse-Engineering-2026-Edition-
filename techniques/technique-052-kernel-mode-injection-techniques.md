# 📖 Técnica 052: Kernel Mode Injection Techniques

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Alto

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 052: Kernel Mode Injection Techniques]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Alto  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Kernel Injection  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Kernel Mode Injection Techniques** injetam código diretamente no kernel do Windows, permitindo manipulação profunda do sistema operacional e bypass de proteções user-mode.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE ALTO RISCO - EXTREMAMENTE PERIGOSO
// NÃO USE EM PRODUÇÃO - APENAS PARA ANÁLISE EDUCACIONAL
class KernelModeInjector {
private:
    DRIVER_COMMUNICATION driverComm;
    KERNEL_MEMORY_ACCESS kernelMem;
    INJECTION_METHODS methods;
    
public:
    KernelModeInjector() {
        InitializeDriverCommunication();
        InitializeKernelMemoryAccess();
        InitializeInjectionMethods();
    }
    
    void InitializeDriverCommunication() {
        // Inicializar comunicação com driver
        driverComm.useDeviceIoControl = true;
        driverComm.useSharedMemory = true;
        driverComm.useEventObjects = true;
    }
    
    void InitializeKernelMemoryAccess() {
        // Inicializar acesso à memória do kernel
        kernelMem.useMmMapIoSpace = true;
        kernelMem.useMmAllocatePages = true;
        kernelMem.useZwMapViewOfSection = true;
    }
    
    void InitializeInjectionMethods() {
        // Inicializar métodos de injeção
        methods.useDKOM = true;
        methods.useSSDT_Hooking = true;
        methods.useIDT_Hooking = true;
        methods.useKernel_Callbacks = true;
    }
    
    bool InjectIntoKernel(PVOID payload, SIZE_T payloadSize) {
        // Injetar payload no kernel
        if (!LoadKernelDriver()) return false;
        
        if (!EstablishDriverCommunication()) return false;
        
        if (!AllocateKernelMemory(payloadSize)) return false;
        
        if (!WritePayloadToKernel(payload, payloadSize)) return false;
        
        if (!ExecuteKernelPayload()) return false;
        
        return true;
    }
    
    bool LoadKernelDriver() {
        // Carregar driver do kernel
        SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
        if (!hSCManager) return false;
        
        SC_HANDLE hService = CreateServiceA(hSCManager, "KernelInjector", "Kernel Injector Service",
                                          SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                                          SERVICE_ERROR_NORMAL, "C:\\Windows\\System32\\drivers\\kernelinj.sys",
                                          NULL, NULL, NULL, NULL, NULL);
        
        if (!hService && GetLastError() != ERROR_SERVICE_EXISTS) {
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        if (!StartService(hService, 0, NULL)) {
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return false;
        }
        
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        
        return true;
    }
    
    bool EstablishDriverCommunication() {
        // Estabelecer comunicação com driver
        HANDLE hDevice = CreateFileA("\\\\.\\KernelInjector", GENERIC_READ | GENERIC_WRITE, 0, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hDevice == INVALID_HANDLE_VALUE) return false;
        
        driverComm.hDevice = hDevice;
        return true;
    }
    
    bool AllocateKernelMemory(SIZE_T size) {
        // Alocar memória no kernel
        KERNEL_MEMORY_ALLOC allocInfo;
        allocInfo.size = size;
        
        DWORD bytesReturned;
        return DeviceIoControl(driverComm.hDevice, IOCTL_ALLOCATE_KERNEL_MEMORY, &allocInfo,
                             sizeof(allocInfo), &kernelMem.kernelAddress, sizeof(PVOID),
                             &bytesReturned, NULL);
    }
    
    bool WritePayloadToKernel(PVOID payload, SIZE_T payloadSize) {
        // Escrever payload na memória do kernel
        KERNEL_MEMORY_WRITE writeInfo;
        writeInfo.address = kernelMem.kernelAddress;
        writeInfo.buffer = payload;
        writeInfo.size = payloadSize;
        
        DWORD bytesReturned;
        return DeviceIoControl(driverComm.hDevice, IOCTL_WRITE_KERNEL_MEMORY, &writeInfo,
                             sizeof(writeInfo), NULL, 0, &bytesReturned, NULL);
    }
    
    bool ExecuteKernelPayload() {
        // Executar payload no kernel
        KERNEL_EXECUTE execInfo;
        execInfo.address = kernelMem.kernelAddress;
        
        DWORD bytesReturned;
        return DeviceIoControl(driverComm.hDevice, IOCTL_EXECUTE_KERNEL_CODE, &execInfo,
                             sizeof(execInfo), NULL, 0, &bytesReturned, NULL);
    }
    
    // DKOM (Direct Kernel Object Manipulation)
    bool PerformDKOM() {
        // Executar DKOM
        if (!methods.useDKOM) return false;
        
        // Encontrar processo alvo no kernel
        PEPROCESS targetProcess = FindProcessById(targetPid);
        if (!targetProcess) return false;
        
        // Modificar estrutura do processo
        ModifyProcessStructure(targetProcess);
        
        return true;
    }
    
    PEPROCESS FindProcessById(DWORD processId) {
        // Encontrar processo por ID
        // Implementar busca
        
        return NULL; // Placeholder
    }
    
    void ModifyProcessStructure(PEPROCESS process) {
        // Modificar estrutura do processo
        // Implementar modificação
    }
    
    // SSDT Hooking
    bool HookSSDT() {
        // Hook SSDT
        if (!methods.useSSDT_Hooking) return false;
        
        // Obter endereço da SSDT
        PVOID ssdtAddress = GetSSDTAddress();
        if (!ssdtAddress) return false;
        
        // Hook função específica
        HookSSDTFunction(ssdtAddress, targetFunctionIndex);
        
        return true;
    }
    
    PVOID GetSSDTAddress() {
        // Obter endereço da SSDT
        // Implementar obtenção
        
        return NULL; // Placeholder
    }
    
    void HookSSDTFunction(PVOID ssdtAddress, int functionIndex) {
        // Hook função da SSDT
        // Implementar hook
    }
    
    // IDT Hooking
    bool HookIDT() {
        // Hook IDT
        if (!methods.useIDT_Hooking) return false;
        
        // Obter endereço da IDT
        PVOID idtAddress = GetIDTAddress();
        if (!idtAddress) return false;
        
        // Hook interrupção específica
        HookIDTInterrupt(idtAddress, targetInterrupt);
        
        return true;
    }
    
    PVOID GetIDTAddress() {
        // Obter endereço da IDT
        // Implementar obtenção
        
        return NULL; // Placeholder
    }
    
    void HookIDTInterrupt(PVOID idtAddress, int interruptNumber) {
        // Hook interrupção da IDT
        // Implementar hook
    }
    
    // Kernel Callbacks
    bool InstallKernelCallbacks() {
        // Instalar callbacks do kernel
        if (!methods.useKernel_Callbacks) return false;
        
        // Instalar callback de processo
        InstallProcessCallback();
        
        // Instalar callback de thread
        InstallThreadCallback();
        
        // Instalar callback de imagem
        InstallImageCallback();
        
        return true;
    }
    
    void InstallProcessCallback() {
        // Instalar callback de processo
        // Implementar instalação
    }
    
    void InstallThreadCallback() {
        // Instalar callback de thread
        // Implementar instalação
    }
    
    void InstallImageCallback() {
        // Instalar callback de imagem
        // Implementar instalação
    }
    
    // Kernel driver implementation
    static NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
        // Entry point do driver
        UNREFERENCED_PARAMETER(RegistryPath);
        
        // Criar dispositivo
        PDEVICE_OBJECT deviceObject;
        UNICODE_STRING deviceName;
        RtlInitUnicodeString(&deviceName, L"\\Device\\KernelInjector");
        
        NTSTATUS status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                                       FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
        
        if (!NT_SUCCESS(status)) return status;
        
        // Criar link simbólico
        UNICODE_STRING symbolicLink;
        RtlInitUnicodeString(&symbolicLink, L"\\DosDevices\\KernelInjector");
        
        status = IoCreateSymbolicLink(&symbolicLink, &deviceName);
        if (!NT_SUCCESS(status)) {
            IoDeleteDevice(deviceObject);
            return status;
        }
        
        // Configurar rotinas de dispatch
        DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
        DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
        DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchDeviceControl;
        DriverObject->DriverUnload = DriverUnload;
        
        return STATUS_SUCCESS;
    }
    
    static NTSTATUS DispatchDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
        // Manipular IOCTLs
        UNREFERENCED_PARAMETER(DeviceObject);
        
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
        
        NTSTATUS status = STATUS_SUCCESS;
        
        switch (ioctl) {
            case IOCTL_ALLOCATE_KERNEL_MEMORY:
                status = HandleAllocateKernelMemory(Irp);
                break;
                
            case IOCTL_WRITE_KERNEL_MEMORY:
                status = HandleWriteKernelMemory(Irp);
                break;
                
            case IOCTL_EXECUTE_KERNEL_CODE:
                status = HandleExecuteKernelCode(Irp);
                break;
                
            default:
                status = STATUS_INVALID_DEVICE_REQUEST;
                break;
        }
        
        Irp->IoStatus.Status = status;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        
        return status;
    }
    
    static NTSTATUS HandleAllocateKernelMemory(PIRP Irp) {
        // Manipular alocação de memória do kernel
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        PKERNEL_MEMORY_ALLOC allocInfo = (PKERNEL_MEMORY_ALLOC)Irp->AssociatedIrp.SystemBuffer;
        
        // Alocar memória não paginada
        PVOID kernelAddress = ExAllocatePoolWithTag(NonPagedPool, allocInfo->size, 'knjI');
        if (!kernelAddress) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        
        // Retornar endereço
        *(PVOID*)Irp->AssociatedIrp.SystemBuffer = kernelAddress;
        
        return STATUS_SUCCESS;
    }
    
    static NTSTATUS HandleWriteKernelMemory(PIRP Irp) {
        // Manipular escrita na memória do kernel
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        PKERNEL_MEMORY_WRITE writeInfo = (PKERNEL_MEMORY_WRITE)Irp->AssociatedIrp.SystemBuffer;
        
        // Copiar dados para memória do kernel
        RtlCopyMemory(writeInfo->address, writeInfo->buffer, writeInfo->size);
        
        return STATUS_SUCCESS;
    }
    
    static NTSTATUS HandleExecuteKernelCode(PIRP Irp) {
        // Manipular execução de código no kernel
        PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
        PKERNEL_EXECUTE execInfo = (PKERNEL_EXECUTE)Irp->AssociatedIrp.SystemBuffer;
        
        // Executar código
        ((PKERNEL_ROUTINE)execInfo->address)();
        
        return STATUS_SUCCESS;
    }
    
    // Structs
    typedef struct _KERNEL_MEMORY_ALLOC {
        SIZE_T size;
    } KERNEL_MEMORY_ALLOC, *PKERNEL_MEMORY_ALLOC;
    
    typedef struct _KERNEL_MEMORY_WRITE {
        PVOID address;
        PVOID buffer;
        SIZE_T size;
    } KERNEL_MEMORY_WRITE, *PKERNEL_MEMORY_WRITE;
    
    typedef struct _KERNEL_EXECUTE {
        PVOID address;
    } KERNEL_EXECUTE, *PKERNEL_EXECUTE;
    
    typedef VOID (*PKERNEL_ROUTINE)(VOID);
    
    // IOCTL codes
    #define IOCTL_ALLOCATE_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_WRITE_KERNEL_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
    #define IOCTL_EXECUTE_KERNEL_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
};
```

### DKOM (Direct Kernel Object Manipulation)

```cpp
// DKOM implementation
class DKOMManipulator {
private:
    OBJECT_MANIPULATION objects;
    PROCESS_HIDING hiding;
    
public:
    DKOMManipulator() {
        InitializeObjectManipulation();
        InitializeProcessHiding();
    }
    
    void InitializeObjectManipulation() {
        // Inicializar manipulação de objetos
        objects.manipulateEPROCESS = true;
        objects.manipulateETHREAD = true;
        objects.manipulateDrivers = true;
    }
    
    void InitializeProcessHiding() {
        // Inicializar ocultação de processos
        hiding.unlinkFromList = true;
        hiding.modifyReferenceCount = true;
        hiding.hideFromQuery = true;
    }
    
    bool HideProcess(DWORD targetPid) {
        // Ocultar processo usando DKOM
        PEPROCESS targetProcess = FindProcessById(targetPid);
        if (!targetProcess) return false;
        
        // Desvincular da lista de processos
        UnlinkFromProcessList(targetProcess);
        
        // Modificar contagem de referências
        ModifyReferenceCount(targetProcess);
        
        return true;
    }
    
    PEPROCESS FindProcessById(DWORD processId) {
        // Encontrar processo por ID no kernel
        // Percorrer lista de processos
        
        PEPROCESS currentProcess = PsGetCurrentProcess();
        PEPROCESS firstProcess = currentProcess;
        
        do {
            if (PsGetProcessId(currentProcess) == (HANDLE)processId) {
                return currentProcess;
            }
            
            PLIST_ENTRY listEntry = (PLIST_ENTRY)((BYTE*)currentProcess + 0x2F0); // ActiveProcessLinks offset
            currentProcess = (PEPROCESS)((BYTE*)listEntry->Flink - 0x2F0);
        } while (currentProcess != firstProcess);
        
        return NULL;
    }
    
    void UnlinkFromProcessList(PEPROCESS process) {
        // Desvincular processo da lista
        PLIST_ENTRY listEntry = (PLIST_ENTRY)((BYTE*)process + 0x2F0); // ActiveProcessLinks
        
        // Remover da lista
        listEntry->Blink->Flink = listEntry->Flink;
        listEntry->Flink->Blink = listEntry->Blink;
        
        // Apontar para si mesmo para evitar detecção
        listEntry->Flink = listEntry;
        listEntry->Blink = listEntry;
    }
    
    void ModifyReferenceCount(PEPROCESS process) {
        // Modificar contagem de referências
        // Implementar modificação
    }
    
    bool HideDriver(const char* driverName) {
        // Ocultar driver
        PDRIVER_OBJECT driverObject = FindDriverByName(driverName);
        if (!driverObject) return false;
        
        // Desvincular da lista de drivers
        UnlinkFromDriverList(driverObject);
        
        return true;
    }
    
    PDRIVER_OBJECT FindDriverByName(const char* driverName) {
        // Encontrar driver por nome
        // Implementar busca
        
        return NULL; // Placeholder
    }
    
    void UnlinkFromDriverList(PDRIVER_OBJECT driver) {
        // Desvincular driver da lista
        // Implementar desvinculação
    }
    
    bool ManipulateThread(DWORD threadId) {
        // Manipular thread
        PETHREAD thread = FindThreadById(threadId);
        if (!thread) return false;
        
        // Modificar estrutura da thread
        ModifyThreadStructure(thread);
        
        return true;
    }
    
    PETHREAD FindThreadById(DWORD threadId) {
        // Encontrar thread por ID
        // Implementar busca
        
        return NULL; // Placeholder
    }
    
    void ModifyThreadStructure(PETHREAD thread) {
        // Modificar estrutura da thread
        // Implementar modificação
    }
};
```

### SSDT Hooking

```cpp
// SSDT hooking implementation
class SSDTHooker {
private:
    SSDT_INFO ssdtInfo;
    HOOK_INFO hooks;
    
public:
    SSDTHooker() {
        InitializeSSDTInfo();
        InitializeHooks();
    }
    
    void InitializeSSDTInfo() {
        // Inicializar informações da SSDT
        ssdtInfo.serviceTable = NULL;
        ssdtInfo.serviceCount = 0;
    }
    
    void InitializeHooks() {
        // Inicializar hooks
        hooks.hookNtOpenProcess = true;
        hooks.hookNtReadVirtualMemory = true;
        hooks.hookNtWriteVirtualMemory = true;
    }
    
    bool InitializeSSDT() {
        // Inicializar SSDT
        // Encontrar endereço da SSDT
        
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        
        ssdtInfo.serviceTable = (PSYSTEM_SERVICE_TABLE)MmGetSystemRoutineAddress(&routineName);
        if (!ssdtInfo.serviceTable) return false;
        
        ssdtInfo.serviceCount = ssdtInfo.serviceTable->NumberOfServices;
        
        return true;
    }
    
    bool HookNtOpenProcess() {
        // Hook NtOpenProcess
        if (!hooks.hookNtOpenProcess) return false;
        
        // Encontrar índice da função
        int functionIndex = GetNtOpenProcessIndex();
        if (functionIndex == -1) return false;
        
        // Hook função
        return HookSSDTFunction(functionIndex, &HkNtOpenProcess);
    }
    
    int GetNtOpenProcessIndex() {
        // Obter índice de NtOpenProcess
        // Implementar obtenção
        
        return 0x26; // Placeholder
    }
    
    bool HookSSDTFunction(int functionIndex, PVOID hookFunction) {
        // Hook função da SSDT
        if (functionIndex >= ssdtInfo.serviceCount) return false;
        
        // Desabilitar proteção de escrita
        DisableWriteProtection();
        
        // Salvar função original
        originalFunctions[functionIndex] = ssdtInfo.serviceTable->ServiceTable[functionIndex];
        
        // Instalar hook
        ssdtInfo.serviceTable->ServiceTable[functionIndex] = (ULONG_PTR)hookFunction;
        
        // Reabilitar proteção de escrita
        EnableWriteProtection();
        
        return true;
    }
    
    void DisableWriteProtection() {
        // Desabilitar proteção de escrita
        __writecr0(__readcr0() & ~0x10000);
    }
    
    void EnableWriteProtection() {
        // Reabilitar proteção de escrita
        __writecr0(__readcr0() | 0x10000);
    }
    
    // Hook functions
    static NTSTATUS NTAPI HkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                        POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
        // Hook para NtOpenProcess
        // Verificar se é acesso ao processo do anti-cheat
        
        if (IsAntiCheatProcess(ClientId)) {
            return STATUS_ACCESS_DENIED;
        }
        
        return ((NTOPENPROCESS)originalFunctions[GetNtOpenProcessIndex()])(ProcessHandle, DesiredAccess,
                                                                          ObjectAttributes, ClientId);
    }
    
    static bool IsAntiCheatProcess(PCLIENT_ID ClientId) {
        // Verificar se é processo do anti-cheat
        // Implementar verificação
        
        return false; // Placeholder
    }
    
    // Original functions storage
    static PVOID originalFunctions[1024];
    
    typedef NTSTATUS (NTAPI *NTOPENPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
};
```

### IDT Hooking

```cpp
// IDT hooking implementation
class IDTHooker {
private:
    IDT_INFO idtInfo;
    INTERRUPT_HOOKS hooks;
    
public:
    IDTHooker() {
        InitializeIDTInfo();
        InitializeInterruptHooks();
    }
    
    void InitializeIDTInfo() {
        // Inicializar informações da IDT
        idtInfo.idtAddress = NULL;
        idtInfo.limit = 0;
    }
    
    void InitializeInterruptHooks() {
        // Inicializar hooks de interrupção
        hooks.hookInt0x2E = true; // System call
        hooks.hookInt0x0E = true; // Page fault
    }
    
    bool InitializeIDT() {
        // Inicializar IDT
        // Obter endereço da IDT
        
        idtInfo.idtAddress = GetIdtAddress();
        if (!idtInfo.idtAddress) return false;
        
        idtInfo.limit = GetIdtLimit();
        
        return true;
    }
    
    PVOID GetIdtAddress() {
        // Obter endereço da IDT
        PIDTR idtr;
        __sidt(&idtr);
        
        return (PVOID)idtr.Base;
    }
    
    WORD GetIdtLimit() {
        // Obter limite da IDT
        PIDTR idtr;
        __sidt(&idtr);
        
        return idtr.Limit;
    }
    
    bool HookInterrupt(int interruptNumber, PVOID hookFunction) {
        // Hook interrupção
        if (interruptNumber >= (idtInfo.limit + 1) / sizeof(KIDTENTRY)) return false;
        
        // Desabilitar interrupções
        _disable();
        
        // Obter entrada da IDT
        PKIDTENTRY idtEntry = &((PKIDTENTRY)idtInfo.idtAddress)[interruptNumber];
        
        // Salvar handler original
        originalHandlers[interruptNumber] = idtEntry->OffsetLow | ((UINT64)idtEntry->OffsetMiddle << 16) |
                                          ((UINT64)idtEntry->OffsetHigh << 32);
        
        // Instalar hook
        UINT64 hookAddress = (UINT64)hookFunction;
        idtEntry->OffsetLow = (UINT16)hookAddress;
        idtEntry->OffsetMiddle = (UINT16)(hookAddress >> 16);
        idtEntry->OffsetHigh = (UINT32)(hookAddress >> 32);
        
        // Reabilitar interrupções
        _enable();
        
        return true;
    }
    
    bool HookSystemCall() {
        // Hook system call (int 0x2E)
        if (!hooks.hookInt0x2E) return false;
        
        return HookInterrupt(0x2E, &HkSystemCall);
    }
    
    bool HookPageFault() {
        // Hook page fault (int 0x0E)
        if (!hooks.hookInt0x0E) return false;
        
        return HookInterrupt(0x0E, &HkPageFault);
    }
    
    // Hook functions
    static VOID __declspec(naked) HkSystemCall() {
        // Hook para system call
        __asm {
            // Verificar se é chamada suspeita
            cmp eax, 0x26 // NtOpenProcess
            jne original_call
            
            // Verificar parâmetros
            // Implementar verificação
            
            original_call:
            // Chamar handler original
            jmp originalHandlers[0x2E]
        }
    }
    
    static VOID __declspec(naked) HkPageFault() {
        // Hook para page fault
        __asm {
            // Implementar hook
            jmp originalHandlers[0x0E]
        }
    }
    
    // Original handlers storage
    static UINT64 originalHandlers[256];
    
    // Structs
    typedef struct _KIDTR {
        UINT16 Limit;
        UINT64 Base;
    } KIDTR, *PKIDTR;
    
    typedef struct _KIDTENTRY {
        UINT16 OffsetLow;
        UINT16 Selector;
        UINT8 Ist;
        UINT8 Type : 4;
        UINT8 Zero : 1;
        UINT8 Dpl : 2;
        UINT8 Present : 1;
        UINT16 OffsetMiddle;
        UINT32 OffsetHigh;
        UINT32 Reserved;
    } KIDTENTRY, *PKIDTENTRY;
    
    typedef union _KIDTENTRY64 {
        struct {
            UINT64 Offset : 16;
            UINT64 Selector : 16;
            UINT64 Ist : 3;
            UINT64 Reserved0 : 5;
            UINT64 Type : 4;
            UINT64 Reserved1 : 1;
            UINT64 Dpl : 2;
            UINT64 Present : 1;
            UINT64 Offset2 : 16;
            UINT64 Offset3 : 32;
            UINT64 Reserved2 : 32;
        };
        UINT64 Alignment;
    } KIDTENTRY64, *PKIDTENTRY64;
};
```

### Por que é Detectado

> [!WARNING]
> **Kernel mode injection deixa rastros através de drivers suspeitos, modificações na SSDT/IDT e comportamento anormal do kernel**

#### 1. Kernel Integrity Monitoring
```cpp
// Detecção via monitoramento de integridade do kernel
class KernelIntegrityMonitor {
private:
    KERNEL_SCANNER scanner;
    INTEGRITY_CHECKER checker;
    
public:
    void MonitorKernelIntegrity() {
        // Monitorar integridade do kernel
        ScanKernelModules();
        CheckSSDTIntegrity();
        CheckIDTIntegrity();
        VerifyKernelCallbacks();
    }
    
    void ScanKernelModules() {
        // Escanear módulos do kernel
        PLIST_ENTRY moduleList = (PLIST_ENTRY)GetKernelModuleList();
        
        for (PLIST_ENTRY entry = moduleList->Flink; entry != moduleList; entry = entry->Flink) {
            PKLDR_DATA_TABLE_ENTRY module = CONTAINING_RECORD(entry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
            
            if (IsSuspiciousModule(module)) {
                ReportSuspiciousModule(module);
            }
        }
    }
    
    PVOID GetKernelModuleList() {
        // Obter lista de módulos do kernel
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"PsLoadedModuleList");
        
        return (PVOID)MmGetSystemRoutineAddress(&routineName);
    }
    
    bool IsSuspiciousModule(PKLDR_DATA_TABLE_ENTRY module) {
        // Verificar se módulo é suspeito
        // Verificar assinatura, caminho, etc.
        
        if (!VerifyModuleSignature(module)) return true;
        if (IsUnsignedModule(module)) return true;
        if (HasSuspiciousPath(module)) return true;
        
        return false;
    }
    
    void CheckSSDTIntegrity() {
        // Verificar integridade da SSDT
        PSYSTEM_SERVICE_TABLE ssdt = GetSSDTAddress();
        
        for (ULONG i = 0; i < ssdt->NumberOfServices; i++) {
            PVOID functionAddress = (PVOID)ssdt->ServiceTable[i];
            
            if (IsHookedFunction(functionAddress)) {
                ReportSSDTIntegrityViolation(i, functionAddress);
            }
        }
    }
    
    PSYSTEM_SERVICE_TABLE GetSSDTAddress() {
        // Obter endereço da SSDT
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"KeServiceDescriptorTable");
        
        return (PSYSTEM_SERVICE_TABLE)MmGetSystemRoutineAddress(&routineName);
    }
    
    bool IsHookedFunction(PVOID functionAddress) {
        // Verificar se função está hookada
        // Verificar prólogo da função
        
        if (IsInKernelRange(functionAddress)) {
            // Verificar se aponta para código do kernel
            if (!IsValidKernelFunction(functionAddress)) {
                return true;
            }
        } else {
            // Aponta para memória alocada - suspeito
            return true;
        }
        
        return false;
    }
    
    void CheckIDTIntegrity() {
        // Verificar integridade da IDT
        PIDTR idtr;
        __sidt(&idtr);
        
        PKIDTENTRY idtEntries = (PKIDTENTRY)idtr.Base;
        
        for (int i = 0; i < 256; i++) {
            UINT64 handlerAddress = GetInterruptHandlerAddress(&idtEntries[i]);
            
            if (IsHookedInterrupt(handlerAddress)) {
                ReportIDTIntegrityViolation(i, handlerAddress);
            }
        }
    }
    
    UINT64 GetInterruptHandlerAddress(PKIDTENTRY entry) {
        // Obter endereço do handler de interrupção
        return (UINT64)entry->OffsetLow | ((UINT64)entry->OffsetMiddle << 16) | ((UINT64)entry->OffsetHigh << 32);
    }
    
    bool IsHookedInterrupt(UINT64 handlerAddress) {
        // Verificar se interrupção está hookada
        // Implementar verificação
        
        return false; // Placeholder
    }
    
    void VerifyKernelCallbacks() {
        // Verificar callbacks do kernel
        // Verificar callbacks de processo, thread, imagem
        
        VerifyProcessCallbacks();
        VerifyThreadCallbacks();
        VerifyImageCallbacks();
    }
    
    void VerifyProcessCallbacks() {
        // Verificar callbacks de processo
        // Implementar verificação
    }
    
    void VerifyThreadCallbacks() {
        // Verificar callbacks de thread
        // Implementar verificação
    }
    
    void VerifyImageCallbacks() {
        // Verificar callbacks de imagem
        // Implementar verificação
    }
    
    // Utility functions
    bool VerifyModuleSignature(PKLDR_DATA_TABLE_ENTRY module) {
        // Verificar assinatura do módulo
        // Implementar verificação
        
        return true; // Placeholder
    }
    
    bool IsUnsignedModule(PKLDR_DATA_TABLE_ENTRY module) {
        // Verificar se módulo não está assinado
        // Implementar verificação
        
        return false; // Placeholder
    }
    
    bool HasSuspiciousPath(PKLDR_DATA_TABLE_ENTRY module) {
        // Verificar se caminho é suspeito
        // Implementar verificação
        
        return false; // Placeholder
    }
    
    bool IsInKernelRange(PVOID address) {
        // Verificar se endereço está no range do kernel
        return (UINT64)address >= 0xFFFFF80000000000ULL && (UINT64)address < 0xFFFFFFFFFFFFFFFFULL;
    }
    
    bool IsValidKernelFunction(PVOID address) {
        // Verificar se é função válida do kernel
        // Implementar verificação
        
        return true; // Placeholder
    }
    
    // Report functions
    void ReportSuspiciousModule(PKLDR_DATA_TABLE_ENTRY module) {
        std::cout << "Suspicious kernel module detected" << std::endl;
    }
    
    void ReportSSDTIntegrityViolation(ULONG index, PVOID address) {
        std::cout << "SSDT integrity violation at index " << index << std::endl;
    }
    
    void ReportIDTIntegrityViolation(int interrupt, UINT64 address) {
        std::cout << "IDT integrity violation at interrupt " << interrupt << std::endl;
    }
};
```

#### 2. Driver Signature Verification
```cpp
// Detecção via verificação de assinatura de drivers
class DriverSignatureVerifier {
private:
    SIGNATURE_CHECKER checker;
    CERTIFICATE_VALIDATOR validator;
    
public:
    void VerifyDriverSignatures() {
        // Verificar assinaturas de drivers
        EnumerateKernelDrivers();
        CheckDriverSignatures();
        ValidateCertificates();
    }
    
    void EnumerateKernelDrivers() {
        // Enumerar drivers do kernel
        // Usar ZwQuerySystemInformation com SystemModuleInformation
        
        ULONG bufferSize = 0;
        ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
        
        PVOID buffer = ExAllocatePoolWithTag(PagedPool, bufferSize, 'drvS');
        if (!buffer) return;
        
        NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, NULL);
        if (!NT_SUCCESS(status)) {
            ExFreePoolWithTag(buffer, 'drvS');
            return;
        }
        
        PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
        
        for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
            PSYSTEM_MODULE module = &moduleInfo->Modules[i];
            
            if (IsUnsignedDriver(module)) {
                ReportUnsignedDriver(module);
            }
        }
        
        ExFreePoolWithTag(buffer, 'drvS');
    }
    
    bool IsUnsignedDriver(PSYSTEM_MODULE module) {
        // Verificar se driver não está assinado
        // Verificar se tem assinatura válida
        
        return !HasValidSignature(module);
    }
    
    bool HasValidSignature(PSYSTEM_MODULE module) {
        // Verificar se tem assinatura válida
        // Implementar verificação
        
        return true; // Placeholder
    }
    
    void CheckDriverSignatures() {
        // Verificar assinaturas dos drivers
        // Implementar verificação
    }
    
    void ValidateCertificates() {
        // Validar certificados
        // Implementar validação
    }
    
    // Report functions
    void ReportUnsignedDriver(PSYSTEM_MODULE module) {
        std::cout << "Unsigned driver detected: " << module->ImageName << std::endl;
    }
};
```

#### 3. Anti-Kernel Injection Techniques
```cpp
// Técnicas anti-injeção no kernel
class AntiKernelInjectionProtector {
public:
    void ProtectAgainstKernelInjection() {
        // Proteger contra injeção no kernel
        PreventDriverLoading();
        ProtectSSDT();
        ProtectIDT();
        MonitorKernelMemory();
    }
    
    void PreventDriverLoading() {
        // Prevenir carregamento de drivers suspeitos
        // Hook ZwLoadDriver
        
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwLoadDriver");
        
        PVOID pZwLoadDriver = MmGetSystemRoutineAddress(&routineName);
        if (pZwLoadDriver) {
            MH_CreateHook(pZwLoadDriver, &HkZwLoadDriver, &oZwLoadDriver);
            MH_EnableHook(pZwLoadDriver);
        }
    }
    
    static NTSTATUS NTAPI HkZwLoadDriver(PUNICODE_STRING DriverServiceName) {
        // Hook para ZwLoadDriver
        // Verificar se driver é suspeito
        
        if (IsSuspiciousDriver(DriverServiceName)) {
            return STATUS_ACCESS_DENIED;
        }
        
        return oZwLoadDriver(DriverServiceName);
    }
    
    void ProtectSSDT() {
        // Proteger SSDT
        // Implementar proteção
    }
    
    void ProtectIDT() {
        // Proteger IDT
        // Implementar proteção
    }
    
    void MonitorKernelMemory() {
        // Monitorar memória do kernel
        // Implementar monitoramento
    }
    
    // Utility functions
    static bool IsSuspiciousDriver(PUNICODE_STRING driverName) {
        // Verificar se driver é suspeito
        // Implementar verificação
        
        return false; // Placeholder
    }
    
    // Original function pointers
    static decltype(&ZwLoadDriver) oZwLoadDriver;
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Kernel integrity checks | < 1 min | 95% |
| VAC Live | Driver signature verification | Imediato | 90% |
| BattlEye | SSDT/IDT monitoring | < 30s | 98% |
| Faceit AC | Kernel callback verification | < 1 min | 85% |

---

## 🔄 Alternativas Seguras

### 1. User-Mode Hooking
```cpp
// ✅ Hooking em user-mode
class UserModeHooker {
private:
    API_HOOKING hooks;
    INJECTION_ENGINE engine;
    
public:
    UserModeHooker() {
        InitializeAPIHooking();
        InitializeInjectionEngine();
    }
    
    void InitializeAPIHooking() {
        // Inicializar hooking de APIs
        hooks.hookLoadLibrary = true;
        hooks.hookGetProcAddress = true;
        hooks.hookVirtualAlloc = true;
    }
    
    void InitializeInjectionEngine() {
        // Inicializar motor de injeção
        engine.useStagedInjection = true;
        engine.useEncryptedPayload = true;
    }
    
    bool HookUserModeAPIs(DWORD targetPid) {
        // Hook APIs em user-mode
        if (!InstallAPIHooks(targetPid)) return false;
        
        if (!SetupHookHandlers()) return false;
        
        return true;
    }
    
    bool InstallAPIHooks(DWORD targetPid) {
        // Instalar hooks de API no processo alvo
        // Implementar instalação
        
        return true; // Placeholder
    }
    
    bool SetupHookHandlers() {
        // Configurar handlers de hook
        // Implementar configuração
        
        return true; // Placeholder
    }
};
```

### 2. Memory Patching
```cpp
// ✅ Patching de memória
class MemoryPatcher {
private:
    MEMORY_ANALYSIS analysis;
    PATCH_ENGINE engine;
    
public:
    MemoryPatcher() {
        InitializeMemoryAnalysis();
        InitializePatchEngine();
    }
    
    void InitializeMemoryAnalysis() {
        // Inicializar análise de memória
        analysis.scanForSignatures = true;
        analysis.findCodePatterns = true;
    }
    
    void InitializePatchEngine() {
        // Inicializar motor de patch
        engine.useInlinePatching = true;
        engine.useDetourPatching = true;
    }
    
    bool PatchMemory(DWORD targetPid, PVOID targetAddress, PVOID patchData, SIZE_T patchSize) {
        // Fazer patch na memória
        if (!AnalyzeTargetMemory(targetPid, targetAddress, patchSize)) return false;
        
        if (!ApplyMemoryPatch(targetPid, targetAddress, patchData, patchSize)) return false;
        
        return true;
    }
    
    bool AnalyzeTargetMemory(DWORD targetPid, PVOID targetAddress, SIZE_T size) {
        // Analisar memória alvo
        // Implementar análise
        
        return true; // Placeholder
    }
    
    bool ApplyMemoryPatch(DWORD targetPid, PVOID targetAddress, PVOID patchData, SIZE_T patchSize) {
        // Aplicar patch na memória
        // Implementar aplicação
        
        return true; // Placeholder
    }
};
```

### 3. DLL Injection via Registry
```cpp
// ✅ Injeção de DLL via registro
class RegistryDLLInjector {
private:
    REGISTRY_MANIPULATION registry;
    DLL_LOADING loading;
    
public:
    RegistryDLLInjector() {
        InitializeRegistryManipulation();
        InitializeDLLLoading();
    }
    
    void InitializeRegistryManipulation() {
        // Inicializar manipulação de registro
        registry.useAppInitDLLs = true;
        registry.useKnownDLLs = false;
    }
    
    void InitializeDLLLoading() {
        // Inicializar carregamento de DLL
        loading.useLoadLibrary = true;
        loading.useLdrLoadDll = true;
    }
    
    bool InjectViaRegistry(DWORD targetPid, const char* dllPath) {
        // Injetar via registro
        if (!ModifyAppInitDLLs(dllPath)) return false;
        
        if (!TriggerDLLLoading(targetPid)) return false;
        
        return true;
    }
    
    bool ModifyAppInitDLLs(const char* dllPath) {
        // Modificar AppInit_DLLs
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
                         0, KEY_SET_VALUE, &hKey) != ERROR_SUCCESS) {
            return false;
        }
        
        // Adicionar DLL
        if (RegSetValueExA(hKey, "AppInit_DLLs", 0, REG_SZ, (BYTE*)dllPath, strlen(dllPath) + 1) != ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return false;
        }
        
        // Habilitar LoadAppInit_DLLs
        DWORD enable = 1;
        RegSetValueExA(hKey, "LoadAppInit_DLLs", 0, REG_DWORD, (BYTE*)&enable, sizeof(DWORD));
        
        RegCloseKey(hKey);
        return true;
    }
    
    bool TriggerDLLLoading(DWORD targetPid) {
        // Disparar carregamento de DLL
        // Implementar trigger
        
        return true; // Placeholder
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ⚠️ Risco | Basic driver checks |
| 2015-2020 | ⚠️ Alto risco | SSDT monitoring |
| 2020-2024 | 🔴 Muito alto risco | Kernel integrity |
| 2025-2026 | 🔴 Muito alto risco | Comprehensive kernel monitoring |

---

## 🎯 Lições Aprendidas

1. **Kernel é o Último Recurso**: Kernel injection é extremamente detectável e perigosa.

2. **Drivers Precisam de Assinatura**: Drivers não assinados são imediatamente detectados.

3. **SSDT/IDT Hooking é Obsoleto**: Anti-cheats modernos monitoram essas estruturas.

4. **User-Mode é Preferível**: Técnicas user-mode são mais seguras e stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#52]]
- [[DKOM]]
- [[SSDT_Hooking]]
- [[IDT_Hooking]]

---

*Kernel mode injection techniques tem risco muito alto. Considere user-mode hooking para mais segurança.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
