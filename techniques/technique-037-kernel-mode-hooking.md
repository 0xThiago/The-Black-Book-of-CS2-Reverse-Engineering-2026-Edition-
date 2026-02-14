# 📖 Técnica 037: Kernel Mode Hooking

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ❌ Defasado/Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 037: Kernel Mode Hooking]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado/Ineficaz  
> **Risco de Detecção:** 🔴 Muito Alto  
> **Domínio:** System & Kernel  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Kernel Mode Hooking** intercepta funções do kernel do Windows para modificar comportamento do sistema. Era usado para bypass de anti-cheats, mas é altamente detectado e ineficaz em 2026.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE ALTO RISCO - KERNEL MODE HOOKING É EXTREMAMENTE PERIGOSO
// NÃO TENTE ISSO EM PRODUÇÃO - PODE CAUSAR BSOD E CORRUPÇÃO DE SISTEMA

#include <ntddk.h>

// Estrutura para hook
typedef struct _HOOK_INFO {
    PVOID OriginalFunction;
    PVOID HookFunction;
    UCHAR OriginalBytes[16]; // Bytes originais
    PMDL Mdl; // Para locking de memória
} HOOK_INFO, *PHOOK_INFO;

// Driver entry point
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    
    // Registrar unload
    DriverObject->DriverUnload = DriverUnload;
    
    // Instalar hooks
    InstallKernelHooks();
    
    DbgPrint("Kernel hooks installed\n");
    return STATUS_SUCCESS;
}

// Instalar hooks no kernel
NTSTATUS InstallKernelHooks() {
    NTSTATUS status;
    
    // Hook NtReadVirtualMemory
    status = HookFunction("NtReadVirtualMemory", &HkNtReadVirtualMemory);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to hook NtReadVirtualMemory: 0x%X\n", status);
        return status;
    }
    
    // Hook NtWriteVirtualMemory
    status = HookFunction("NtWriteVirtualMemory", &HkNtWriteVirtualMemory);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to hook NtWriteVirtualMemory: 0x%X\n", status);
        return status;
    }
    
    // Hook NtOpenProcess
    status = HookFunction("NtOpenProcess", &HkNtOpenProcess);
    if (!NT_SUCCESS(status)) {
        DbgPrint("Failed to hook NtOpenProcess: 0x%X\n", status);
        return status;
    }
    
    return STATUS_SUCCESS;
}

// Função genérica de hooking
NTSTATUS HookFunction(const char* FunctionName, PVOID HookFunction) {
    UNICODE_STRING functionName;
    PVOID functionAddress;
    NTSTATUS status;
    
    // Obter endereço da função
    RtlInitUnicodeString(&functionName, L"NtReadVirtualMemory");
    status = MmGetSystemRoutineAddress(&functionName, &functionAddress);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    
    // Criar hook info
    PHOOK_INFO hookInfo = (PHOOK_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(HOOK_INFO), 'HKIF');
    if (!hookInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Salvar informações originais
    hookInfo->OriginalFunction = functionAddress;
    hookInfo->HookFunction = HookFunction;
    
    // Ler bytes originais
    RtlCopyMemory(hookInfo->OriginalBytes, functionAddress, sizeof(hookInfo->OriginalBytes));
    
    // Criar MDL para locking
    hookInfo->Mdl = IoAllocateMdl(functionAddress, sizeof(hookInfo->OriginalBytes), FALSE, FALSE, NULL);
    if (!hookInfo->Mdl) {
        ExFreePoolWithTag(hookInfo, 'HKIF');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Lock pages
    MmProbeAndLockPages(hookInfo->Mdl, KernelMode, IoReadAccess);
    
    // Map para writable
    PVOID mappedAddress = MmMapLockedPagesSpecifyCache(hookInfo->Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
    if (!mappedAddress) {
        MmUnlockPages(hookInfo->Mdl);
        IoFreeMdl(hookInfo->Mdl);
        ExFreePoolWithTag(hookInfo, 'HKIF');
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    // Instalar hook (jump)
    UCHAR jumpCode[] = {
        0x48, 0xB8,                         // mov rax, HookFunction
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // endereço
        0xFF, 0xE0                          // jmp rax
    };
    
    *(PVOID*)&jumpCode[2] = HookFunction;
    
    // Escrever jump
    RtlCopyMemory(mappedAddress, jumpCode, sizeof(jumpCode));
    
    // Unmap
    MmUnmapLockedPages(mappedAddress, hookInfo->Mdl);
    
    // Salvar hook info globalmente
    // ... código para armazenar hookInfo ...
    
    return STATUS_SUCCESS;
}

// Hook functions
NTSTATUS HkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, 
                              SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    // Verificar se é acesso ao processo do jogo
    PEPROCESS process;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_VM_READ, *PsProcessType, 
                                               KernelMode, (PVOID*)&process, NULL);
    
    if (NT_SUCCESS(status)) {
        // Verificar se é processo do CS2
        if (IsCS2Process(process)) {
            // Modificar leitura para anti-cheat bypass
            status = ModifyReadOperation(process, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }
        
        ObDereferenceObject(process);
    }
    
    // Chamar função original
    return CallOriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
}

NTSTATUS HkNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                               SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {
    // Similar ao read, mas para escrita
    PEPROCESS process;
    NTSTATUS status = ObReferenceObjectByHandle(ProcessHandle, PROCESS_VM_WRITE, *PsProcessType,
                                               KernelMode, (PVOID*)&process, NULL);
    
    if (NT_SUCCESS(status)) {
        if (IsCS2Process(process)) {
            // Verificar/modificar operação de escrita
            status = ModifyWriteOperation(process, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
        }
        
        ObDereferenceObject(process);
    }
    
    return CallOriginalNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, BufferSize, NumberOfBytesWritten);
}

NTSTATUS HkNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, 
                        POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    // Hook para prevenir abertura de processo pelo anti-cheat
    if (ClientId && ClientId->UniqueProcess) {
        PEPROCESS targetProcess;
        NTSTATUS status = PsLookupProcessByProcessId(ClientId->UniqueProcess, &targetProcess);
        
        if (NT_SUCCESS(status)) {
            if (IsCS2Process(targetProcess)) {
                // Modificar desired access para remover direitos sensíveis
                DesiredAccess &= ~PROCESS_VM_READ;
                DesiredAccess &= ~PROCESS_VM_WRITE;
                DesiredAccess &= ~PROCESS_SUSPEND_RESUME;
            }
            
            ObDereferenceObject(targetProcess);
        }
    }
    
    return CallOriginalNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
}

// Funções auxiliares
BOOLEAN IsCS2Process(PEPROCESS Process) {
    // Verificar se é processo do CS2
    // Comparar nome do executável
    
    PUNICODE_STRING processName = NULL;
    SeLocateProcessImageName(Process, &processName);
    
    if (processName) {
        UNICODE_STRING cs2Name;
        RtlInitUnicodeString(&cs2Name, L"cs2.exe");
        
        if (RtlEqualUnicodeString(processName, &cs2Name, TRUE)) {
            return TRUE;
        }
    }
    
    return FALSE;
}

NTSTATUS ModifyReadOperation(PEPROCESS Process, PVOID BaseAddress, PVOID Buffer, 
                           SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    // Modificar operação de leitura para bypass
    // Por exemplo, ocultar módulos injetados
    
    if ((uintptr_t)BaseAddress >= 0x10000 && (uintptr_t)BaseAddress < 0x7FFFFFFFFFFF) {
        // Verificar se é leitura de memória do processo
        // Modificar buffer para ocultar cheats
        
        // Exemplo: se lendo região de código, retornar zeros para hooks
        if (IsCodeSection(BaseAddress)) {
            RtlZeroMemory(Buffer, BufferSize);
            *NumberOfBytesRead = BufferSize;
            return STATUS_SUCCESS;
        }
    }
    
    return STATUS_UNSUCCESSFUL; // Continuar com leitura normal
}

NTSTATUS ModifyWriteOperation(PEPROCESS Process, PVOID BaseAddress, PVOID Buffer,
                            SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {
    // Modificar operação de escrita
    // Prevenir escrita em regiões protegidas
    
    if (IsProtectedRegion(BaseAddress)) {
        // Bloquear escrita
        return STATUS_ACCESS_DENIED;
    }
    
    return STATUS_UNSUCCESSFUL; // Permitir escrita normal
}

BOOLEAN IsCodeSection(PVOID Address) {
    // Verificar se endereço está em seção de código
    // Usar MmIsAddressValid e verificar proteção de página
    
    return FALSE; // Placeholder
}

BOOLEAN IsProtectedRegion(PVOID Address) {
    // Verificar se é região protegida pelo anti-cheat
    
    return FALSE; // Placeholder
}

// Chamadas para funções originais
NTSTATUS CallOriginalNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, 
                                       SIZE_T BufferSize, PSIZE_T NumberOfBytesRead) {
    // Chamar função original através do hook info
    
    return STATUS_SUCCESS; // Placeholder
}

NTSTATUS CallOriginalNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer,
                                        SIZE_T BufferSize, PSIZE_T NumberOfBytesWritten) {
    // Similar ao read
    
    return STATUS_SUCCESS; // Placeholder
}

NTSTATUS CallOriginalNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess,
                                 POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    // Chamar original
    
    return STATUS_SUCCESS; // Placeholder
}

// Driver unload
VOID DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    
    // Remover hooks
    RemoveKernelHooks();
    
    DbgPrint("Kernel hooks removed\n");
}

// Remover hooks
VOID RemoveKernelHooks() {
    // Restaurar bytes originais para cada hook
    // ... código para restaurar hooks ...
}
```

### SSDT Hooking

```cpp
// SSDT hooking (mais antigo, menos usado)
typedef struct _SSDT_ENTRY {
    PVOID FunctionAddress;
} SSDT_ENTRY, *PSSDT_ENTRY;

typedef struct _SSDT {
    SSDT_ENTRY Entries[1024];
} SSDT, *PSSDT;

// Obter endereço da SSDT
PSSDT GetSSDTAddress() {
    // Encontrar SSDT através de KeServiceDescriptorTable
    extern PSSDT KeServiceDescriptorTable;
    return KeServiceDescriptorTable;
}

// Hook SSDT entry
NTSTATUS HookSSDTEntry(ULONG Index, PVOID HookFunction, PVOID* OriginalFunction) {
    PSSDT ssdt = GetSSDTAddress();
    
    if (Index >= 1024) {
        return STATUS_INVALID_PARAMETER;
    }
    
    // Desabilitar interrupts
    KIRQL oldIrql = KeRaiseIrqlToDpcLevel();
    
    // Salvar função original
    *OriginalFunction = ssdt->Entries[Index].FunctionAddress;
    
    // Instalar hook
    ssdt->Entries[Index].FunctionAddress = HookFunction;
    
    // Restaurar interrupts
    KeLowerIrql(oldIrql);
    
    return STATUS_SUCCESS;
}

// Exemplo de hook SSDT
NTSTATUS HkNtReadFile(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine,
                     PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, PVOID Buffer,
                     ULONG Length, PLARGE_INTEGER ByteOffset, PULONG Key) {
    // Hook para interceptar leitura de arquivos
    // Usado para ocultar arquivos de cheat
    
    if (IsCheatFile(FileHandle)) {
        // Modificar operação
        return STATUS_ACCESS_DENIED;
    }
    
    // Chamar original
    return OriginalNtReadFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock,
                            Buffer, Length, ByteOffset, Key);
}

BOOLEAN IsCheatFile(HANDLE FileHandle) {
    // Verificar se arquivo é relacionado a cheat
    // Comparar nome do arquivo
    
    return FALSE; // Placeholder
}
```

### IRP Hooking

```cpp
// IRP hooking para drivers
typedef NTSTATUS (*IRP_HANDLER)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

typedef struct _IRP_HOOK_INFO {
    PDRIVER_OBJECT DriverObject;
    IRP_HANDLER OriginalHandlers[IRP_MJ_MAXIMUM_FUNCTION];
    IRP_HANDLER HookHandlers[IRP_MJ_MAXIMUM_FUNCTION];
} IRP_HOOK_INFO, *PIRP_HOOK_INFO;

// Hook IRP handlers
NTSTATUS HookIRPHandlers(PDRIVER_OBJECT DriverObject) {
    PIRP_HOOK_INFO hookInfo = (PIRP_HOOK_INFO)ExAllocatePoolWithTag(NonPagedPool, sizeof(IRP_HOOK_INFO), 'IRPH');
    if (!hookInfo) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    
    hookInfo->DriverObject = DriverObject;
    
    // Hook handlers específicos
    HookIRPHandler(hookInfo, IRP_MJ_READ, &HkIRPRead);
    HookIRPHandler(hookInfo, IRP_MJ_WRITE, &HkIRPWrite);
    HookIRPHandler(hookInfo, IRP_MJ_DEVICE_CONTROL, &HkIRPDeviceControl);
    
    return STATUS_SUCCESS;
}

NTSTATUS HookIRPHandler(PIRP_HOOK_INFO HookInfo, UCHAR MajorFunction, IRP_HANDLER HookHandler) {
    // Salvar handler original
    HookInfo->OriginalHandlers[MajorFunction] = HookInfo->DriverObject->MajorFunction[MajorFunction];
    
    // Instalar hook
    HookInfo->DriverObject->MajorFunction[MajorFunction] = HookHandler;
    
    return STATUS_SUCCESS;
}

// Hook handlers
NTSTATUS HkIRPRead(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    
    // Verificar se é leitura de dispositivo suspeito
    if (IsSuspiciousDevice(DeviceObject)) {
        // Modificar operação
        Irp->IoStatus.Status = STATUS_ACCESS_DENIED;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_ACCESS_DENIED;
    }
    
    // Chamar original
    return HookInfo->OriginalHandlers[IRP_MJ_READ](DeviceObject, Irp);
}

NTSTATUS HkIRPWrite(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    // Similar ao read
    
    return HookInfo->OriginalHandlers[IRP_MJ_WRITE](DeviceObject, Irp);
}

NTSTATUS HkIRPDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);
    
    // Verificar IOCTL
    ULONG ioctl = irpSp->Parameters.DeviceIoControl.IoControlCode;
    
    if (IsAntiCheatIOCTL(ioctl)) {
        // Bloquear ou modificar IOCTL
        Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_INVALID_DEVICE_REQUEST;
    }
    
    return HookInfo->OriginalHandlers[IRP_MJ_DEVICE_CONTROL](DeviceObject, Irp);
}

BOOLEAN IsSuspiciousDevice(PDEVICE_OBJECT DeviceObject) {
    // Verificar se dispositivo é relacionado a anti-cheat
    
    return FALSE; // Placeholder
}

BOOLEAN IsAntiCheatIOCTL(ULONG Ioctl) {
    // Verificar se IOCTL é usado por anti-cheat
    
    return FALSE; // Placeholder
}
```

### Por que é Detectado

> [!DANGER]
> **Kernel mode hooking é extremamente detectado por proteção de kernel e verificações de integridade**

#### 1. Kernel Patch Protection (KPP)
```cpp
// KPP detecta modificações no kernel
void KPP_DetectKernelHooks() {
    // Verificar integridade da SSDT
    CheckSSDTIntegrity();
    
    // Verificar hooks em funções críticas
    CheckCriticalFunctionHooks();
    
    // Verificar modificações em drivers
    CheckDriverIntegrity();
}

void CheckSSDTIntegrity() {
    PSSDT ssdt = GetSSDTAddress();
    
    for (ULONG i = 0; i < 1024; i++) {
        PVOID functionAddr = ssdt->Entries[i].FunctionAddress;
        
        // Verificar se endereço está em ntoskrnl.exe
        if (!IsAddressInKernelImage(functionAddr)) {
            ReportSSDTModification(i, functionAddr);
        }
        
        // Verificar se função foi modificada
        if (IsFunctionModified(functionAddr)) {
            ReportFunctionModification(i, functionAddr);
        }
    }
}

void CheckCriticalFunctionHooks() {
    // Verificar hooks em funções críticas
    PVOID functions[] = {
        GetProcAddress(GetModuleHandleA("ntoskrnl.exe"), "NtReadVirtualMemory"),
        GetProcAddress(GetModuleHandleA("ntoskrnl.exe"), "NtWriteVirtualMemory"),
        GetProcAddress(GetModuleHandleA("ntoskrnl.exe"), "NtOpenProcess")
    };
    
    for (int i = 0; i < sizeof(functions)/sizeof(PVOID); i++) {
        if (IsFunctionHooked(functions[i])) {
            ReportCriticalFunctionHook(functions[i]);
        }
    }
}

BOOLEAN IsAddressInKernelImage(PVOID Address) {
    // Verificar se endereço está no módulo do kernel
    PVOID kernelBase = GetKernelBase();
    SIZE_T kernelSize = GetKernelSize();
    
    return (Address >= kernelBase && Address < (PVOID)((uintptr_t)kernelBase + kernelSize));
}

BOOLEAN IsFunctionModified(PVOID FunctionAddr) {
    // Verificar assinatura da função
    UCHAR expectedSignature[16];
    GetExpectedFunctionSignature(FunctionAddr, expectedSignature);
    
    return memcmp(FunctionAddr, expectedSignature, 16) != 0;
}

BOOLEAN IsFunctionHooked(PVOID FunctionAddr) {
    // Verificar se começa com jump
    PUCHAR bytes = (PUCHAR)FunctionAddr;
    
    return (bytes[0] == 0xE9 || bytes[0] == 0xEB || // JMP
            (bytes[0] == 0xFF && bytes[1] == 0x25)); // JMP DWORD PTR
}
```

#### 2. Driver Signature Verification
```cpp
// Verificação de assinatura de drivers
class DriverSignatureVerifier {
private:
    std::map<PDRIVER_OBJECT, DRIVER_SIGNATURE> driverSignatures;
    
public:
    void Initialize() {
        // Registrar drivers do sistema
        EnumerateSystemDrivers();
        
        // Hook carregamento de drivers
        HookDriverLoading();
    }
    
    void VerifyDriverSignatures() {
        // Verificar assinatura de todos os drivers carregados
        for (auto& pair : driverSignatures) {
            PDRIVER_OBJECT driver = pair.first;
            DRIVER_SIGNATURE& sig = pair.second;
            
            if (!VerifyDriverSignature(driver, sig)) {
                ReportInvalidDriverSignature(driver);
            }
        }
    }
    
    void EnumerateSystemDrivers() {
        // Enumerar drivers através de ZwQuerySystemInformation
        // SystemModuleInformation
        
        // Para cada driver, calcular hash
        // ... código para enumerar ...
    }
    
    void HookDriverLoading() {
        // Hook IoLoadDriver
        HookFunction("IoLoadDriver", &HkIoLoadDriver);
    }
    
    static NTSTATUS HkIoLoadDriver(PUNICODE_STRING DriverServiceName) {
        // Verificar assinatura antes de carregar
        if (!IsDriverSigned(DriverServiceName)) {
            return STATUS_DRIVER_UNABLE_TO_LOAD;
        }
        
        // Chamar original
        return OriginalIoLoadDriver(DriverServiceName);
    }
    
    BOOLEAN VerifyDriverSignature(PDRIVER_OBJECT Driver, DRIVER_SIGNATURE& Sig) {
        // Verificar hash do driver
        UCHAR currentHash[32];
        CalculateDriverHash(Driver, currentHash);
        
        return memcmp(currentHash, Sig.expectedHash, 32) == 0;
    }
    
    void CalculateDriverHash(PDRIVER_OBJECT Driver, UCHAR* Hash) {
        // Calcular SHA256 do código do driver
        PVOID driverBase = Driver->DriverStart;
        SIZE_T driverSize = Driver->DriverSize;
        
        // Usar BCrypt ou similar para hash
        // ... código para hash ...
    }
    
    BOOLEAN IsDriverSigned(PUNICODE_STRING DriverName) {
        // Verificar assinatura do arquivo
        // Usar ZwCreateFile e verificar certificado
        
        return FALSE; // Placeholder - em produção, verificar assinatura real
    }
};
```

#### 3. Memory Integrity Checks
```cpp
// Verificações de integridade de memória
class KernelMemoryIntegrityChecker {
private:
    std::map<PVOID, MEMORY_REGION_INFO> protectedRegions;
    
public:
    void Initialize() {
        // Registrar regiões críticas
        RegisterCriticalMemoryRegions();
        
        // Iniciar verificação periódica
        StartIntegrityMonitoring();
    }
    
    void CheckMemoryIntegrity() {
        for (auto& pair : protectedRegions) {
            PVOID regionAddr = pair.first;
            MEMORY_REGION_INFO& info = pair.second;
            
            // Verificar hash da região
            UCHAR currentHash[32];
            CalculateMemoryHash(regionAddr, info.size, currentHash);
            
            if (memcmp(currentHash, info.expectedHash, 32) != 0) {
                ReportMemoryModification(regionAddr);
            }
        }
    }
    
    void RegisterCriticalMemoryRegions() {
        // Registrar SSDT
        PSSDT ssdt = GetSSDTAddress();
        RegisterMemoryRegion((PVOID)ssdt, sizeof(SSDT), "SSDT");
        
        // Registrar IDT
        RegisterMemoryRegion(GetIDTAddress(), GetIDTSize(), "IDT");
        
        // Registrar GDT
        RegisterMemoryRegion(GetGDTAddress(), GetGDTSize(), "GDT");
        
        // Registrar handlers de IRP críticos
        // ... código para registrar ...
    }
    
    void RegisterMemoryRegion(PVOID Address, SIZE_T Size, const char* Name) {
        MEMORY_REGION_INFO info;
        info.address = Address;
        info.size = Size;
        strcpy_s(info.name, Name);
        
        // Calcular hash inicial
        CalculateMemoryHash(Address, Size, info.expectedHash);
        
        protectedRegions[Address] = info;
    }
    
    void CalculateMemoryHash(PVOID Address, SIZE_T Size, UCHAR* Hash) {
        // Calcular hash da região de memória
        // Usar SHA256
        
        // Para simplificar, usar CRC32
        *(uint32_t*)Hash = RtlComputeCrc32(0, Address, Size);
    }
    
    void StartIntegrityMonitoring() {
        // Criar thread do sistema para verificação periódica
        HANDLE threadHandle;
        PsCreateSystemThread(&threadHandle, 0, NULL, NULL, NULL, IntegrityCheckThread, this);
    }
    
    static VOID IntegrityCheckThread(PVOID Context) {
        PKernelMemoryIntegrityChecker checker = (PKernelMemoryIntegrityChecker)Context;
        
        while (TRUE) {
            // Verificar integridade a cada 30 segundos
            checker->CheckMemoryIntegrity();
            KeDelayExecutionThread(KernelMode, FALSE, (PLARGE_INTEGER)&delay30Seconds);
        }
    }
    
    void ReportMemoryModification(PVOID Address) {
        // Reportar modificação de memória crítica
        // Log ou enviar para sistema de segurança
    }
    
    PVOID GetIDTAddress() {
        // Obter endereço da IDT
        return (PVOID)__readmsr(0xC0000082); // IA32_LSTAR
    }
    
    SIZE_T GetIDTSize() {
        // Tamanho da IDT (256 entradas * 16 bytes)
        return 256 * 16;
    }
    
    PVOID GetGDTAddress() {
        // Obter endereço da GDT
        struct {
            uint16_t limit;
            uint64_t base;
        } gdtr;
        
        __sgdt(&gdtr);
        return (PVOID)gdtr.base;
    }
    
    SIZE_T GetGDTSize() {
        struct {
            uint16_t limit;
            uint64_t base;
        } gdtr;
        
        __sgdt(&gdtr);
        return gdtr.limit + 1;
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| Windows KPP | Kernel patch detection | Imediato | 95% |
| Secure Boot | Driver signature | Load time | 100% |
| VAC | Memory integrity | < 1 min | 90% |
| BattlEye | SSDT monitoring | Imediato | 85% |

---

## 🔄 Alternativas Seguras

### 1. User-Mode Hooking
```cpp
// ✅ User-mode hooking (muito mais seguro)
class UserModeHooker {
private:
    HMODULE hNtdll;
    
public:
    void Initialize() {
        hNtdll = GetModuleHandleA("ntdll.dll");
        
        // Hook funções em user-mode
        HookNtFunctions();
    }
    
    void HookNtFunctions() {
        // Hook NtReadVirtualMemory
        HookFunction(GetProcAddress(hNtdll, "NtReadVirtualMemory"), &HkNtReadVirtualMemory);
        
        // Hook NtWriteVirtualMemory
        HookFunction(GetProcAddress(hNtdll, "NtWriteVirtualMemory"), &HkNtWriteVirtualMemory);
    }
    
    uintptr_t HookFunction(uintptr_t targetFunc, uintptr_t hkFunc) {
        // Usar MinHook para hooking seguro
        MH_STATUS status = MH_CreateHook((LPVOID)targetFunc, (LPVOID)hkFunc, nullptr);
        if (status == MH_OK) {
            MH_EnableHook((LPVOID)targetFunc);
        }
        return targetFunc;
    }
    
    static NTSTATUS NTAPI HkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, 
                                               PVOID Buffer, SIZE_T BufferSize, 
                                               PSIZE_T NumberOfBytesRead) {
        // Hook em user-mode - muito mais seguro
        // Modificar leitura apenas para processo local
        
        if (IsCurrentProcess(ProcessHandle)) {
            // Aplicar modificações
            return ModifyLocalRead(BaseAddress, Buffer, BufferSize, NumberOfBytesRead);
        }
        
        // Chamar original
        return OriginalNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, 
                                         BufferSize, NumberOfBytesRead);
    }
    
    static BOOLEAN IsCurrentProcess(HANDLE ProcessHandle) {
        return ProcessHandle == NtCurrentProcess();
    }
    
    static NTSTATUS ModifyLocalRead(PVOID BaseAddress, PVOID Buffer, SIZE_T BufferSize, 
                                  PSIZE_T NumberOfBytesRead) {
        // Modificar leitura local
        // Por exemplo, ocultar hooks na memória
        
        return STATUS_SUCCESS;
    }
};
```

### 2. API Redirection
```cpp
// ✅ API redirection através de DLL proxy
class APIProxy {
public:
    void Initialize() {
        // Criar DLL proxy
        CreateProxyDLL();
        
        // Injetar proxy no processo
        InjectProxyDLL();
    }
    
    void CreateProxyDLL() {
        // Criar d3d11.dll proxy que redireciona chamadas
        // Proxy forwarda chamadas legítimas e modifica suspeitas
        
        const char* proxyCode = 
            "BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {\n"
            "    if (fdwReason == DLL_PROCESS_ATTACH) {\n"
            "        // Carregar DLL real\n"
            "        hRealDLL = LoadLibraryA(\"C:\\\\Windows\\\\System32\\\\d3d11_real.dll\");\n"
            "        \n"
            "        // Hook funções\n"
            "        HookD3D11Functions();\n"
            "    }\n"
            "    return TRUE;\n"
            "}\n"
            "\n"
            "HRESULT WINAPI D3D11CreateDevice(...) {\n"
            "    // Verificar parâmetros suspeitos\n"
            "    if (IsSuspiciousCall()) {\n"
            "        // Modificar ou bloquear\n"
            "        return D3D11_ERROR_FILE_NOT_FOUND;\n"
            "    }\n"
            "    \n"
            "    // Forward para real\n"
            "    return RealD3D11CreateDevice(...);\n"
            "}\n";
        
        // Compilar e salvar DLL proxy
        // ... código para criar DLL ...
    }
    
    void InjectProxyDLL() {
        // Injetar DLL proxy no processo do jogo
        // Usar LoadLibrary injection
        
        // Redirecionar carregamento através de PATH manipulation
        SetDllDirectoryA("C:\\ProxyDLLs\\");
    }
};
```

### 3. Virtual Machine Introspection
```cpp
// ✅ Virtual machine para isolamento
class CheatVM {
private:
    // Máquina virtual para executar cheats isoladamente
    
public:
    void Initialize() {
        // Criar VM leve
        CreateLightweightVM();
        
        // Executar cheats dentro da VM
        ExecuteCheatsInVM();
    }
    
    void CreateLightweightVM() {
        // Usar biblioteca de VM como TinyVM ou similar
        // VM executa em user-mode, isolada do kernel
        
        // ... código para VM ...
    }
    
    void ExecuteCheatsInVM() {
        // Executar lógica de cheat dentro da VM
        // VM intercepta syscalls e modifica respostas
        
        // ... código para execução ...
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010-2015 | ⚠️ Risco | KPP básico |
| 2015-2020 | ❌ Ineficaz | Secure Boot |
| 2020-2026 | ❌ Obsoleto | Kernel integrity |

---

## 🎯 Lições Aprendidas

1. **Kernel é Protegido**: Modificações no kernel são imediatamente detectadas.

2. **Drivers Precisam de Assinatura**: Drivers não assinados são bloqueados.

3. **Memória é Verificada**: Integridade da memória crítica é checada.

4. **User-Mode é Suficiente**: A maioria dos cheats pode funcionar em user-mode.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#37]]
- [[User_Mode_Hooking]]
- [[API_Proxy]]
- [[Virtual_Machine_Introspection]]

---

*Kernel mode hooking é completamente obsoleto e extremamente perigoso. Use alternativas user-mode.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
