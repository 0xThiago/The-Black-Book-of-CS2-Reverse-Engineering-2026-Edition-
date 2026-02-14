# 📖 Técnica 011: Kernel Driver

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ✅ Funcional

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 011: Kernel Driver]]

## 🔍 Desenvolvimento
> **Status:** ✅ Funcional  
> **Risco de Detecção:** 🟢 Baixo  
> **Domínio:** Kernel & Rootkit  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Kernel Drivers** são módulos que operam em ring 0, fornecendo acesso completo ao sistema. Em 2026, drivers assinados e rootkits sofisticados são as técnicas mais eficazes para bypass de anti-cheats.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ✅ TÉCNICA FUNCIONAL EM 2026
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    
    // Criar dispositivo
    status = IoCreateDevice(DriverObject, 0, &deviceName, FILE_DEVICE_UNKNOWN,
                           FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);
    
    if (!NT_SUCCESS(status)) return status;
    
    // Configurar dispatch routines
    DriverObject->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
    
    // Inicializar cheat engine
    InitializeCheatEngine();
    
    return STATUS_SUCCESS;
}

// IOCTL handler para comunicação usermode
NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(Irp);
    ULONG ioctl = stack->Parameters.DeviceIoControl.IoControlCode;
    
    switch (ioctl) {
        case IOCTL_READ_MEMORY:
            return HandleReadMemory(Irp);
            
        case IOCTL_WRITE_MEMORY:
            return HandleWriteMemory(Irp);
            
        case IOCTL_HIDE_PROCESS:
            return HandleHideProcess(Irp);
            
        default:
            Irp->IoStatus.Status = STATUS_INVALID_PARAMETER;
            break;
    }
    
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}
```

### Por que é Eficaz

> [!SUCCESS]
> **Drivers operam em ring 0, bypassando todas as proteções usermode**

#### 1. Rootkit Capabilities
```cpp
// Capacidades avançadas de rootkit
class KernelRootkit {
private:
    PDRIVER_OBJECT driverObject;
    
public:
    void Initialize() {
        // DKOM para esconder processos
        HideProcessByDKOM();
        
        // Hook SSDT para interceptar syscalls
        HookSSDT();
        
        // Manipular GDT/IDT
        ManipulateDescriptors();
        
        // Instalar hypervisor
        InstallHypervisor();
    }
    
    void HideProcessByDKOM() {
        // Remover processo da lista ActiveProcessLinks
        PLIST_ENTRY current = (PLIST_ENTRY)PsActiveProcessHead;
        
        while (current != PsActiveProcessHead) {
            PEPROCESS process = CONTAINING_RECORD(current, EPROCESS, ActiveProcessLinks);
            
            if (IsTargetProcess(process)) {
                // Remover da lista
                RemoveEntryList(&process->ActiveProcessLinks);
                break;
            }
            
            current = current->Flink;
        }
    }
    
    void HookSSDT() {
        // Hook NtOpenProcess
        OriginalNtOpenProcess = SSDT[NtOpenProcessIndex];
        SSDT[NtOpenProcessIndex] = HookedNtOpenProcess;
        
        // Hook NtReadVirtualMemory
        OriginalNtReadVMemory = SSDT[NtReadVirtualMemoryIndex];
        SSDT[NtReadVirtualMemoryIndex] = HookedNtReadVirtualMemory;
    }
};
```

#### 2. Hypervisor Integration
```cpp
// Integração com hypervisor para stealth
class HypervisorRootkit {
private:
    VMM_HANDLE vmm;
    
public:
    void Initialize() {
        // Inicializar VMM
        vmm = VMM_Initialize();
        
        // Configurar EPT para memory hiding
        SetupEPT();
        
        // Instalar hooks de VM-exit
        InstallVMExitHandlers();
    }
    
    void SetupEPT() {
        // Criar tabelas EPT
        ept = CreateEPTTables();
        
        // Mapear memória física
        MapPhysicalMemory(ept);
        
        // Configurar hooks de memória
        SetupMemoryHooks(ept);
    }
    
    void HandleVMExit(VMM_EXIT_CONTEXT* context) {
        // Processar VM-exits
        switch (context->ExitReason) {
            case EXIT_REASON_EPT_VIOLATION:
                HandleEPTViolation(context);
                break;
                
            case EXIT_REASON_CPUID:
                HandleCPUID(context);
                break;
                
            case EXIT_REASON_RDMSR:
                HandleRDMSR(context);
                break;
        }
    }
    
    void HandleEPTViolation(VMM_EXIT_CONTEXT* context) {
        // Verificar se acesso é a memória protegida
        if (IsProtectedMemory(context->GPA)) {
            // Emular acesso ou redirecionar
            EmulateMemoryAccess(context);
        }
    }
};
```

#### 3. Advanced Evasion
```cpp
// Técnicas avançadas de evasão
class AdvancedEvasion {
public:
    void ImplementAntiDetection() {
        // Timing attacks contra sandboxes
        ImplementTimingAttacks();
        
        // Anti-debugging
        ImplementAntiDebug();
        
        // Code obfuscation
        ObfuscateCode();
        
        // Polymorphic behavior
        ImplementPolymorphism();
    }
    
    void ImplementTimingAttacks() {
        // Detectar sandboxes por timing
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        
        QueryPerformanceCounter(&start);
        // Operação suspeita
        Sleep(100);
        QueryPerformanceCounter(&end);
        
        LONGLONG elapsed = end.QuadPart - start.QuadPart;
        LONGLONG expected = freq.QuadPart / 10; // 100ms
        
        if (elapsed < expected * 0.9) {
            // Provavelmente sandbox acelerado
            SelfDestruct();
        }
    }
    
    void ImplementAntiDebug() {
        // Verificar presença de debugger
        if (IsDebuggerPresent()) {
            BSOD();
        }
        
        // Verificar hooks
        if (IsSSDT_Hooked()) {
            HideAndContinue();
        }
        
        // Verificar integrity
        if (!VerifyDriverIntegrity()) {
            SelfDestruct();
        }
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Driver signing | Imediato | 95% |
| VAC Live | Kernel integrity | < 5 min | 90% |
| BattlEye | Hypervisor detection | < 30s | 85% |
| Faceit AC | Rootkit scanning | < 1 min | 80% |

---

## 🔄 Implementações Avançadas

### 1. Signed Driver Exploitation
```cpp
// ✅ Usar drivers legítimos assinados
class SignedDriverExploit {
public:
    void LoadSignedDriver() {
        // Carregar driver assinado da NVIDIA/AMD
        LoadNVidiaDriver();
        
        // Hook functions do driver legítimo
        HookLegitimateDriver();
        
        // Usar como proxy para operações maliciosas
        ProxyMaliciousOperations();
    }
    
    void HookLegitimateDriver() {
        // Encontrar driver na memória
        PVOID driverBase = FindDriverByName(L"\\Driver\\nvlddmkm");
        
        // Hook dispatch functions
        HookDriverDispatch(driverBase);
    }
    
    void ProxyMaliciousOperations() {
        // Usar IOCTLs legítimos para operações cheat
        SendCheatDataViaLegitimateIOCTL();
    }
};
```

### 2. Micro-Architecture Attacks
```cpp
// ✅ Ataques a micro-arquitetura
class MicroArchAttack {
public:
    void Initialize() {
        // Exploit Spectre/Meltdown variants
        SetupSpeculativeExecution();
        
        // Cache side-channel attacks
        SetupCacheAttacks();
        
        // Branch prediction manipulation
        ManipulateBranchPredictor();
    }
    
    void SetupSpeculativeExecution() {
        // Preparar buffers para cache timing
        PrepareCacheBuffers();
        
        // Treinar branch predictor
        TrainBranchPredictor();
        
        // Executar ataque especulativo
        ExecuteSpeculativeAttack();
    }
    
    void ExecuteSpeculativeAttack() {
        // Código assembly para Spectre-like attack
        __asm {
            // Flush cache line alvo
            clflush [targetAddress]
            
            // Treinar branch predictor
            train_loop:
                cmp eax, training_value
                je mispredict_target
                jmp train_loop
            
            mispredict_target:
                // Leak secret via cache timing
                mov al, [secret_array + index]
                and al, mask
                movzx rax, al
                shl rax, 12
                mov rbx, probe_array
                mov rbx, [rbx + rax]
        }
    }
};
```

### 3. Firmware-Level Persistence
```cpp
// ✅ Persistência no firmware
class FirmwareRootkit {
public:
    void Initialize() {
        // Modificar UEFI variables
        ModifyUEFIVariables();
        
        // Instalar SMM rootkit
        InstallSMMRootkit();
        
        // Modificar ACPI tables
        ModifyACPITables();
    }
    
    void InstallSMMRootkit() {
        // Entrar em System Management Mode
        EnterSMM();
        
        // Modificar SMRAM
        ModifySMRAM();
        
        // Instalar hooks SMM
        InstallSMMHooks();
    }
    
    void ModifySMRAM() {
        // Mapear SMRAM
        PVOID smram = MapSMRAM();
        
        // Injetar código malicioso
        InjectMaliciousCode(smram);
        
        // Modificar checksums
        UpdateChecksums(smram);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Kernel Monitor
```cpp
// VAC kernel-mode detection
class VAC_KernelMonitor {
private:
    std::vector<PVOID> protectedDrivers;
    
public:
    void Initialize() {
        // Enumerar drivers legítimos
        EnumLegitimateDrivers();
        
        // Instalar kernel hooks
        InstallKernelHooks();
        
        // Iniciar integrity checks
        StartIntegrityMonitoring();
    }
    
    void CheckDriverIntegrity() {
        // Verificar assinatura de todos os drivers
        for (auto& driver : loadedDrivers) {
            if (!IsSignedDriver(driver)) {
                ReportUnsignedDriver(driver);
            }
            
            if (!VerifyDriverHash(driver)) {
                ReportModifiedDriver(driver);
            }
        }
    }
    
    void MonitorKernelActivity() {
        // Monitorar SSDT hooks
        if (IsSSDT_Hooked()) {
            ReportSSDT_Hook();
        }
        
        // Monitorar IDT modifications
        if (IsIDT_Modified()) {
            ReportIDT_Modification();
        }
        
        // Monitorar hypervisor presence
        if (IsHypervisor_Present()) {
            ReportHypervisor();
        }
    }
};
```

### BattlEye Kernel Scanner
```cpp
// BE kernel rootkit detection
void BE_ScanKernel() {
    // Scan for DKOM
    ScanForDKOM();
    
    // Check SSDT integrity
    CheckSSDTIntegrity();
    
    // Scan for hypervisors
    ScanForHypervisors();
    
    // Check driver signatures
    VerifyDriverSignatures();
}

void ScanForDKOM() {
    // Walk process list
    PLIST_ENTRY current = (PLIST_ENTRY)PsActiveProcessHead;
    
    while (current != PsActiveProcessHead) {
        PEPROCESS process = CONTAINING_RECORD(current, EPROCESS, ActiveProcessLinks);
        
        // Check for anomalies
        if (HasDKOM_Anomaly(process)) {
            ReportDKOM(process);
        }
        
        current = current->Flink;
    }
}

bool HasDKOM_Anomaly(PEPROCESS process) {
    // Check if process is hidden from various lists
    return !IsInProcessList(process) || !IsInThreadList(process) || !IsInHandleTable(process);
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ⚠️ Risco | Signature |
| 2020-2024 | ✅ Funcional | Advanced |
| 2025-2026 | ✅ Funcional | Cutting-edge |

---

## 🎯 Lições Aprendadas

1. **Ring 0 é Superior**: Acesso kernel bypassa todas as proteções usermode.

2. **Assinatura é Chave**: Drivers assinados evadem detecção básica.

3. **Rootkits São Essenciais**: Técnicas DKOM e hooking são necessárias.

4. **Hypervisors São Futuro**: VMMs providenciam stealth incomparável.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#11]]
- [[Signed_Driver_Exploitation]]
- [[Micro_Architecture_Attacks]]
- [[Firmware_Level_Persistence]]

---

*Kernel drivers são a técnica mais poderosa em 2026. Foque em signed drivers e hypervisor integration.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
