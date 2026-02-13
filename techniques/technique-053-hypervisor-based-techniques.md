# Técnica 053: Hypervisor-Based Techniques

> **Status:** ⚠️ Risco Alto  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Virtualization  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Hypervisor-Based Techniques** utilizam hypervisors (como VMware, VirtualBox ou custom hypervisors) para executar código em um nível abaixo do sistema operacional, permitindo manipulação profunda do hardware virtualizado e bypass de proteções.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE ALTO RISCO - EXTREMAMENTE PERIGOSO
// NÃO USE EM PRODUÇÃO - APENAS PARA ANÁLISE EDUCACIONAL
class HypervisorInjector {
private:
    HYPERVISOR_COMMUNICATION hypervisorComm;
    VIRTUAL_MACHINE_CONTROL vmControl;
    MEMORY_MANIPULATION memoryManip;
    
public:
    HypervisorInjector() {
        InitializeHypervisorCommunication();
        InitializeVirtualMachineControl();
        InitializeMemoryManipulation();
    }
    
    void InitializeHypervisorCommunication() {
        // Inicializar comunicação com hypervisor
        hypervisorComm.useVMwareBackdoor = true;
        hypervisorComm.useVirtualBoxGuestAdditions = true;
        hypervisorComm.useCustomHypervisor = true;
    }
    
    void InitializeVirtualMachineControl() {
        // Inicializar controle de VM
        vmControl.controlGuestMemory = true;
        vmControl.controlGuestExecution = true;
        vmControl.interceptSystemCalls = true;
    }
    
    void InitializeMemoryManipulation() {
        // Inicializar manipulação de memória
        memoryManip.readGuestMemory = true;
        memoryManip.writeGuestMemory = true;
        memoryManip.allocateGuestMemory = true;
    }
    
    bool InjectViaHypervisor(const char* vmName, PVOID payload, SIZE_T payloadSize) {
        // Injetar payload via hypervisor
        if (!ConnectToHypervisor()) return false;
        
        if (!LocateTargetVM(vmName)) return false;
        
        if (!AllocateMemoryInVM(payloadSize)) return false;
        
        if (!WritePayloadToVM(payload, payloadSize)) return false;
        
        if (!ExecutePayloadInVM()) return false;
        
        return true;
    }
    
    bool ConnectToHypervisor() {
        // Conectar ao hypervisor
        if (hypervisorComm.useVMwareBackdoor) {
            return ConnectVMwareBackdoor();
        }
        
        if (hypervisorComm.useVirtualBoxGuestAdditions) {
            return ConnectVirtualBox();
        }
        
        if (hypervisorComm.useCustomHypervisor) {
            return ConnectCustomHypervisor();
        }
        
        return false;
    }
    
    bool ConnectVMwareBackdoor() {
        // Conectar via backdoor do VMware
        // Usar portas I/O especiais
        
        __asm {
            push eax
            push ebx
            push ecx
            push edx
            
            mov eax, 'VMXh'    // VMware magic
            mov ebx, 0x564D5868 // "VMXh"
            mov ecx, 0x0000000A // Command
            mov edx, 0x5658     // VMware I/O port
            
            in eax, dx          // VMware backdoor call
            
            pop edx
            pop ecx
            pop ebx
            pop eax
        }
        
        return true; // Placeholder - verificar resultado
    }
    
    bool ConnectVirtualBox() {
        // Conectar via VirtualBox Guest Additions
        // Implementar conexão
        
        return true; // Placeholder
    }
    
    bool ConnectCustomHypervisor() {
        // Conectar a hypervisor customizado
        // Implementar conexão
        
        return true; // Placeholder
    }
    
    bool LocateTargetVM(const char* vmName) {
        // Localizar VM alvo
        // Implementar localização
        
        return true; // Placeholder
    }
    
    bool AllocateMemoryInVM(SIZE_T size) {
        // Alocar memória na VM
        // Implementar alocação
        
        return true; // Placeholder
    }
    
    bool WritePayloadToVM(PVOID payload, SIZE_T payloadSize) {
        // Escrever payload na VM
        // Implementar escrita
        
        return true; // Placeholder
    }
    
    bool ExecutePayloadInVM() {
        // Executar payload na VM
        // Implementar execução
        
        return true; // Placeholder
    }
    
    // VM Control
    bool ControlVMExecution() {
        // Controlar execução da VM
        if (!vmControl.controlGuestExecution) return false;
        
        // Pausar VM
        PauseVM();
        
        // Modificar estado
        ModifyVMState();
        
        // Retomar VM
        ResumeVM();
        
        return true;
    }
    
    void PauseVM() {
        // Pausar VM
        // Implementar pausa
    }
    
    void ModifyVMState() {
        // Modificar estado da VM
        // Implementar modificação
    }
    
    void ResumeVM() {
        // Retomar VM
        // Implementar retomada
    }
    
    bool InterceptSystemCalls() {
        // Interceptar system calls
        if (!vmControl.interceptSystemCalls) return false;
        
        // Instalar hooks de system call
        InstallSyscallHooks();
        
        return true;
    }
    
    void InstallSyscallHooks() {
        // Instalar hooks de system call
        // Implementar instalação
    }
    
    // Memory Manipulation
    bool ManipulateGuestMemory() {
        // Manipular memória do guest
        if (!ReadGuestMemory()) return false;
        
        if (!WriteGuestMemory()) return false;
        
        if (!ScanGuestMemory()) return false;
        
        return true;
    }
    
    bool ReadGuestMemory() {
        // Ler memória do guest
        if (!memoryManip.readGuestMemory) return false;
        
        // Implementar leitura
        
        return true; // Placeholder
    }
    
    bool WriteGuestMemory() {
        // Escrever memória do guest
        if (!memoryManip.writeGuestMemory) return false;
        
        // Implementar escrita
        
        return true; // Placeholder
    }
    
    bool ScanGuestMemory() {
        // Escanear memória do guest
        // Procurar por padrões específicos
        
        return true; // Placeholder
    }
    
    // Hypervisor Implementation
    static bool CreateCustomHypervisor() {
        // Criar hypervisor customizado
        // Verificar suporte a VT-x/AMD-V
        
        if (!CheckVirtualizationSupport()) return false;
        
        // Inicializar hypervisor
        if (!InitializeHypervisor()) return false;
        
        // Criar VM
        if (!CreateVirtualMachine()) return false;
        
        return true;
    }
    
    static bool CheckVirtualizationSupport() {
        // Verificar suporte a virtualização
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        
        // Verificar bit de virtualização (bit 5 de ECX)
        return (cpuInfo[2] & (1 << 5)) != 0;
    }
    
    static bool InitializeHypervisor() {
        // Inicializar hypervisor
        // Configurar VT-x ou AMD-V
        
        return true; // Placeholder
    }
    
    static bool CreateVirtualMachine() {
        // Criar máquina virtual
        // Implementar criação
        
        return true; // Placeholder
    }
    
    // VM Exit Handling
    static void HandleVMExit() {
        // Manipular VM exits
        // Quando guest executa instrução sensível
        
        // Verificar razão do exit
        VM_EXIT_REASON exitReason = GetVMExitReason();
        
        switch (exitReason) {
            case EXIT_REASON_CPUID:
                HandleCPUIDExit();
                break;
                
            case EXIT_REASON_VMCALL:
                HandleVMCALLExit();
                break;
                
            case EXIT_REASON_EXCEPTION:
                HandleExceptionExit();
                break;
                
            default:
                // Handle other exits
                break;
        }
        
        // Retornar ao guest
        ResumeGuestExecution();
    }
    
    static VM_EXIT_REASON GetVMExitReason() {
        // Obter razão do VM exit
        // Ler VMCS ou VMCB
        
        return EXIT_REASON_CPUID; // Placeholder
    }
    
    static void HandleCPUIDExit() {
        // Manipular exit de CPUID
        // Modificar resultados para ocultar hypervisor
        
        // Escrever resultado modificado nos registradores
        // Implementar manipulação
    }
    
    static void HandleVMCALLExit() {
        // Manipular exit de VMCALL
        // Comunicação entre guest e host
        
        // Implementar manipulação
    }
    
    static void HandleExceptionExit() {
        // Manipular exit de exception
        // Implementar manipulação
    }
    
    static void ResumeGuestExecution() {
        // Retomar execução do guest
        // Implementar retomada
    }
    
    // Anti-Detection
    void ImplementAntiDetection() {
        // Implementar anti-detecção
        HideHypervisorPresence();
        SpoofCPUIDResults();
        HandleTimingAttacks();
    }
    
    void HideHypervisorPresence() {
        // Ocultar presença do hypervisor
        // Modificar resultados de detecção
        
        // Hook CPUID para ocultar hypervisor
        // Implementar ocultação
    }
    
    void SpoofCPUIDResults() {
        // Falsificar resultados de CPUID
        // Fazer parecer que não há hypervisor
        
        // Implementar falsificação
    }
    
    void HandleTimingAttacks() {
        // Manipular ataques de timing
        // Implementar manipulação
    }
};
```

### VMware Backdoor Communication

```cpp
// Comunicação via backdoor do VMware
class VMwareBackdoor {
private:
    BACKDOOR_COMMANDS commands;
    DATA_TRANSFER transfer;
    
public:
    VMwareBackdoor() {
        InitializeBackdoorCommands();
        InitializeDataTransfer();
    }
    
    void InitializeBackdoorCommands() {
        // Inicializar comandos do backdoor
        commands.getVersion = 0x0000000A;
        commands.sendMessage = 0x00000011;
        commands.receiveMessage = 0x00000012;
    }
    
    void InitializeDataTransfer() {
        // Inicializar transferência de dados
        transfer.useChannel = true;
        transfer.maxPacketSize = 4096;
    }
    
    bool SendDataViaBackdoor(PVOID data, SIZE_T size) {
        // Enviar dados via backdoor
        if (size > transfer.maxPacketSize) return false;
        
        return VMwareBackdoorCall(commands.sendMessage, (UINT32)data, size);
    }
    
    bool ReceiveDataViaBackdoor(PVOID buffer, SIZE_T size) {
        // Receber dados via backdoor
        return VMwareBackdoorCall(commands.receiveMessage, (UINT32)buffer, size);
    }
    
    bool VMwareBackdoorCall(UINT32 command, UINT32 param1, UINT32 param2) {
        // Chamada do backdoor do VMware
        bool success = false;
        
        __asm {
            push eax
            push ebx
            push ecx
            push edx
            
            mov eax, 'VMXh'        // VMware magic
            mov ebx, command       // Command
            mov ecx, param1        // Parameter 1
            mov edx, param2        // Parameter 2
            
            mov dx, 0x5658         // VMware I/O port
            in eax, dx             // VMware backdoor call
            
            mov success, al        // Result
            
            pop edx
            pop ecx
            pop ebx
            pop eax
        }
        
        return success;
    }
    
    UINT32 GetVMwareVersion() {
        // Obter versão do VMware
        UINT32 version = 0;
        
        VMwareBackdoorCall(commands.getVersion, 0, (UINT32)&version);
        
        return version;
    }
    
    bool IsVMwarePresent() {
        // Verificar se VMware está presente
        UINT32 version = GetVMwareVersion();
        
        return version != 0;
    }
    
    // Advanced backdoor operations
    bool InjectCodeViaBackdoor(DWORD targetPid, PVOID code, SIZE_T codeSize) {
        // Injetar código via backdoor
        // Preparar estrutura de injeção
        
        VMWARE_INJECTION_DATA injectData;
        injectData.targetPid = targetPid;
        injectData.code = code;
        injectData.codeSize = codeSize;
        
        // Enviar via backdoor
        return SendDataViaBackdoor(&injectData, sizeof(injectData));
    }
    
    bool ManipulateMemoryViaBackdoor(PVOID address, PVOID data, SIZE_T size, bool write) {
        // Manipular memória via backdoor
        VMWARE_MEMORY_OP memOp;
        memOp.address = address;
        memOp.data = data;
        memOp.size = size;
        memOp.write = write;
        
        return SendDataViaBackdoor(&memOp, sizeof(memOp));
    }
    
    // Structs
    typedef struct _VMWARE_INJECTION_DATA {
        DWORD targetPid;
        PVOID code;
        SIZE_T codeSize;
    } VMWARE_INJECTION_DATA, *PVMWARE_INJECTION_DATA;
    
    typedef struct _VMWARE_MEMORY_OP {
        PVOID address;
        PVOID data;
        SIZE_T size;
        bool write;
    } VMWARE_MEMORY_OP, *PVMWARE_MEMORY_OP;
};
```

### Custom Hypervisor Implementation

```cpp
// Implementação de hypervisor customizado
class CustomHypervisor {
private:
    VMM vmm;
    VMCS vmcs;
    EPT ept;
    
public:
    CustomHypervisor() {
        InitializeVMM();
        InitializeVMCS();
        InitializeEPT();
    }
    
    void InitializeVMM() {
        // Inicializar VMM (Virtual Machine Monitor)
        vmm.vmxonRegion = NULL;
        vmm.vmcsRegion = NULL;
        vmm.eptPointer = NULL;
    }
    
    void InitializeVMCS() {
        // Inicializar VMCS (Virtual Machine Control Structure)
        vmcs.guestState = NULL;
        vmcs.hostState = NULL;
        vmcs.controlFields = NULL;
    }
    
    void InitializeEPT() {
        // Inicializar EPT (Extended Page Tables)
        ept.pml4 = NULL;
        ept.pageTables = NULL;
    }
    
    bool SetupHypervisor() {
        // Configurar hypervisor
        if (!EnableVirtualization()) return false;
        
        if (!AllocateVMMRegions()) return false;
        
        if (!SetupVMCS()) return false;
        
        if (!SetupEPT()) return false;
        
        if (!LaunchVM()) return false;
        
        return true;
    }
    
    bool EnableVirtualization() {
        // Habilitar virtualização
        // Verificar suporte e habilitar VT-x
        
        // Ler CR4
        UINT64 cr4 = __readcr4();
        
        // Verificar se VMXE está habilitado
        if (!(cr4 & (1ULL << 13))) {
            // Habilitar VMXE
            __writecr4(cr4 | (1ULL << 13));
        }
        
        return true;
    }
    
    bool AllocateVMMRegions() {
        // Alocar regiões para VMM
        // VMXON region deve ser alocado em memória física contígua
        
        PHYSICAL_ADDRESS physAddr = {0};
        physAddr.QuadPart = MAXULONG64;
        
        vmm.vmxonRegion = (PVOID)MmAllocateContiguousMemory(PAGE_SIZE, physAddr);
        if (!vmm.vmxonRegion) return false;
        
        // Alocar VMCS region
        vmm.vmcsRegion = (PVOID)MmAllocateContiguousMemory(PAGE_SIZE, physAddr);
        if (!vmm.vmcsRegion) return false;
        
        return true;
    }
    
    bool SetupVMCS() {
        // Configurar VMCS
        // Inicializar estrutura VMCS
        
        // VMXON
        UINT64 vmxonPhysical = MmGetPhysicalAddress(vmm.vmxonRegion).QuadPart;
        if (__vmx_on(&vmxonPhysical)) return false;
        
        // VMCLEAR
        UINT64 vmcsPhysical = MmGetPhysicalAddress(vmm.vmcsRegion).QuadPart;
        if (__vmx_vmclear(&vmcsPhysical)) return false;
        
        // VMPTRLD
        if (__vmx_vmptrld(&vmcsPhysical)) return false;
        
        // Configurar campos de controle
        ConfigureVMCSControlFields();
        
        // Configurar estado do guest
        ConfigureGuestState();
        
        // Configurar estado do host
        ConfigureHostState();
        
        return true;
    }
    
    void ConfigureVMCSControlFields() {
        // Configurar campos de controle da VMCS
        // Pin-based controls
        __vmx_vmwrite(VMCS_PIN_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PINBASED_CTLS));
        
        // Processor-based controls
        __vmx_vmwrite(VMCS_PROC_BASED_VM_EXEC_CONTROL, AdjustControls(0, MSR_IA32_VMX_PROCBASED_CTLS));
        
        // Exception bitmap
        __vmx_vmwrite(VMCS_EXCEPTION_BITMAP, 0);
        
        // I/O bitmap A
        __vmx_vmwrite(VMCS_IO_BITMAP_A, 0);
        
        // I/O bitmap B
        __vmx_vmwrite(VMCS_IO_BITMAP_B, 0);
    }
    
    void ConfigureGuestState() {
        // Configurar estado do guest
        // Registradores
        __vmx_vmwrite(VMCS_GUEST_CR0, __readcr0());
        __vmx_vmwrite(VMCS_GUEST_CR3, __readcr3());
        __vmx_vmwrite(VMCS_GUEST_CR4, __readcr4());
        
        // Seletores de segmento
        __vmx_vmwrite(VMCS_GUEST_CS_SELECTOR, GetCs());
        __vmx_vmwrite(VMCS_GUEST_DS_SELECTOR, GetDs());
        __vmx_vmwrite(VMCS_GUEST_ES_SELECTOR, GetEs());
        __vmx_vmwrite(VMCS_GUEST_FS_SELECTOR, GetFs());
        __vmx_vmwrite(VMCS_GUEST_GS_SELECTOR, GetGs());
        __vmx_vmwrite(VMCS_GUEST_SS_SELECTOR, GetSs());
        __vmx_vmwrite(VMCS_GUEST_TR_SELECTOR, GetTr());
        __vmx_vmwrite(VMCS_GUEST_LDTR_SELECTOR, GetLdtr());
        
        // RIP e RSP
        __vmx_vmwrite(VMCS_GUEST_RIP, (UINT64)GuestEntryPoint);
        __vmx_vmwrite(VMCS_GUEST_RSP, 0); // Será configurado
        
        // RFLAGS
        __vmx_vmwrite(VMCS_GUEST_RFLAGS, __readeflags());
    }
    
    void ConfigureHostState() {
        // Configurar estado do host
        // Registradores
        __vmx_vmwrite(VMCS_HOST_CR0, __readcr0());
        __vmx_vmwrite(VMCS_HOST_CR3, __readcr3());
        __vmx_vmwrite(VMCS_HOST_CR4, __readcr4());
        
        // Seletores
        __vmx_vmwrite(VMCS_HOST_CS_SELECTOR, GetCs());
        __vmx_vmwrite(VMCS_HOST_DS_SELECTOR, GetDs());
        __vmx_vmwrite(VMCS_HOST_ES_SELECTOR, GetEs());
        __vmx_vmwrite(VMCS_HOST_FS_SELECTOR, GetFs());
        __vmx_vmwrite(VMCS_HOST_GS_SELECTOR, GetGs());
        __vmx_vmwrite(VMCS_HOST_SS_SELECTOR, GetSs());
        __vmx_vmwrite(VMCS_HOST_TR_SELECTOR, GetTr());
        
        // RIP e RSP
        __vmx_vmwrite(VMCS_HOST_RIP, (UINT64)VMExitHandler);
        __vmx_vmwrite(VMCS_HOST_RSP, 0); // Será configurado
    }
    
    bool SetupEPT() {
        // Configurar EPT
        // Criar tabelas de página extendidas
        
        // Alocar PML4
        PHYSICAL_ADDRESS physAddr = {0};
        physAddr.QuadPart = MAXULONG64;
        
        ept.pml4 = (PEPT_PML4)MmAllocateContiguousMemory(PAGE_SIZE, physAddr);
        if (!ept.pml4) return false;
        
        // Inicializar PML4
        RtlZeroMemory(ept.pml4, PAGE_SIZE);
        
        // Configurar EPT pointer
        EPT_POINTER eptPtr;
        eptPtr.MemoryType = 6; // Write-back
        eptPtr.PageWalkLength = 3; // 4-level paging
        eptPtr.EnableAccessAndDirtyFlags = 0;
        eptPtr.Reserved1 = 0;
        eptPtr.PhysicalAddress = MmGetPhysicalAddress(ept.pml4).QuadPart >> 12;
        
        __vmx_vmwrite(VMCS_EPT_POINTER, eptPtr.Flags);
        
        return true;
    }
    
    bool LaunchVM() {
        // Lançar VM
        UINT64 error = 0;
        
        if (__vmx_vmlaunch()) {
            error = __vmx_vmread(VMCS_VM_INSTRUCTION_ERROR);
            return false;
        }
        
        return true;
    }
    
    // VM Exit Handler
    static VOID VMExitHandler() {
        // Manipular VM exit
        UINT64 exitReason = 0;
        __vmx_vmread(VMCS_EXIT_REASON, &exitReason);
        
        exitReason &= 0xFFFF; // Máscara para obter razão
        
        switch (exitReason) {
            case EXIT_REASON_EXCEPTION_NMI:
                HandleException();
                break;
                
            case EXIT_REASON_EXTERNAL_INTERRUPT:
                HandleExternalInterrupt();
                break;
                
            case EXIT_REASON_TRIPLE_FAULT:
                HandleTripleFault();
                break;
                
            case EXIT_REASON_INIT_SIGNAL:
                HandleInitSignal();
                break;
                
            case EXIT_REASON_SIPI_SIGNAL:
                HandleSIPISignal();
                break;
                
            case EXIT_REASON_IO_SMI:
                HandleIOSMI();
                break;
                
            case EXIT_REASON_OTHER_SMI:
                HandleOtherSMI();
                break;
                
            case EXIT_REASON_PENDING_INTERRUPT:
                HandlePendingInterrupt();
                break;
                
            case EXIT_REASON_NMI_WINDOW:
                HandleNMIWindow();
                break;
                
            case EXIT_REASON_TASK_SWITCH:
                HandleTaskSwitch();
                break;
                
            case EXIT_REASON_CPUID:
                HandleCPUID();
                break;
                
            case EXIT_REASON_GETSEC:
                HandleGETSEC();
                break;
                
            case EXIT_REASON_HLT:
                HandleHLT();
                break;
                
            case EXIT_REASON_INVD:
                HandleINVD();
                break;
                
            case EXIT_REASON_INVLPG:
                HandleINVLPG();
                break;
                
            case EXIT_REASON_RDPMC:
                HandleRDPMC();
                break;
                
            case EXIT_REASON_RDTSC:
                HandleRDTSC();
                break;
                
            case EXIT_REASON_RSM:
                HandleRSM();
                break;
                
            case EXIT_REASON_VMCALL:
                HandleVMCALL();
                break;
                
            case EXIT_REASON_VMCLEAR:
                HandleVMCLEAR();
                break;
                
            case EXIT_REASON_VMLAUNCH:
                HandleVMLAUNCH();
                break;
                
            case EXIT_REASON_VMPTRLD:
                HandleVMPTRLD();
                break;
                
            case EXIT_REASON_VMPTRST:
                HandleVMPTRST();
                break;
                
            case EXIT_REASON_VMREAD:
                HandleVMREAD();
                break;
                
            case EXIT_REASON_VMRESUME:
                HandleVMRESUME();
                break;
                
            case EXIT_REASON_VMWRITE:
                HandleVMWRITE();
                break;
                
            case EXIT_REASON_VMXOFF:
                HandleVMXOFF();
                break;
                
            case EXIT_REASON_VMXON:
                HandleVMXON();
                break;
                
            case EXIT_REASON_CR_ACCESS:
                HandleCRAccess();
                break;
                
            case EXIT_REASON_DR_ACCESS:
                HandleDR Access();
                break;
                
            case EXIT_REASON_IO_INSTRUCTION:
                HandleIOInstruction();
                break;
                
            case EXIT_REASON_MSR_READ:
                HandleMSRRead();
                break;
                
            case EXIT_REASON_MSR_WRITE:
                HandleMSRWrite();
                break;
                
            case EXIT_REASON_INVALID_GUEST_STATE:
                HandleInvalidGuestState();
                break;
                
            case EXIT_REASON_MSR_LOADING:
                HandleMSRLoading();
                break;
                
            case EXIT_REASON_MWAIT_INSTRUCTION:
                HandleMWAITInstruction();
                break;
                
            case EXIT_REASON_MONITOR_TRAP_FLAG:
                HandleMonitorTrapFlag();
                break;
                
            case EXIT_REASON_MONITOR_INSTRUCTION:
                HandleMonitorInstruction();
                break;
                
            case EXIT_REASON_PAUSE_INSTRUCTION:
                HandlePauseInstruction();
                break;
                
            case EXIT_REASON_MCE_DURING_VMENTRY:
                HandleMCEDuringVMEntry();
                break;
                
            case EXIT_REASON_TPR_BELOW_THRESHOLD:
                HandleTPRBelowThreshold();
                break;
                
            case EXIT_REASON_APIC_ACCESS:
                HandleAPICAccess();
                break;
                
            case EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR:
                HandleAccessToGDTRorIDTR();
                break;
                
            case EXIT_REASON_ACCESS_TO_LDTR_OR_TR:
                HandleAccessToLDTRorTR();
                break;
                
            case EXIT_REASON_EPT_VIOLATION:
                HandleEPTViolation();
                break;
                
            case EXIT_REASON_EPT_MISCONFIGURATION:
                HandleEPTMisconfiguration();
                break;
                
            case EXIT_REASON_INVEPT:
                HandleINVEPT();
                break;
                
            case EXIT_REASON_RDTSCP:
                HandleRDTSCP();
                break;
                
            case EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED:
                HandleVMXPreemptionTimerExpired();
                break;
                
            case EXIT_REASON_INVVPID:
                HandleINVVPID();
                break;
                
            case EXIT_REASON_WBINVD:
                HandleWBINVD();
                break;
                
            case EXIT_REASON_XSETBV:
                HandleXSETBV();
                break;
                
            case EXIT_REASON_APIC_WRITE:
                HandleAPICWrite();
                break;
                
            case EXIT_REASON_RDRAND:
                HandleRDRAND();
                break;
                
            case EXIT_REASON_INVPCID:
                HandleINVPCID();
                break;
                
            case EXIT_REASON_RDSEED:
                HandleRDSEED();
                break;
                
            case EXIT_REASON_PML_FULL:
                HandlePMLFull();
                break;
                
            case EXIT_REASON_XSAVES:
                HandleXSAVES();
                break;
                
            case EXIT_REASON_XRSTORS:
                HandleXRSTORS();
                break;
                
            default:
                // Handle unknown exit reason
                break;
        }
        
        // Resume guest
        __vmx_vmresume();
    }
    
    // Handler implementations (placeholders)
    static void HandleException() { /* Implement */ }
    static void HandleExternalInterrupt() { /* Implement */ }
    static void HandleTripleFault() { /* Implement */ }
    static void HandleInitSignal() { /* Implement */ }
    static void HandleSIPISignal() { /* Implement */ }
    static void HandleIOSMI() { /* Implement */ }
    static void HandleOtherSMI() { /* Implement */ }
    static void HandlePendingInterrupt() { /* Implement */ }
    static void HandleNMIWindow() { /* Implement */ }
    static void HandleTaskSwitch() { /* Implement */ }
    static void HandleCPUID() { /* Implement */ }
    static void HandleGETSEC() { /* Implement */ }
    static void HandleHLT() { /* Implement */ }
    static void HandleINVD() { /* Implement */ }
    static void HandleINVLPG() { /* Implement */ }
    static void HandleRDPMC() { /* Implement */ }
    static void HandleRDTSC() { /* Implement */ }
    static void HandleRSM() { /* Implement */ }
    static void HandleVMCALL() { /* Implement */ }
    static void HandleVMCLEAR() { /* Implement */ }
    static void HandleVMLAUNCH() { /* Implement */ }
    static void HandleVMPTRLD() { /* Implement */ }
    static void HandleVMPTRST() { /* Implement */ }
    static void HandleVMREAD() { /* Implement */ }
    static void HandleVMRESUME() { /* Implement */ }
    static void HandleVMWRITE() { /* Implement */ }
    static void HandleVMXOFF() { /* Implement */ }
    static void HandleVMXON() { /* Implement */ }
    static void HandleCRAccess() { /* Implement */ }
    static void HandleDR Access() { /* Implement */ }
    static void HandleIOInstruction() { /* Implement */ }
    static void HandleMSRRead() { /* Implement */ }
    static void HandleMSRWrite() { /* Implement */ }
    static void HandleInvalidGuestState() { /* Implement */ }
    static void HandleMSRLoading() { /* Implement */ }
    static void HandleMWAITInstruction() { /* Implement */ }
    static void HandleMonitorTrapFlag() { /* Implement */ }
    static void HandleMonitorInstruction() { /* Implement */ }
    static void HandlePauseInstruction() { /* Implement */ }
    static void HandleMCEDuringVMEntry() { /* Implement */ }
    static void HandleTPRBelowThreshold() { /* Implement */ }
    static void HandleAPICAccess() { /* Implement */ }
    static void HandleAccessToGDTRorIDTR() { /* Implement */ }
    static void HandleAccessToLDTRorTR() { /* Implement */ }
    static void HandleEPTViolation() { /* Implement */ }
    static void HandleEPTMisconfiguration() { /* Implement */ }
    static void HandleINVEPT() { /* Implement */ }
    static void HandleRDTSCP() { /* Implement */ }
    static void HandleVMXPreemptionTimerExpired() { /* Implement */ }
    static void HandleINVVPID() { /* Implement */ }
    static void HandleWBINVD() { /* Implement */ }
    static void HandleXSETBV() { /* Implement */ }
    static void HandleAPICWrite() { /* Implement */ }
    static void HandleRDRAND() { /* Implement */ }
    static void HandleINVPCID() { /* Implement */ }
    static void HandleRDSEED() { /* Implement */ }
    static void HandlePMLFull() { /* Implement */ }
    static void HandleXSAVES() { /* Implement */ }
    static void HandleXRSTORS() { /* Implement */ }
    
    static VOID GuestEntryPoint() {
        // Ponto de entrada do guest
        // Código que roda na VM
        
        // Executar payload
        // ...
        
        // Sair da VM
        __vmx_off();
    }
    
    // VMCS Field Encodings (simplified)
    #define VMCS_VIRTUAL_PROCESSOR_ID 0x00000000
    #define VMCS_POSTED_INTR_NOTIFICATION_VECTOR 0x00000002
    #define VMCS_EPTP_INDEX 0x00000004
    #define VMCS_GUEST_ES_SELECTOR 0x00000800
    #define VMCS_GUEST_CS_SELECTOR 0x00000802
    #define VMCS_GUEST_SS_SELECTOR 0x00000804
    #define VMCS_GUEST_DS_SELECTOR 0x00000806
    #define VMCS_GUEST_FS_SELECTOR 0x00000808
    #define VMCS_GUEST_GS_SELECTOR 0x0000080A
    #define VMCS_GUEST_LDTR_SELECTOR 0x0000080C
    #define VMCS_GUEST_TR_SELECTOR 0x0000080E
    #define VMCS_GUEST_INTR_STATUS 0x00000810
    #define VMCS_HOST_ES_SELECTOR 0x00000C00
    #define VMCS_HOST_CS_SELECTOR 0x00000C02
    #define VMCS_HOST_SS_SELECTOR 0x00000C04
    #define VMCS_HOST_DS_SELECTOR 0x00000C06
    #define VMCS_HOST_FS_SELECTOR 0x00000C08
    #define VMCS_HOST_GS_SELECTOR 0x00000C0A
    #define VMCS_HOST_TR_SELECTOR 0x00000C0C
    #define VMCS_IO_BITMAP_A 0x00002000
    #define VMCS_IO_BITMAP_B 0x00002002
    #define VMCS_MSR_BITMAP 0x00002004
    #define VMCS_VM_EXIT_MSR_STORE_ADDR 0x00002006
    #define VMCS_VM_EXIT_MSR_LOAD_ADDR 0x00002008
    #define VMCS_VM_ENTRY_MSR_LOAD_ADDR 0x0000200A
    #define VMCS_EXECUTIVE_VMCS_PTR 0x0000200C
    #define VMCS_TSC_OFFSET 0x00002010
    #define VMCS_VIRTUAL_APIC_PAGE_ADDR 0x00002012
    #define VMCS_APIC_ACCESS_ADDR 0x00002014
    #define VMCS_EPT_POINTER 0x0000201A
    #define VMCS_GUEST_PHYSICAL_ADDRESS 0x00002400
    #define VMCS_VMCS_LINK_PTR 0x00002800
    #define VMCS_GUEST_IA32_DEBUGCTL 0x00002802
    #define VMCS_GUEST_IA32_PAT 0x00002804
    #define VMCS_GUEST_IA32_EFER 0x00002806
    #define VMCS_GUEST_IA32_PERF_GLOBAL_CTRL 0x00002808
    #define VMCS_GUEST_PDPTE0 0x0000280A
    #define VMCS_GUEST_PDPTE1 0x0000280C
    #define VMCS_GUEST_PDPTE2 0x0000280E
    #define VMCS_GUEST_PDPTE3 0x00002810
    #define VMCS_HOST_IA32_PAT 0x00002C00
    #define VMCS_HOST_IA32_EFER 0x00002C02
    #define VMCS_HOST_IA32_PERF_GLOBAL_CTRL 0x00002C04
    #define VMCS_PIN_BASED_VM_EXEC_CONTROL 0x00004000
    #define VMCS_PROC_BASED_VM_EXEC_CONTROL 0x00004002
    #define VMCS_EXCEPTION_BITMAP 0x00004004
    #define VMCS_PAGE_FAULT_ERROR_CODE_MASK 0x00004006
    #define VMCS_PAGE_FAULT_ERROR_CODE_MATCH 0x00004008
    #define VMCS_CR3_TARGET_COUNT 0x0000400A
    #define VMCS_VM_EXIT_CONTROLS 0x0000400C
    #define VMCS_VM_EXIT_MSR_STORE_COUNT 0x0000400E
    #define VMCS_VM_EXIT_MSR_LOAD_COUNT 0x00004010
    #define VMCS_VM_ENTRY_CONTROLS 0x00004012
    #define VMCS_VM_ENTRY_MSR_LOAD_COUNT 0x00004014
    #define VMCS_VM_ENTRY_INTR_INFO_FIELD 0x00004016
    #define VMCS_VM_ENTRY_EXCEPTION_ERROR_CODE 0x00004018
    #define VMCS_VM_ENTRY_INSTRUCTION_LEN 0x0000401A
    #define VMCS_TPR_THRESHOLD 0x0000401C
    #define VMCS_SECONDARY_VM_EXEC_CONTROL 0x0000401E
    #define VMCS_PLE_GAP 0x00004020
    #define VMCS_PLE_WINDOW 0x00004022
    #define VMCS_INSTRUCTION_TIMEOUT 0x00004024
    #define VMCS_GUEST_CR0 0x00006800
    #define VMCS_GUEST_CR3 0x00006802
    #define VMCS_GUEST_CR4 0x00006804
    #define VMCS_GUEST_ES_BASE 0x00006806
    #define VMCS_GUEST_CS_BASE 0x00006808
    #define VMCS_GUEST_SS_BASE 0x0000680A
    #define VMCS_GUEST_DS_BASE 0x0000680C
    #define VMCS_GUEST_FS_BASE 0x0000680E
    #define VMCS_GUEST_GS_BASE 0x00006810
    #define VMCS_GUEST_LDTR_BASE 0x00006812
    #define VMCS_GUEST_TR_BASE 0x00006814
    #define VMCS_GUEST_GDTR_BASE 0x00006816
    #define VMCS_GUEST_IDTR_BASE 0x00006818
    #define VMCS_GUEST_DR7 0x0000681A
    #define VMCS_GUEST_RSP 0x0000681C
    #define VMCS_GUEST_RIP 0x0000681E
    #define VMCS_GUEST_RFLAGS 0x00006820
    #define VMCS_GUEST_PENDING_DEBUG_EXCEPTIONS 0x00006822
    #define VMCS_GUEST_SYSENTER_ESP 0x00006824
    #define VMCS_GUEST_SYSENTER_EIP 0x00006826
    #define VMCS_HOST_CR0 0x00006C00
    #define VMCS_HOST_CR3 0x00006C02
    #define VMCS_HOST_CR4 0x00006C04
    #define VMCS_HOST_FS_BASE 0x00006C06
    #define VMCS_HOST_GS_BASE 0x00006C08
    #define VMCS_HOST_TR_BASE 0x00006C0A
    #define VMCS_HOST_GDTR_BASE 0x00006C0C
    #define VMCS_HOST_IDTR_BASE 0x00006C0E
    #define VMCS_HOST_IA32_SYSENTER_ESP 0x00006C10
    #define VMCS_HOST_IA32_SYSENTER_EIP 0x00006C12
    #define VMCS_HOST_RSP 0x00006C14
    #define VMCS_HOST_RIP 0x00006C16
    #define VMCS_IO_RCX 0x00006400
    #define VMCS_IO_RSI 0x00006402
    #define VMCS_IO_RDI 0x00006404
    #define VMCS_IO_RIP 0x00006406
    #define VMCS_EXIT_REASON 0x00004402
    #define VMCS_VM_INSTRUCTION_ERROR 0x00004400
    #define VMCS_EXIT_QUALIFICATION 0x00006400
    #define VMCS_IO_ECX 0x00006402
    #define VMCS_IO_ESI 0x00006404
    #define VMCS_IO_EDI 0x00006406
    #define VMCS_IO_EIP 0x00006408
    #define VMCS_VMX_INSTRUCTION_INFO 0x0000640A
    #define VMCS_GUEST_LINEAR_ADDRESS 0x0000640C
    #define VMCS_GUEST_PAGING 0x0000440A
    #define VMCS_GUEST_INTERRUPTIBILITY_INFO 0x00004424
    #define VMCS_GUEST_ACTIVITY_STATE 0x00004426
    #define VMCS_DATA_TRANSFER 0x00004428
    #define VMCS_DATA_OFFSET 0x0000442A
    #define VMCS_DATA_LENGTH 0x0000442C
    #define VMCS_DATA_DIRECTION 0x0000442E
    #define VMCS_DATA_STRING 0x00004430
    #define VMCS_DATA_REP 0x00004432
    #define VMCS_DATA_REP_COUNT 0x00004434
    #define VMCS_DATA_XFER 0x00004436
    #define VMCS_DATA_XFER_COUNT 0x00004438
    #define VMCS_DATA_XFER_TYPE 0x0000443A
    #define VMCS_DATA_XFER_WIDTH 0x0000443C
    #define VMCS_DATA_XFER_SEGMENT 0x0000443E
    #define VMCS_DATA_XFER_ES 0x00004440
    #define VMCS_DATA_XFER_CS 0x00004442
    #define VMCS_DATA_XFER_SS 0x00004444
    #define VMCS_DATA_XFER_DS 0x00004446
    #define VMCS_DATA_XFER_FS 0x00004448
    #define VMCS_DATA_XFER_GS 0x0000444A
    #define VMCS_DATA_XFER_LDTR 0x0000444C
    #define VMCS_DATA_XFER_TR 0x0000444E
    #define VMCS_DATA_XFER_GDTR 0x00004450
    #define VMCS_DATA_XFER_IDTR 0x00004452
    #define VMCS_DATA_XFER_DR7 0x00004454
    #define VMCS_DATA_XFER_RSP 0x00004456
    #define VMCS_DATA_XFER_RIP 0x00004458
    #define VMCS_DATA_XFER_RFLAGS 0x0000445A
    #define VMCS_DATA_XFER_PENDING_DEBUG_EXCEPTIONS 0x0000445C
    #define VMCS_DATA_XFER_SYSENTER_ESP 0x0000445E
    #define VMCS_DATA_XFER_SYSENTER_EIP 0x00004460
    #define VMCS_DATA_XFER_CR0 0x00004462
    #define VMCS_DATA_XFER_CR3 0x00004464
    #define VMCS_DATA_XFER_CR4 0x00004466
    #define VMCS_DATA_XFER_ES_BASE 0x00004468
    #define VMCS_DATA_XFER_CS_BASE 0x0000446A
    #define VMCS_DATA_XFER_SS_BASE 0x0000446C
    #define VMCS_DATA_XFER_DS_BASE 0x0000446E
    #define VMCS_DATA_XFER_FS_BASE 0x00004470
    #define VMCS_DATA_XFER_GS_BASE 0x00004472
    #define VMCS_DATA_XFER_LDTR_BASE 0x00004474
    #define VMCS_DATA_XFER_TR_BASE 0x00004476
    #define VMCS_DATA_XFER_GDTR_BASE 0x00004478
    #define VMCS_DATA_XFER_IDTR_BASE 0x0000447A
    #define VMCS_DATA_XFER_DR7 0x0000447C
    #define VMCS_DATA_XFER_RSP 0x0000447E
    #define VMCS_DATA_XFER_RIP 0x00004480
    #define VMCS_DATA_XFER_RFLAGS 0x00004482
    #define VMCS_DATA_XFER_PENDING_DEBUG_EXCEPTIONS 0x00004484
    #define VMCS_DATA_XFER_SYSENTER_ESP 0x00004486
    #define VMCS_DATA_XFER_SYSENTER_EIP 0x00004488
    #define VMCS_HOST_CR0 0x00006C00
    #define VMCS_HOST_CR3 0x00006C02
    #define VMCS_HOST_CR4 0x00006C04
    #define VMCS_HOST_FS_BASE 0x00006C06
    #define VMCS_HOST_GS_BASE 0x00006C08
    #define VMCS_HOST_TR_BASE 0x00006C0A
    #define VMCS_HOST_GDTR_BASE 0x00006C0C
    #define VMCS_HOST_IDTR_BASE 0x00006C0E
    #define VMCS_HOST_IA32_SYSENTER_ESP 0x00006C10
    #define VMCS_HOST_IA32_SYSENTER_EIP 0x00006C12
    #define VMCS_HOST_RSP 0x00006C14
    #define VMCS_HOST_RIP 0x00006C16
    
    // Exit reasons
    #define EXIT_REASON_EXCEPTION_NMI 0
    #define EXIT_REASON_EXTERNAL_INTERRUPT 1
    #define EXIT_REASON_TRIPLE_FAULT 2
    #define EXIT_REASON_INIT_SIGNAL 3
    #define EXIT_REASON_SIPI_SIGNAL 4
    #define EXIT_REASON_IO_SMI 5
    #define EXIT_REASON_OTHER_SMI 6
    #define EXIT_REASON_PENDING_INTERRUPT 7
    #define EXIT_REASON_NMI_WINDOW 8
    #define EXIT_REASON_TASK_SWITCH 9
    #define EXIT_REASON_CPUID 10
    #define EXIT_REASON_GETSEC 11
    #define EXIT_REASON_HLT 12
    #define EXIT_REASON_INVD 13
    #define EXIT_REASON_INVLPG 14
    #define EXIT_REASON_RDPMC 15
    #define EXIT_REASON_RDTSC 16
    #define EXIT_REASON_RSM 17
    #define EXIT_REASON_VMCALL 18
    #define EXIT_REASON_VMCLEAR 19
    #define EXIT_REASON_VMLAUNCH 20
    #define EXIT_REASON_VMPTRLD 21
    #define EXIT_REASON_VMPTRST 22
    #define EXIT_REASON_VMREAD 23
    #define EXIT_REASON_VMRESUME 24
    #define EXIT_REASON_VMWRITE 25
    #define EXIT_REASON_VMXOFF 26
    #define EXIT_REASON_VMXON 27
    #define EXIT_REASON_CR_ACCESS 28
    #define EXIT_REASON_DR_ACCESS 29
    #define EXIT_REASON_IO_INSTRUCTION 30
    #define EXIT_REASON_MSR_READ 31
    #define EXIT_REASON_MSR_WRITE 32
    #define EXIT_REASON_INVALID_GUEST_STATE 33
    #define EXIT_REASON_MSR_LOADING 34
    #define EXIT_REASON_MWAIT_INSTRUCTION 36
    #define EXIT_REASON_MONITOR_TRAP_FLAG 37
    #define EXIT_REASON_MONITOR_INSTRUCTION 39
    #define EXIT_REASON_PAUSE_INSTRUCTION 40
    #define EXIT_REASON_MCE_DURING_VMENTRY 41
    #define EXIT_REASON_TPR_BELOW_THRESHOLD 43
    #define EXIT_REASON_APIC_ACCESS 44
    #define EXIT_REASON_ACCESS_TO_GDTR_OR_IDTR 46
    #define EXIT_REASON_ACCESS_TO_LDTR_OR_TR 47
    #define EXIT_REASON_EPT_VIOLATION 48
    #define EXIT_REASON_EPT_MISCONFIGURATION 49
    #define EXIT_REASON_INVEPT 50
    #define EXIT_REASON_RDTSCP 51
    #define EXIT_REASON_VMX_PREEMPTION_TIMER_EXPIRED 52
    #define EXIT_REASON_INVVPID 53
    #define EXIT_REASON_WBINVD 54
    #define EXIT_REASON_XSETBV 55
    #define EXIT_REASON_APIC_WRITE 56
    #define EXIT_REASON_RDRAND 57
    #define EXIT_REASON_INVPCID 58
    #define EXIT_REASON_RDSEED 59
    #define EXIT_REASON_PML_FULL 60
    #define EXIT_REASON_XSAVES 61
    #define EXIT_REASON_XRSTORS 62
    
    // Structs
    typedef struct _EPT_POINTER {
        UINT64 MemoryType : 3;
        UINT64 PageWalkLength : 3;
        UINT64 EnableAccessAndDirtyFlags : 1;
        UINT64 Reserved1 : 5;
        UINT64 PhysicalAddress : 36;
        UINT64 Reserved2 : 16;
    } EPT_POINTER, *PEPT_POINTER;
    
    typedef union _EPT_PML4 {
        UINT64 Flags;
        struct {
            UINT64 Read : 1;
            UINT64 Write : 1;
            UINT64 Execute : 1;
            UINT64 Reserved1 : 5;
            UINT64 Accessed : 1;
            UINT64 Reserved2 : 1;
            UINT64 UserModeExecute : 1;
            UINT64 Reserved3 : 1;
            UINT64 PhysicalAddress : 36;
            UINT64 Reserved4 : 16;
        };
    } EPT_PML4, *PEPT_PML4;
};
```

### Por que é Detectado

> [!WARNING]
> **Hypervisor-based techniques deixam rastros através de detecção de virtualização, timing anomalies e comportamento anormal do sistema**

#### 1. Virtualization Detection
```cpp
// Detecção de virtualização
class VirtualizationDetector {
private:
    CPUID_CHECKER cpuidChecker;
    TIMING_ANALYZER timingAnalyzer;
    ARTIFACT_SCANNER artifactScanner;
    
public:
    void DetectVirtualization() {
        // Detectar virtualização
        CheckCPUID();
        AnalyzeTiming();
        ScanForArtifacts();
    }
    
    void CheckCPUID() {
        // Verificar CPUID
        int cpuInfo[4];
        
        // CPUID com EAX=1
        __cpuid(cpuInfo, 1);
        
        // Verificar bit de hypervisor (bit 31 de ECX)
        if (cpuInfo[2] & (1 << 31)) {
            ReportHypervisorPresent();
        }
        
        // CPUID com EAX=0x40000000 (Hypervisor CPUID leaf)
        __cpuid(cpuInfo, 0x40000000);
        
        // Verificar se é VMware/VirtualBox/etc
        if (cpuInfo[0] == 'VMwa' || cpuInfo[0] == 'VBox') {
            ReportSpecificHypervisor(cpuInfo[0]);
        }
    }
    
    void AnalyzeTiming() {
        // Analisar timing
        // Ataques de timing podem detectar hypervisors
        
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        
        // Medir tempo de instrução sensível
        QueryPerformanceCounter(&start);
        
        // Instrução que pode causar VM exit
        __cpuid((int[4]){0}, 0);
        
        QueryPerformanceCounter(&end);
        
        double time = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
        
        if (time > EXPECTED_CPUID_TIME) {
            ReportTimingAnomaly();
        }
    }
    
    void ScanForArtifacts() {
        // Procurar por artefatos
        ScanRegistryForVMArtifacts();
        ScanFilesForVMArtifacts();
        ScanProcessesForVMArtifacts();
    }
    
    void ScanRegistryForVMArtifacts() {
        // Escanear registro por artefatos de VM
        HKEY hKey;
        
        // VMware
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\VMware, Inc.\\VMware Tools", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            ReportVMwareDetected();
            RegCloseKey(hKey);
        }
        
        // VirtualBox
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Oracle\\VirtualBox Guest Additions", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            ReportVirtualBoxDetected();
            RegCloseKey(hKey);
        }
    }
    
    void ScanFilesForVMArtifacts() {
        // Escanear arquivos por artefatos de VM
        // VMware tools, VirtualBox Guest Additions, etc.
        
        const char* vmFiles[] = {
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\VBoxGuest.sys",
            "C:\\Windows\\System32\\VBoxSF.sys"
        };
        
        for (const char* file : vmFiles) {
            if (GetFileAttributesA(file) != INVALID_FILE_ATTRIBUTES) {
                ReportVMArtifactFound(file);
            }
        }
    }
    
    void ScanProcessesForVMArtifacts() {
        // Escanear processos por artefatos de VM
        // vmtoolsd.exe, VBoxService.exe, etc.
        
        const char* vmProcesses[] = {
            "vmtoolsd.exe",
            "VBoxService.exe",
            "VBoxTray.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (const char* vmProc : vmProcesses) {
                    if (_stricmp(pe.szExeFile, vmProc) == 0) {
                        ReportVMProcessFound(pe.szExeFile);
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
    }
    
    // Report functions
    void ReportHypervisorPresent() {
        std::cout << "Hypervisor detected via CPUID" << std::endl;
    }
    
    void ReportSpecificHypervisor(int vendor) {
        if (vendor == 'VMwa') {
            std::cout << "VMware hypervisor detected" << std::endl;
        } else if (vendor == 'VBox') {
            std::cout << "VirtualBox hypervisor detected" << std::endl;
        }
    }
    
    void ReportTimingAnomaly() {
        std::cout << "Timing anomaly detected - possible hypervisor" << std::endl;
    }
    
    void ReportVMwareDetected() {
        std::cout << "VMware detected in registry" << std::endl;
    }
    
    void ReportVirtualBoxDetected() {
        std::cout << "VirtualBox detected in registry" << std::endl;
    }
    
    void ReportVMArtifactFound(const char* file) {
        std::cout << "VM artifact found: " << file << std::endl;
    }
    
    void ReportVMProcessFound(const char* process) {
        std::cout << "VM process found: " << process << std::endl;
    }
    
    // Constants
    static const double EXPECTED_CPUID_TIME = 0.000001; // 1 microsecond
};
```

#### 2. Hypervisor Integrity Checks
```cpp
// Verificações de integridade do hypervisor
class HypervisorIntegrityChecker {
private:
    VMCS_VALIDATOR vmcsValidator;
    EPT_CHECKER eptChecker;
    EXIT_HANDLER_VERIFIER exitVerifier;
    
public:
    void CheckHypervisorIntegrity() {
        // Verificar integridade do hypervisor
        ValidateVMCS();
        CheckEPTIntegrity();
        VerifyExitHandlers();
    }
    
    void ValidateVMCS() {
        // Validar VMCS
        // Verificar se campos foram modificados indevidamente
        
        // Implementar validação
    }
    
    void CheckEPTIntegrity() {
        // Verificar integridade do EPT
        // Verificar se tabelas de página foram modificadas
        
        // Implementar verificação
    }
    
    void VerifyExitHandlers() {
        // Verificar handlers de exit
        // Verificar se handlers são válidos e não foram hookados
        
        // Implementar verificação
    }
};
```

#### 3. Anti-Hypervisor Techniques
```cpp
// Técnicas anti-hypervisor
class AntiHypervisorProtector {
public:
    void ProtectAgainstHypervisor() {
        // Proteger contra hypervisor
        PreventVMXOperation();
        DetectHypervisorPresence();
        BlockHypervisorCommunication();
    }
    
    void PreventVMXOperation() {
        // Prevenir operação VMX
        // Desabilitar VT-x se possível
        
        // Implementar prevenção
    }
    
    void DetectHypervisorPresence() {
        // Detectar presença de hypervisor
        // Usar técnicas de detecção
        
        // Implementar detecção
    }
    
    void BlockHypervisorCommunication() {
        // Bloquear comunicação com hypervisor
        // Hook VMCALL, etc.
        
        // Implementar bloqueio
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Virtualization detection | < 30s | 95% |
| VAC Live | Hypervisor artifacts | Imediato | 90% |
| BattlEye | VMCS integrity checks | < 1 min | 98% |
| Faceit AC | Timing analysis | < 30s | 85% |

---

## 🔄 Alternativas Seguras

### 1. Hardware-Assisted Techniques
```cpp
// ✅ Técnicas assistidas por hardware
class HardwareAssistedInjector {
private:
    CPU_FEATURES cpuFeatures;
    HARDWARE_BREAKPOINTS hwBreakpoints;
    
public:
    HardwareAssistedInjector() {
        InitializeCPUFeatures();
        InitializeHardwareBreakpoints();
    }
    
    void InitializeCPUFeatures() {
        // Inicializar recursos de CPU
        cpuFeatures.useDRx = true;
        cpuFeatures.useMSR = true;
    }
    
    void InitializeHardwareBreakpoints() {
        // Inicializar breakpoints de hardware
        hwBreakpoints.useDR0_DR3 = true;
        hwBreakpoints.useDR6_DR7 = true;
    }
    
    bool InjectViaHardware(DWORD targetPid, PVOID payload, SIZE_T payloadSize) {
        // Injetar via hardware
        if (!SetupHardwareBreakpoints(targetPid)) return false;
        
        if (!WritePayloadToTarget(targetPid, payload, payloadSize)) return false;
        
        if (!TriggerExecution(targetPid)) return false;
        
        return true;
    }
    
    bool SetupHardwareBreakpoints(DWORD targetPid) {
        // Configurar breakpoints de hardware
        // Implementar configuração
        
        return true; // Placeholder
    }
    
    bool WritePayloadToTarget(DWORD targetPid, PVOID payload, SIZE_T payloadSize) {
        // Escrever payload no alvo
        // Implementar escrita
        
        return true; // Placeholder
    }
    
    bool TriggerExecution(DWORD targetPid) {
        // Disparar execução
        // Implementar trigger
        
        return true; // Placeholder
    }
};
```

### 2. Micro-Architecture Attacks
```cpp
// ✅ Ataques de micro-arquitetura
class MicroArchitectureAttacker {
private:
    CACHE_ATTACKS cacheAttacks;
    BRANCH_PREDICTION branchPrediction;
    
public:
    MicroArchitectureAttacker() {
        InitializeCacheAttacks();
        InitializeBranchPrediction();
    }
    
    void InitializeCacheAttacks() {
        // Inicializar ataques de cache
        cacheAttacks.useFlushReload = true;
        cacheAttacks.usePrimeProbe = true;
    }
    
    void InitializeBranchPrediction() {
        // Inicializar predição de branch
        branchPrediction.useSpectre = true;
        branchPrediction.useMeltdown = true;
    }
    
    bool PerformMicroArchitectureAttack(DWORD targetPid) {
        // Executar ataque de micro-arquitetura
        if (!SetupCacheAttack(targetPid)) return false;
        
        if (!ExecuteBranchPredictionAttack(targetPid)) return false;
        
        if (!ExtractData(targetPid)) return false;
        
        return true;
    }
    
    bool SetupCacheAttack(DWORD targetPid) {
        // Configurar ataque de cache
        // Implementar configuração
        
        return true; // Placeholder
    }
    
    bool ExecuteBranchPredictionAttack(DWORD targetPid) {
        // Executar ataque de predição de branch
        // Implementar execução
        
        return true; // Placeholder
    }
    
    bool ExtractData(DWORD targetPid) {
        // Extrair dados
        // Implementar extração
        
        return true; // Placeholder
    }
};
```

### 3. Side-Channel Attacks
```cpp
// ✅ Ataques side-channel
class SideChannelAttacker {
private:
    TIMING_ATTACKS timingAttacks;
    POWER_ANALYSIS powerAnalysis;
    
public:
    SideChannelAttacker() {
        InitializeTimingAttacks();
        InitializePowerAnalysis();
    }
    
    void InitializeTimingAttacks() {
        // Inicializar ataques de timing
        timingAttacks.useCacheTiming = true;
        timingAttacks.useBranchTiming = true;
    }
    
    void InitializePowerAnalysis() {
        // Inicializar análise de energia
        powerAnalysis.usePowerSideChannel = true;
    }
    
    bool PerformSideChannelAttack(DWORD targetPid) {
        // Executar ataque side-channel
        if (!SetupTimingAttack(targetPid)) return false;
        
        if (!AnalyzePowerConsumption(targetPid)) return false;
        
        if (!ExtractInformation(targetPid)) return false;
        
        return true;
    }
    
    bool SetupTimingAttack(DWORD targetPid) {
        // Configurar ataque de timing
        // Implementar configuração
        
        return true; // Placeholder
    }
    
    bool AnalyzePowerConsumption(DWORD targetPid) {
        // Analisar consumo de energia
        // Implementar análise
        
        return true; // Placeholder
    }
    
    bool ExtractInformation(DWORD targetPid) {
        // Extrair informação
        // Implementar extração
        
        return true; // Placeholder
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ⚠️ Risco | Basic VM detection |
| 2015-2020 | ⚠️ Alto risco | Advanced timing analysis |
| 2020-2024 | 🔴 Muito alto risco | Hypervisor integrity |
| 2025-2026 | 🔴 Muito alto risco | Comprehensive VM detection |

---

## 🎯 Lições Aprendidas

1. **Hypervisors são Detectáveis**: CPUID, timing e artefatos revelam presença.

2. **Hardware-Level é Melhor**: Técnicas em nível de hardware são mais difíceis de detectar.

3. **Anti-Detection é Essencial**: Ocultar presença do hypervisor é crítico.

4. **Custom Hypervisors são Complexos**: Implementar hypervisor customizado é muito complexo.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#53]]
- [[VMware_Backdoor]]
- [[Custom_Hypervisor]]
- [[VT-x]]

---

*Hypervisor-based techniques tem risco muito alto. Considere hardware-assisted techniques para mais segurança.*