# 💾 APC Injection

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #injection #process-manipulation #stealth

## 📌 Definição

**APC Injection** (Asynchronous Procedure Call Injection) é uma técnica de code injection que explora o mecanismo de APCs do Windows para executar código malicioso no contexto de threads de outros processos. É mais stealthy que `CreateRemoteThread` pois utiliza infraestrutura nativa do sistema operacional.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[DLL_Injection]]
- [[Code_Injection]]
- [[Early_Bird_APC]]
- [[Alertable_Thread_Creation]]

## 📚 Como APCs Funcionam

### Arquitetura do Windows APC

```
User Mode:
┌────────────────────────────────┐
│  Thread em estado Alertable    │ ← QueueUserAPC()
│  (WaitForSingleObjectEx, etc.) │
└────────┬───────────────────────┘
         │
         ▼
    APC Queue (User-mode)
         │
         ▼
    Execução da função APC
    quando thread entra em
    estado alertable


Kernel Mode:
┌────────────────────────────────┐
│    Kernel APC Queue             │
│    (KAPC_STATE)                 │
└─────────────────────────────────┘
```

### Estados Alertable

Um thread entra em estado alertable ao chamar:
- `SleepEx(timeout, TRUE)`
- `WaitForSingleObjectEx(handle, timeout, TRUE)`
- `WaitForMultipleObjectsEx(..., TRUE)`
- `SignalObjectAndWait(..., TRUE)`

## 🛠️ Implementação em Rust (2026)

### 1. Classic User-Mode APC Injection

```rust
use windows::Win32::System::{Threading::*, Memory::*};
use windows::core::*;

/// Injeta código via QueueUserAPC
pub unsafe fn apc_injection(
    target_pid: u32,
    shellcode: &[u8],
) -> Result<(), String> {
    // 1. Abrir processo alvo
    let process_handle = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD,
        false,
        target_pid,
    ).map_err(|e| format!("OpenProcess failed: {}", e))?;
    
    // 2. Alocar memória no processo remoto
    let remote_buffer = VirtualAllocEx(
        process_handle,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    if remote_buffer.is_null() {
        return Err("VirtualAllocEx failed".to_string());
    }
    
    // 3. Escrever shellcode
    WriteProcessMemory(
        process_handle,
        remote_buffer,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        None,
    ).map_err(|e| format!("WriteProcessMemory failed: {}", e))?;
    
    // 4. Encontrar thread alertable no processo alvo
    let thread_id = find_alertable_thread(target_pid)?;
    
    let thread_handle = OpenThread(
        THREAD_SET_CONTEXT,
        false,
        thread_id,
    ).map_err(|e| format!("OpenThread failed: {}", e))?;
    
    // 5. Queue APC para executar shellcode
    QueueUserAPC(
        Some(std::mem::transmute(remote_buffer)),
        thread_handle,
        0,
    );
    
    // Cleanup
    CloseHandle(thread_handle);
    CloseHandle(process_handle);
    
    Ok(())
}

unsafe fn find_alertable_thread(pid: u32) -> Result<u32, String> {
    use windows::Win32::System::Diagnostics::ToolHelp::*;
    
    // Snapshot de threads
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        .map_err(|e| format!("CreateToolhelp32Snapshot failed: {}", e))?;
    
    let mut thread_entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    
    // Iterar sobre threads
    if Thread32First(snapshot, &mut thread_entry).is_ok() {
        loop {
            if thread_entry.th32OwnerProcessID == pid {
                // Retornar primeiro thread do processo
                // (Idealmente, verificar se está em estado alertable)
                CloseHandle(snapshot);
                return Ok(thread_entry.th32ThreadID);
            }
            
            if Thread32Next(snapshot, &mut thread_entry).is_err() {
                break;
            }
        }
    }
    
    CloseHandle(snapshot);
    Err("No threads found".to_string())
}
```

**Análise Rust Sentinel**:

> **CAMADA 1: SINTAXE**  
> Utilizamos `QueueUserAPC` para agendar execução de shellcode. A função só executa quando thread entra em estado alertable.
> 
> **CAMADA 2: MEMÓRIA**  
> Shellcode reside em páginas RWX no address space do processo alvo. APC queue é gerenciada pelo kernel, não alocamos memória para ela.
> 
> **CAMADA 3: SEGURANÇA & OWNERSHIP**  
> Rust força que gerenciemos handles via RAII padrão do Windows. `CloseHandle` evita vazamento de recursos.

### 2. Early Bird APC Injection (Mais Stealth)

```rust
/// Injeta APC em processo suspenso antes da primeira execução
pub unsafe fn early_bird_apc_injection(
    target_path: &str,
    shellcode: &[u8],
) -> Result<(), String> {
    use windows::Win32::System::Threading::*;
    
    // 1. Criar processo em estado suspenso
    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    
    let mut process_info = PROCESS_INFORMATION::default();
    
    let target_path_wide: Vec<u16> = target_path.encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    
    CreateProcessW(
        None,
        PWSTR(target_path_wide.as_ptr() as *mut u16),
        None,
        None,
        false,
        CREATE_SUSPENDED, // IMPORTANTE: Criar suspenso
        None,
        None,
        &startup_info,
        &mut process_info,
    ).map_err(|e| format!("CreateProcessW failed: {}", e))?;
    
    // 2. Alocar memória no processo suspenso
    let remote_buffer = VirtualAllocEx(
        process_info.hProcess,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );
    
    if remote_buffer.is_null() {
        TerminateProcess(process_info.hProcess, 1);
        return Err("VirtualAllocEx failed".to_string());
    }
    
    // 3. Escrever shellcode
    WriteProcessMemory(
        process_info.hProcess,
        remote_buffer,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        None,
    )?;
    
    // 4. Queue APC no main thread (antes de iniciar)
    QueueUserAPC(
        Some(std::mem::transmute(remote_buffer)),
        process_info.hThread,
        0,
    );
    
    // 5. Resumir thread - APC executa ANTES do entry point!
    ResumeThread(process_info.hThread);
    
    // Cleanup
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);
    
    Ok(())
}
```

### 3. Kernel APC Injection (Ring 0)

```rust
/// Injeta APC de kernel mode (requer driver)
/// 
/// ATENÇÃO: Código ilustrativo apenas. Execução real requer driver assinado.
pub unsafe fn kernel_apc_injection(
    target_pid: u32,
    shellcode_kernel_addr: *mut u8,
) -> Result<(), String> {
    // Pseudo-código (requer estar em kernel mode)
    
    // 1. Obter EPROCESS do target via PID
    // let eprocess = PsLookupProcessByProcessId(target_pid);
    
    // 2. Obter primeiro thread (ETHREAD)
    // let ethread = PsGetNextProcessThread(eprocess, None);
    
    // 3. Alocar KAPC structure
    // let kapc = ExAllocatePoolWithTag(NonPagedPool, sizeof(KAPC), 'cpaK');
    
    // 4. Inicializar KAPC
    /*
    KeInitializeApc(
        kapc,
        ethread,
        OriginalApcEnvironment,
        KernelRoutine,
        RundownRoutine,
        NormalRoutine,       // Função a executar
        UserMode,            // Executar em user mode
        shellcode_kernel_addr
    );
    */
    
    // 5. Inserir APC na queue
    // KeInsertQueueApc(kapc, None, None, 0);
    
    Ok(())
}
```

## 🎯 Aplicação em CS2 (2026)

### Caso: Injetar Aimbot via APC

```rust
/// Injeta aimbot DLL via Early Bird APC
pub fn inject_aimbot_apc(cs2_path: &str) -> Result<(), String> {
    // Shellcode: LoadLibraryA("C:\\cheats\\aimbot.dll")
    let shellcode = generate_loadlibrary_shellcode("C:\\cheats\\aimbot.dll");
    
    unsafe {
        early_bird_apc_injection(cs2_path, &shellcode)
    }
}

fn generate_loadlibrary_shellcode(dll_path: &str) -> Vec<u8> {
    // x86-64 shellcode que chama LoadLibraryA
    let mut shellcode = Vec::new();
    
    // sub rsp, 0x28   ; Shadow space
    shellcode.extend_from_slice(&[0x48, 0x83, 0xEC, 0x28]);
    
    // mov rcx, <dll_path_addr>  ; Arg1 = path
    // ... implementação completa de shellcode
    
    shellcode
}
```

## ⚠️ Detecção e Contramedidas (2026)

### Como Anti-Cheats Detectam APC Injection

```
1. Monitoramento de QueueUserAPC
   ├─ Hook de QueueUserAPC via IAT/EAT
   ├─ Detecção de APCs de processos externos
   └─ Solução: Direct syscall (NtQueueApcThread)

2. Análise de APC queues
   ├─ Kernel driver verifica KAPC_STATE
   ├─ Identifica APCs suspeitos (endereços fora de módulos)
   └─ Solução: Executar APC que então carrega DLL legítima

3. Processo criado suspenso
   ├─ CREATE_SUSPENDED é red flag
   ├─ Especialmente se combinado com WriteProcessMemory
   └─ Solução: Injetar em processo já existente

4. Memory scanning
   ├─ Shellcode em memória RWX sem módulo associado
   └─ Solução: Encrypt shellcode, decrypt em runtime

5. Behavioral analysis
   ├─ Processo "inocente" executando código suspeito
   └─ Solução: Mimicry - shellcode imita comportamento normal
```

### Vantagens sobre CreateRemoteThread

| Aspecto | CreateRemoteThread | APC Injection |
|---------|-------------------|---------------|
| **Stealth** | 🟡 Médio | 🟢 Alto |
| **Detecção** | 🔴 Fácil | 🟡 Médio |
| **Dependência de estado** | ❌ Não | ✅ Sim (alertable) |
| **Early execution** | ❌ Não | ✅ Sim (Early Bird) |

## 📊 Variações de APC Injection

### Special User APC (sAPC)

```rust
// Windows 10+: Special User APC não respeita alertable state
// Executado imediatamente quando thread volta de kernel mode
// Requer NT API interna (não documentada)
```

### APC Queue Bombing

```rust
/// Enfileirar múltiplas APCs para garantir execução
pub unsafe fn apc_bombing(target_pid: u32, shellcode: &[u8]) -> Result<(), String> {
    let threads = enumerate_all_threads(target_pid)?;
    
    for thread_id in threads {
        let thread_handle = OpenThread(THREAD_SET_CONTEXT, false, thread_id)?;
        
        // Alocar shellcode uma vez
        let remote_buffer = allocate_and_write_shellcode(target_pid, shellcode)?;
        
        // Queue APC em TODOS os threads
        QueueUserAPC(
            Some(std::mem::transmute(remote_buffer)),
            thread_handle,
            0,
        );
        
        CloseHandle(thread_handle);
    }
    
    Ok(())
}
```

## 📖 Ver Também
- [[DLL_Injection]]
- [[Early_Bird_APC]]
- [[Code_Injection]]
- [[Alertable_Thread_Creation]]

---
<p align="center">REDFLAG © 2026</p>
