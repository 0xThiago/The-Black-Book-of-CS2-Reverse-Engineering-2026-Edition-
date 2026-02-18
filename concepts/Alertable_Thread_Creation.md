# ⏰ Alertable Thread Creation

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #windows-internals #threading #apc

## 📌 Definição

**Alertable Thread Creation** refere-se ao mecanismo do Windows onde threads entram em um estado especial chamado **"alertable wait"**, permitindo que **APCs** (Asynchronous Procedure Calls) enfileiradas sejam processadas. Entender este conceito é fundamental para explorar [[APC_Injection]] e [[Early_Bird_APC]], pois uma APC de user-mode só executa quando o thread alvo está em estado alertable.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[APC_Injection]]
- [[Early_Bird_APC]]
- [[Code_Injection]]
- [[DLL_Injection]]
- [[Técnica 014 - DLL Injection via APC]]
- [[Técnica 029 - APC Injection]]

## 📚 Arquitetura Windows — APC Dispatch

### Como o Kernel Processa APCs
```
      Thread em User Mode
      ┌──────────────────────┐
      │ Executando código     │
      │ normalmente...        │
      └──────────┬───────────┘
                 │
                 ▼
      Chama WaitForSingleObjectEx(h, t, TRUE)
                 │             ▲ bAlertable = TRUE
                 ▼
      ┌──────────────────────┐
      │ KERNEL MODE           │
      │ KiUserApcDispatcher   │
      │                       │
      │ Verifica APC Queue:   │
      │ ├─ Kernel APCs        │ ← Executam SEMPRE
      │ └─ User APCs          │ ← Executam SÓ se alertable
      │                       │
      │ Se APC presente:      │
      │ → Retorna ao user     │
      │   mode com callback   │
      └──────────────────────┘
                 │
                 ▼
      APC callback executa em user mode
      (no contexto do thread alvo!)
```

### Funções que Entram em Estado Alertable

```rust
/// Funções da WinAPI que colocam thread em estado alertable
///
/// # Camada 1: SINTAXE
/// Cada função aceita um parâmetro `bAlertable` (BOOL).
/// Quando TRUE, o thread processa APCs de user-mode pendentes.
///
/// # Camada 2: MEMÓRIA
/// O estado alertable é um flag no KTHREAD (kernel structure).
/// Campo: KTHREAD.Alertable (offset ~0x74 no Windows 11).
/// Ocupa 1 byte na estrutura kernel do thread.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Em Rust, wrappamos essas chamadas com tipos seguros.
/// O HANDLE é tomado por empréstimo (&HANDLE), não movido.
pub mod alertable_functions {
    use windows::Win32::System::Threading::*;
    use windows::Win32::Foundation::*;

    /// SleepEx — dormir em estado alertable
    pub unsafe fn alertable_sleep(duration_ms: u32) -> u32 {
        SleepEx(duration_ms, true) // bAlertable = TRUE
    }

    /// WaitForSingleObjectEx — esperar objeto em estado alertable
    pub unsafe fn alertable_wait(handle: HANDLE, timeout_ms: u32) -> u32 {
        WaitForSingleObjectEx(handle, timeout_ms, true).0
    }

    /// WaitForMultipleObjectsEx — esperar múltiplos objetos
    pub unsafe fn alertable_wait_multiple(
        handles: &[HANDLE],
        wait_all: bool,
        timeout_ms: u32,
    ) -> u32 {
        WaitForMultipleObjectsEx(
            handles,
            wait_all,
            timeout_ms,
            true, // bAlertable = TRUE
        ).0
    }

    /// MsgWaitForMultipleObjectsEx — para threads com message loop
    pub unsafe fn alertable_msg_wait(
        handles: &[HANDLE],
        timeout_ms: u32,
    ) -> u32 {
        windows::Win32::UI::WindowsAndMessaging::MsgWaitForMultipleObjectsEx(
            Some(handles),
            timeout_ms,
            windows::Win32::UI::WindowsAndMessaging::QS_ALLINPUT,
            MWMO_ALERTABLE,
        ).0
    }
}
```

## 🛠️ Encontrar Threads Alertable (2026)

### Detector de Threads Alertable

```rust
use windows::Win32::System::Diagnostics::ToolHelp::*;
use windows::Win32::System::Threading::*;
use windows::Win32::Foundation::*;

/// Encontra threads de um processo que estão (ou provavelmente
/// estarão) em estado alertable
///
/// # Camada 1: SINTAXE
/// Enumera todos os threads do processo via ToolHelp API,
/// tenta identificar quais estão em wait state alertable.
///
/// # Camada 2: MEMÓRIA
/// THREADENTRY32 = 28 bytes na stack.
/// Snapshot handle é um kernel object (descriptor na Object Table).
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// O snapshot HANDLE é fechado no final — em produção,
/// usar OwnedHandle para RAII automático.
pub unsafe fn find_alertable_threads(pid: u32) -> Vec<u32> {
    let mut alertable_threads = Vec::new();

    let snapshot = match CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) {
        Ok(s) => s,
        Err(_) => return alertable_threads,
    };

    let mut entry = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    if Thread32First(snapshot, &mut entry).is_ok() {
        loop {
            if entry.th32OwnerProcessID == pid {
                // Verificar se thread está em wait state
                let thread_handle = OpenThread(
                    THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT,
                    false,
                    entry.th32ThreadID,
                );

                if let Ok(handle) = thread_handle {
                    // Heurística: threads em wait geralmente são alertable
                    // (especialmente message loop threads do jogo)
                    if is_thread_in_wait_state(handle) {
                        alertable_threads.push(entry.th32ThreadID);
                    }
                    let _ = CloseHandle(handle);
                }
            }

            if Thread32Next(snapshot, &mut entry).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(snapshot);
    alertable_threads
}

/// Verifica se thread está em estado de espera (wait)
///
/// Threads que estão executando código ativamente NÃO processam APCs.
/// Apenas threads em wait (alertable) vão executar a APC.
unsafe fn is_thread_in_wait_state(thread_handle: HANDLE) -> bool {
    // Usar NtQueryInformationThread para verificar ThreadState
    // ThreadState == 5 (Waiting) e ThreadWaitReason == alertable
    // Implementação simplificada: verificar se SuspendThread retorna
    // indicating the thread was already suspended/waiting

    let suspend_count = SuspendThread(thread_handle);
    if suspend_count != u32::MAX {
        // Thread estava rodando ou esperando — resumir
        ResumeThread(thread_handle);
        // Se suspend_count == 0, thread estava ativo
        // Para APC injection, qualquer thread serve se
        // o processo usa message loops (GUI threads)
        return true;
    }
    false
}
```

## 🎯 Criando Threads Alertable (Offensivo)

### Forçar Thread Alertable

```rust
/// Cria um thread alertable no processo alvo
///
/// Útil quando nenhum thread do processo está em estado alertable.
/// O thread criado executa SleepEx em loop, processando APCs.
///
/// ⚠️ RISCO DE ESTABILIDADE/DETECÇÃO:
/// Criar threads remotamente é detectado por ObRegisterCallbacks.
/// Considerar usar Early Bird APC (processo suspenso) como alternativa.
pub unsafe fn create_alertable_thread(process_handle: HANDLE) -> Result<HANDLE, String> {
    // Shellcode x64 que faz SleepEx(INFINITE, TRUE) em loop
    let shellcode: [u8; 20] = [
        0x48, 0x83, 0xEC, 0x28,     // sub rsp, 0x28
        0x48, 0xC7, 0xC1, 0xFF,     // mov rcx, -1 (INFINITE)
        0xFF, 0xFF, 0xFF,
        0x48, 0xC7, 0xC2, 0x01,     // mov rdx, 1 (bAlertable = TRUE)
        0x00, 0x00, 0x00,
        0xEB, 0xEC,                   // jmp back (loop)
        // Nota: falta call SleepEx — shellcode real precisa
        // resolver o endereço via PEB ou hash
    ];

    let remote_addr = VirtualAllocEx(
        process_handle,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_addr.is_null() {
        return Err("VirtualAllocEx falhou".to_string());
    }

    WriteProcessMemory(
        process_handle,
        remote_addr,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        None,
    ).map_err(|e| format!("Escrita falhou: {}", e))?;

    let mut thread_id = 0u32;
    let thread_handle = CreateRemoteThread(
        process_handle,
        None,
        0,
        Some(std::mem::transmute(remote_addr)),
        None,
        THREAD_CREATION_FLAGS(0),
        Some(&mut thread_id),
    ).map_err(|e| format!("CreateRemoteThread falhou: {}", e))?;

    Ok(thread_handle)
}
```

## 📊 CS2 — Threads Alertable Típicos

No CS2 (2026), os seguintes threads costumam estar em estado alertable:

| Thread | Função | Alertable? | Motivo |
|--------|--------|-----------|--------|
| **Main thread** | Game loop | 🟡 Às vezes | WaitForSingleObjectEx no vsync |
| **Render thread** | Vulkan present | 🟡 Às vezes | vkQueueWaitIdle |
| **Audio thread** | WASAPI stream | ✅ Frequente | WaitForSingleObjectEx |
| **Network thread** | Socket I/O | ✅ Frequente | WSAWaitForMultipleEvents |
| **Input thread** | Raw Input | 🔴 Raramente | Busy polling |

> [!TIP]
> **Alvo ideal para APC injection no CS2**: O **audio thread** é o melhor candidato,
> pois frequentemente entra em estado alertable esperando buffers de áudio.

## 📖 Ver Também
- [[APC_Injection]]
- [[Early_Bird_APC]]
- [[Code_Injection]]
- [[DLL_Injection]]

---
<p align="center">REDFLAG © 2026</p>
