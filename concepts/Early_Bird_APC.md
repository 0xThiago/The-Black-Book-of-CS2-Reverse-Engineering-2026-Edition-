# 🐣 Early Bird APC Injection

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #injection #apc #stealth #early-bird

## 📌 Definição

**Early Bird APC Injection** é uma variante da [[APC_Injection]] que explora o fato de que, quando um processo é criado em estado **suspenso** (`CREATE_SUSPENDED`), o main thread ainda não executou nenhum código do user-mode. Ao enfileirar uma APC nesse thread antes de resumi-lo, o shellcode executa **antes do entry point** do processo — antes de qualquer inicialização de anti-cheat, anti-debug, ou runtime CRT.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[APC_Injection]]
- [[Code_Injection]]
- [[DLL_Injection]]
- [[Alertable_Thread_Creation]]
- [[Técnica 030 - Early Bird APC Injection]]

## 📚 Por Que é Mais Stealth que APC Normal

### Fluxo de Execução
```
APC Normal:
─────────────────────────────────────────────────
Processo já correndo → Thread já inicializado
→ Anti-cheat já carregado e monitorando
→ QueueUserAPC → Espera estado alertable
→ ⚠️ APC executa DEPOIS das proteções
─────────────────────────────────────────────────

Early Bird APC:
─────────────────────────────────────────────────
CreateProcess(SUSPENDED) → Thread NÃO executou nada
→ QueueUserAPC → ResumeThread
→ ✅ APC executa ANTES de qualquer código!
→ Shellcode roda antes de ntdll!LdrInitializeThunk
→ Anti-cheat nunca viu o código ser injetado
─────────────────────────────────────────────────
```

### Vantagem Técnica Chave
```
Timeline do processo:
0ms  ─ CreateProcess(SUSPENDED)
1ms  ─ VirtualAllocEx + WriteProcessMemory
2ms  ─ QueueUserAPC (shellcode como callback)
3ms  ─ ResumeThread
4ms  ─ ★ SHELLCODE EXECUTA AQUI ★
5ms  ─ ntdll!LdrInitializeThunk (loader do Windows)
10ms ─ CRT initialization
15ms ─ main() do processo alvo
20ms ─ Anti-cheat se inicializa (tarde demais!)
```

## 🛠️ Implementação em Rust (2026)

### Implementação Completa

```rust
use windows::Win32::System::{Threading::*, Memory::*};
use windows::Win32::Foundation::*;
use windows::core::*;

/// Injeta shellcode via Early Bird APC
///
/// # Camada 1: SINTAXE
/// Cria processo suspenso, aloca shellcode na memória remota,
/// enfileira APC no main thread, e resume a execução.
///
/// # Camada 2: MEMÓRIA
/// - STARTUPINFOW: ~100 bytes na stack
/// - PROCESS_INFORMATION: 24 bytes (4 campos)
/// - Shellcode: alocado no heap do processo REMOTO
/// - APC queue: gerenciada pelo kernel (KAPC_STATE no ETHREAD)
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Todos os HANDLEs (processo, thread) devem ser fechados via
/// CloseHandle. Implementamos Drop manual para garantir cleanup.
///
/// ⚠️ RISCO DE ESTABILIDADE/DETECÇÃO:
/// CREATE_SUSPENDED + WriteProcessMemory é uma combinação
/// monitorada por ACs avançados. Mitigação: usar processo
/// legítimo como host (ex: svchost.exe, RuntimeBroker.exe).
pub unsafe fn early_bird_inject(
    target_exe: &str,
    shellcode: &[u8],
) -> Result<u32, String> {
    // 1. Criar processo em estado suspenso
    let startup_info = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut proc_info = PROCESS_INFORMATION::default();

    let target_wide: Vec<u16> = target_exe.encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    CreateProcessW(
        None,
        PWSTR(target_wide.as_ptr() as *mut u16),
        None,
        None,
        false,
        CREATE_SUSPENDED,
        None,
        None,
        &startup_info,
        &mut proc_info,
    ).map_err(|e| format!("CreateProcessW falhou: {}", e))?;

    // Guard: se algo falhar depois, terminar processo
    let _process_guard = scopeguard::guard((), |_| {
        let _ = TerminateProcess(proc_info.hProcess, 1);
        let _ = CloseHandle(proc_info.hProcess);
        let _ = CloseHandle(proc_info.hThread);
    });

    // 2. Alocar memória no processo suspenso
    let remote_buffer = VirtualAllocEx(
        proc_info.hProcess,
        None,
        shellcode.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    );

    if remote_buffer.is_null() {
        return Err("VirtualAllocEx falhou".to_string());
    }

    // 3. Escrever shellcode
    WriteProcessMemory(
        proc_info.hProcess,
        remote_buffer,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        None,
    ).map_err(|e| format!("WriteProcessMemory falhou: {}", e))?;

    // 4. Enfileirar APC no main thread (ainda suspenso)
    QueueUserAPC(
        Some(std::mem::transmute(remote_buffer)),
        proc_info.hThread,
        0,
    );

    // 5. Resumir thread — APC executa ANTES do entry point!
    ResumeThread(proc_info.hThread);

    // Desarmando o guard (sucesso)
    std::mem::forget(_process_guard);

    // Cleanup de handles
    CloseHandle(proc_info.hThread).ok();
    CloseHandle(proc_info.hProcess).ok();

    Ok(proc_info.dwProcessId)
}
```

## 🎯 Detecção e Evasão (2026)

### Como ACs Detectam
```
Padrões monitorados:
├─ 1. CreateProcess com CREATE_SUSPENDED
│   └─ Solução: Usar NtCreateUserProcess diretamente
│
├─ 2. WriteProcessMemory em processo recém-criado
│   └─ Solução: Usar kernel driver para escrita
│
├─ 3. QueueUserAPC de processo externo
│   └─ Solução: Direct syscall (NtQueueApcThread)
│
└─ 4. Páginas RWX sem módulo associado
    └─ Solução: RW → escrever → RX (duas chamadas)
```

### Tabela de Detecção

| Anti-Cheat | Detecção Early Bird | Notas |
|------------|-------------------|-------|
| **VAC Live** | 🟡 Baixo-Médio | Monitora CREATE_SUSPENDED |
| **BattlEye** | 🟠 Médio | Hook em NtQueueApcThread |
| **Faceit AC** | 🟠 Médio-Alto | Análise de callstack |
| **EAC** | 🟡 Baixo | Foco em módulos carregados |

## 📖 Ver Também
- [[APC_Injection]]
- [[Code_Injection]]
- [[Alertable_Thread_Creation]]
- [[DLL_Injection]]
- [[Técnica 030 - Early Bird APC Injection]]

---
<p align="center">REDFLAG © 2026</p>
