# 💉 Code Injection

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #injection #core #process-manipulation

## 📌 Definição

**Code Injection** é o conceito guarda-chuva que abrange todas as técnicas para executar código arbitrário dentro do espaço de endereçamento de outro processo. É a base fundamental de cheats internos (internal cheats), permitindo acesso direto à memória do jogo sem passar por APIs monitoradas.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[DLL_Injection]]
- [[APC_Injection]]
- [[Early_Bird_APC]]
- [[Alertable_Thread_Creation]]
- [[Técnica 007 - CreateRemoteThread]]
- [[Técnica 014 - DLL Injection via APC]]
- [[Técnica 015 - Manual DLL Mapping]]
- [[Técnica 038 - Process Hollowing]]

## 📚 Taxonomia de Code Injection

### Mapa de Técnicas
```
Code Injection
├─ DLL Injection
│   ├─ LoadLibrary (❌ Defasado)
│   ├─ Manual Mapping (🟡 Parcial)
│   ├─ Reflective DLL (🟡 Parcial)
│   └─ APC-based DLL Load (🟡 Parcial)
│
├─ Shellcode Injection
│   ├─ CreateRemoteThread (❌ Defasado)
│   ├─ APC Injection (🟡 Stealth médio)
│   ├─ Early Bird APC (🟢 Alto stealth)
│   ├─ Thread Hijacking (🟡 Parcial)
│   └─ Callback Injection (🟡 Parcial)
│
├─ Process Manipulation
│   ├─ Process Hollowing (🟡 Parcial)
│   ├─ Process Doppelgänging (🟡 Parcial)
│   └─ Transaction Hollowing (🟡 Parcial)
│
└─ Kernel-Level
    ├─ APC Kernel Mode (🟢 Alto stealth)
    ├─ Notify Routines (🟢 Alto stealth)
    └─ PsSetCreateProcessNotifyRoutine (🟢 Elite)
```

## 🛠️ Conceitos Fundamentais em Rust

### 1. O Padrão de Injection em Rust

```rust
use windows::Win32::System::{Threading::*, Memory::*};
use windows::Win32::Foundation::*;

/// Trait genérica para todas as técnicas de injection
///
/// # Camada 1: SINTAXE
/// Trait que define a interface comum para qualquer método
/// de code injection. Cada implementação é uma técnica diferente.
///
/// # Camada 2: MEMÓRIA
/// O trait object (dyn CodeInjector) ocupa 2 ponteiros na stack:
/// - Ponteiro para os dados (vtable data ptr)
/// - Ponteiro para a vtable (vtable ptr)
/// Total: 16 bytes em x64.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// O trait exige `&self` (empréstimo imutável), pois a injeção
/// não deve alterar o estado do injector. O payload é passado
/// como `&[u8]` (slice emprestado) — zero-copy.
pub trait CodeInjector {
    /// Nome da técnica para logging
    fn name(&self) -> &str;

    /// Injeta payload no processo alvo
    ///
    /// # Safety
    /// - `target_pid` deve ser um PID válido
    /// - `payload` deve ser shellcode x64 válido
    unsafe fn inject(&self, target_pid: u32, payload: &[u8]) -> Result<(), String>;

    /// Nível de risco de detecção (0-100)
    fn detection_risk(&self) -> u8;
}
```

### 2. Alocação Remota de Memória (Comum a todas as técnicas)

```rust
/// Aloca e escreve payload na memória de processo remoto
///
/// # Camada 1: SINTAXE
/// Wrapper seguro sobre VirtualAllocEx + WriteProcessMemory.
/// Retorna o endereço remoto onde o payload foi escrito.
///
/// # Camada 2: MEMÓRIA
/// O payload é copiado para uma nova página no address space
/// do processo alvo. A página é marcada como RWX (Read/Write/Execute).
///
/// ⚠️ RISCO DE ESTABILIDADE/DETECÇÃO:
/// Páginas RWX sem módulo associado são red flags para AC.
/// Mitigação: alterar proteção após escrita (RW -> RX).
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// O HANDLE retornado por OpenProcess precisa de CloseHandle.
/// Em Rust, encapsulamos em OwnedHandle para RAII automático.
pub unsafe fn allocate_remote_payload(
    process_handle: HANDLE,
    payload: &[u8],
) -> Result<*mut std::ffi::c_void, String> {
    // 1. Alocar memória remota
    let remote_addr = VirtualAllocEx(
        process_handle,
        None,
        payload.len(),
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE, // Alocar como RW primeiro
    );

    if remote_addr.is_null() {
        return Err("VirtualAllocEx falhou".to_string());
    }

    // 2. Escrever payload
    WriteProcessMemory(
        process_handle,
        remote_addr,
        payload.as_ptr() as *const _,
        payload.len(),
        None,
    ).map_err(|e| format!("WriteProcessMemory falhou: {}", e))?;

    // 3. Alterar proteção para RX (mais stealth que RWX)
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtectEx(
        process_handle,
        remote_addr,
        payload.len(),
        PAGE_EXECUTE_READ,
        &mut old_protect,
    ).map_err(|e| format!("VirtualProtectEx falhou: {}", e))?;

    Ok(remote_addr)
}
```

## 🎯 State of Art (2026)

### Detecção por Anti-Cheat

| Técnica | VAC | Faceit AC | Overhead |
|---------|-----|-----------|----------|
| **CreateRemoteThread** | ⛔ Imediata | ⛔ Imediata | Mínimo |
| **LoadLibrary DLL** | ⛔ Imediata | ⛔ Imediata | Mínimo |
| **APC Injection** | 🟡 Médio | 🟠 Médio | Baixo |
| **Early Bird APC** | 🟢 Baixo | 🟡 Médio | Baixo |
| **Manual Mapping** | 🟠 Médio | 🟠 Alto | Médio |
| **Process Hollowing** | 🟠 Médio | 🔴 Alto | Alto |
| **Kernel Notify** | 🟢 Mínimo | 🟡 Baixo | Baixo |

> [!IMPORTANT]
> **Tendência 2026**: Code injection internamente no jogo está sendo substituída por
> abordagens **externas** (DMA, kernel page table, hypervisor). Injeção direta
> é cada vez mais arriscada contra ACs modernos.

## ⚠️ Contra-Medidas Comuns (2026)

1. **ObRegisterCallbacks** — Intercepta criação de handles, monitora `PROCESS_VM_WRITE`
2. **PsSetCreateProcessNotifyRoutine** — Detecta processos criados em estado suspenso
3. **Memory Scanning** — Verifica páginas executáveis sem módulo associado
4. **ETW (Event Tracing)** — Loga operações de injeção via telemetry
5. **Integrity Checks** — Verifica se módulos carregados batem com disco

## 📖 Ver Também
- [[DLL_Injection]]
- [[APC_Injection]]
- [[Early_Bird_APC]]
- [[Técnica 007 - CreateRemoteThread]]
- [[Técnica 015 - Manual DLL Mapping]]
- [[Técnica 038 - Process Hollowing]]

---
<p align="center">REDFLAG © 2026</p>
