# 🔌 Syscall Proxying

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #evasion #kernel #syscall #stealth

## 📌 Definição

**Syscall Proxying** (também chamado de **Direct Syscall**) é uma técnica de evasão que chama funções do kernel diretamente através da instrução `syscall`, bypando completamente hooks de user-mode instalados por Anti-Cheats na `ntdll.dll`. Em 2026, é considerada **essencial** para qualquer cheat que interaja com o kernel.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[API_Hashing]]
- [[Compile_Time_Obfuscation]]
- [[Técnica 039 - Anti-Debugging Techniques]]

## 📚 Por Que Syscall Proxying é Necessário

### Problema: ntdll.dll Hookada
```
Fluxo normal (hookado pelo AC):
─────────────────────────────────────────────────
App → NtReadVirtualMemory (ntdll.dll)
       │
       ├─ AC Hook: JMP para AC_Scanner
       │            └─ Loga operação
       │            └─ Verifica target process
       │            └─ JMP de volta para ntdll
       │
       └─ syscall (kernel mode)
─────────────────────────────────────────────────

Fluxo com Direct Syscall:
─────────────────────────────────────────────────
App → [mov r10, rcx; mov eax, SSN; syscall]
       │
       └─ Direto para kernel mode (hook ignorado!)
─────────────────────────────────────────────────
```

## 🛠️ Implementação em Rust (2026)

### 1. Resolver Syscall Number Dinamicamente

```rust
use windows::Win32::System::LibraryLoader::*;
use windows::core::PCSTR;

/// Resolve o Syscall Service Number (SSN) de uma função NT
///
/// # Camada 1: SINTAXE
/// Lê os primeiros bytes da função na ntdll.dll para extrair
/// o SSN da instrução `mov eax, <SSN>`.
///
/// # Camada 2: MEMÓRIA
/// Acessa diretamente os bytes mapeados da ntdll.dll no
/// address space do processo. A ntdll é sempre mapeada.
/// Leitura via ponteiro raw — zero allocation.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// O slice `std::slice::from_raw_parts` empresta bytes
/// da imagem da DLL. Não há ownership — apenas leitura.
///
/// ⚠️ RISCO DE ESTABILIDADE/DETECÇÃO:
/// Se a ntdll estiver hookada, os primeiros bytes estarão
/// alterados (JMP). O resolve precisa saber pular hooks.
pub unsafe fn resolve_ssn(function_name: &str) -> Option<u32> {
    let ntdll = GetModuleHandleA(PCSTR(b"ntdll.dll\0".as_ptr())).ok()?;
    let func_name = std::ffi::CString::new(function_name).ok()?;
    let addr = GetProcAddress(ntdll, PCSTR(func_name.as_ptr() as *const u8))?;

    let bytes = std::slice::from_raw_parts(addr as *const u8, 32);

    // Padrão normal (não hookado):
    // 4C 8B D1       mov r10, rcx
    // B8 XX XX 00 00 mov eax, SSN
    if bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1
        && bytes[3] == 0xB8
    {
        return Some(u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]));
    }

    // Se hookado (JMP no início), procurar padrão mais adiante
    for i in 0..24 {
        if bytes[i] == 0xB8
            && bytes.get(i + 5) == Some(&0x0F)
            && bytes.get(i + 6) == Some(&0x05)
        {
            return Some(u32::from_le_bytes([
                bytes[i + 1], bytes[i + 2], bytes[i + 3], bytes[i + 4],
            ]));
        }
    }

    // Fallback: ler de cópia limpa da ntdll do disco
    resolve_ssn_from_disk(function_name)
}

/// Resolve SSN lendo ntdll.dll diretamente do disco
/// (bypassa hooks em memória)
unsafe fn resolve_ssn_from_disk(function_name: &str) -> Option<u32> {
    let ntdll_bytes = std::fs::read(r"C:\Windows\System32\ntdll.dll").ok()?;

    // Parse PE headers
    let dos = &ntdll_bytes[0..64];
    let e_lfanew = u32::from_le_bytes([dos[60], dos[61], dos[62], dos[63]]) as usize;

    // Encontrar export table e resolver manualmente
    // (implementação completa requer PE parser)
    None // Simplificado
}
```

### 2. Direct Syscall via Inline Assembly

```rust
use std::arch::asm;

/// Chama NtReadVirtualMemory via syscall direto
///
/// # Camada 1: SINTAXE
/// Inline assembly x86-64 que configura registradores
/// conforme a Windows x64 calling convention e executa
/// a instrução syscall sem passar pela ntdll.dll.
///
/// # Camada 2: MEMÓRIA
/// Nenhuma alocação. Registradores usados:
/// - rcx → r10 (1o argumento, ProcessHandle)
/// - rdx (2o argumento, BaseAddress)
/// - r8 (3o argumento, Buffer)
/// - r9 (4o argumento, Size)
/// - stack (5o argumento, BytesRead)
/// - eax (SSN do syscall)
/// Após `syscall`, o kernel opera em ring 0.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Bloco unsafe obrigatório — estamos bypassando todas
/// as garantias do Rust. O caller deve garantir que os
/// ponteiros são válidos e o buffer tem tamanho suficiente.
pub unsafe fn nt_read_virtual_memory(
    process_handle: isize,
    base_address: *const u8,
    buffer: *mut u8,
    size: usize,
    bytes_read: *mut usize,
    ssn: u32,
) -> i32 {
    let status: i32;

    asm!(
        "mov r10, rcx",    // Windows syscall convention
        "syscall",
        in("eax") ssn,
        in("rcx") process_handle,
        in("rdx") base_address,
        in("r8") buffer,
        in("r9") size,
        // 5o argumento via stack (já no lugar correto pela ABI)
        lateout("rax") status,
        clobber_abi("win64"),
    );

    status
}
```

### 3. Syscall Proxy Completo (Encapsulado)

```rust
/// Wrapper seguro para syscalls diretos
///
/// Ponte C++: Em C++ você usaria macros ou funções naked.
/// Em Rust, usamos generics + inline asm para type safety.
pub struct SyscallProxy {
    ssn_cache: std::collections::HashMap<String, u32>,
}

impl SyscallProxy {
    pub unsafe fn new() -> Self {
        let mut proxy = Self {
            ssn_cache: std::collections::HashMap::new(),
        };

        // Pré-resolver SSNs comuns
        let functions = [
            "NtReadVirtualMemory",
            "NtWriteVirtualMemory",
            "NtAllocateVirtualMemory",
            "NtProtectVirtualMemory",
            "NtQueryInformationProcess",
            "NtOpenProcess",
            "NtClose",
        ];

        for func in &functions {
            if let Some(ssn) = resolve_ssn(func) {
                proxy.ssn_cache.insert(func.to_string(), ssn);
            }
        }

        proxy
    }

    pub fn get_ssn(&self, name: &str) -> Option<u32> {
        self.ssn_cache.get(name).copied()
    }
}
```

## 📊 Efetividade (2026)

| AC | Hook Type | Syscall Proxy Bypass? | Overhead |
|----|-----------|----------------------|----------|
| **VAC** | IAT hook | ✅ Sim | ~0% |
| **VAC Live** | ntdll inline | ✅ Sim | ~0% |
| **BattlEye** | Kernel callback | ❌ Não (kernel level) | N/A |
| **Faceit AC** | ETW + ntdll | 🟡 Parcial | ~0% |

> [!WARNING]
> Syscall proxying **não** bypassa detecção em kernel mode
> (ObRegisterCallbacks, kernel ETW). É eficaz apenas contra
> hooks de user-mode na ntdll.dll.

## 📖 Ver Também
- [[API_Hashing]]
- [[Compile_Time_Obfuscation]]
- [[Técnica 039 - Anti-Debugging Techniques]]

---
<p align="center">REDFLAG © 2026</p>
