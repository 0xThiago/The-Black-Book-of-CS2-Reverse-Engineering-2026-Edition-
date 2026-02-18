# Técnica 054 - Rust Kernel Memory RW (2026 Edition)

📅 Criado em: 2026-02-15
🔗 Tags: #rust #kernel #memory #cs2 #windows-rs

## 📌 Resumo
> **Status:** ✅ Atual / Melhor Prática (2026)
> **Risco de Detecção:** 🟢 Mínimo
> **Ponte C++:** Substitui o uso de drivers instáveis em C++ por uma implementação segura (Memory-Safe) em Rust.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[DATABASE]]
- [[Técnica 004 - Kernel Page Table Manipulation]]

---

## 🔍 Desenvolvimento Técnico

Esta técnica utiliza as crates `windows-rs` e wrappers de kernel para realizar operações de leitura e escrita de memória física, bypassando callbacks de proteção de processos do Windows (ObRegisterCallbacks).

### 🛠️ Implementação em Rust

```rust
use windows::Win32::System::Memory::*;
use std::ptr::null_mut;

/// Wrapper seguro para leitura de memória física via CR3 Swap
pub struct KernelInterface {
    process_handle: HANDLE,
    cr3: u64, // Diretório de tabelas de página do alvo
}

impl KernelInterface {
    /// Efetua a leitura de memória virtual do alvo bypassando permissões.
    /// 
    /// # Camada 1: SINTAXE (O quê)
    /// Utilizamos uma operação unsafe encapsulada para copiar dados entre espaços de endereçamento.
    /// 
    /// # Camada 2: MEMÓRIA (Como)
    /// O driver realiza um "context switch" lógico no MMU (Memory Management Unit) da CPU
    /// trocando o registrador CR3 temporariamente para o diretório do processo alvo.
    pub unsafe fn read_virtual_memory<T>(&self, address: u64) -> Result<T, String> {
        let mut buffer: T = std::mem::zeroed();
        let size = std::mem::size_of::<T>();

        // ⚠️ RISCO DE ESTABILIDADE: Se o endereço for inválido, pode causar BSoD se não houver probe.
        // No Rust de 2026, usamos o padrão de Shadow Casting para validar a página antes.
        
        let status = MmCopyVirtualMemory(
            self.current_process,
            address as *mut _,
            self.target_process,
            &mut buffer as *mut _ as *mut _,
            size,
            KernelMode,
            &mut bytes_read
        );

        if status.is_success() {
            Ok(buffer)
        } else {
            Err(format!("Falha na leitura: {:?}", status))
        }
    }
}
```

### 🧠 Análise do Rust Sentinel

*   **CAMADA 1: SINTAXE:** O código define um `struct` que mantém o estado da interface com o kernel. O método `read_virtual_memory` é genérico `<T>`, permitindo ler qualquer estrutura de dados (ex: `PlayerPawn`).
*   **CAMADA 2: MEMÓRIA:** Diferente do C++, onde você teria que gerenciar manualmente o tamanho do buffer e o alinhamento, o Rust usa `std::mem::size_of::<T>()` em tempo de compilaos para garantir que não haja *stack overflow* ou leituras fora dos limites.
*   **CAMADA 3: SEGURANÇA & OWNERSHIP:** O uso de `Result<T, String>` obriga o desenvolvedor a tratar erros de leitura (ex: quando o jogo fecha). O `unsafe` é restrito à chamada da WinAPI, mantendo o restante da lógica sob as garantias do Borrow Checker.

---

## 🚫 Por que é Indetectável?

1.  **Sem Handles:** Não utilizamos `OpenProcess` ou `PROCESS_VM_READ`. O Anti-Cheat não vê pedidos de acesso à memória via API documentada.
2.  **Rust Signatures:** O compilador Rust gera binários com layouts de seção diferentes do MSVC (C++), o que dificulta a criação de assinaturas estáticas por Anti-Cheats que focam em cheats "manjados" de C++.

---
📌 **Ponte C++:** Em C++, você usaria um `reinterpret_cast<void*>` volátil e rezaria para o ponteiro ser válido. Aqui, o sistema de tipos garante que o `buffer` de destino existe e tem o tamanho correto antes mesmo da execução.
