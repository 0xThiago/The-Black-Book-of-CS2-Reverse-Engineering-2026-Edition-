# 🔮 EPT Manipulation

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #hypervisor #ept #ring-minus-1 #elite

## 📌 Definição

**EPT Manipulation** (Extended Page Table Manipulation) é uma técnica de evasão de nível hypervisor (Ring -1) que explora as **Extended Page Tables** do Intel VT-x para criar visões duplas da memória — uma visão "limpa" que o Anti-Cheat vê, e uma visão "real" com o código do cheat. É considerada uma das técnicas mais avançadas e difíceis de detectar em 2026.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Code_Virtualization]]
- [[DMA_Attack]]
- [[Técnica 044 - Anti-VM Techniques]]

## 📚 Arquitetura de EPT

### Address Translation com EPT
```
Sem EPT (Legacy):
  Virtual Address → CR3 Page Tables → Physical Address

Com EPT (VT-x):
  Guest Virtual → Guest Page Tables (CR3) → Guest Physical
                                              │
                                              ▼
                                  EPT Page Tables → Host Physical
                                  (controlada pelo Hypervisor!)

O hypervisor decide o que cada página física REALMENTE contém.
Um AC no Guest OS não tem visibilidade sobre as EPT entries.
```

### Dual-View Memory
```
┌─────────────────────────────────────────────────┐
│                 HYPERVISOR (Ring -1)              │
│                                                   │
│   EPT View "Clean" (para AC scanner):             │
│   ┌──────────┐                                    │
│   │ Código    │ → Página com código legítimo       │
│   │ Original  │   (cópia limpa do binário)         │
│   └──────────┘                                    │
│                                                   │
│   EPT View "Real" (para execução):                │
│   ┌──────────┐                                    │
│   │ Código    │ → Página com cheat code            │
│   │ Hookado   │   (hooks, patches, shellcode)      │
│   └──────────┘                                    │
│                                                   │
│   Trigger: EPT Violation Handler                   │
│   - Leitura pela AC → View Clean                   │
│   - Execução pelo CPU → View Real                  │
└─────────────────────────────────────────────────┘
```

## 🛠️ Implementação Conceitual em Rust (2026)

### 1. EPT Entry Structure

```rust
/// Entrada de Extended Page Table (EPT PTE)
///
/// # Camada 1: SINTAXE
/// Estrutura bitfield que mapeia exatamente o formato
/// de uma entrada EPT de 64 bits conforme Intel SDM Vol. 3C.
///
/// # Camada 2: MEMÓRIA
/// Exatamente 8 bytes (u64). Layout é definido pelo hardware
/// Intel — não pode ser alterado. #[repr(C)] garante que
/// Rust não adiciona padding.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Operações bitwise em u64 são safe. O unsafe vem apenas
/// quando escrevemos a EPT entry na memória do hypervisor.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct EptEntry {
    pub value: u64,
}

impl EptEntry {
    /// Bits de permissão
    pub const READ: u64    = 1 << 0;
    pub const WRITE: u64   = 1 << 1;
    pub const EXECUTE: u64 = 1 << 2;

    /// Cria entrada com permissões e endereço físico
    pub fn new(physical_addr: u64, permissions: u64) -> Self {
        let pfn = (physical_addr >> 12) & 0xF_FFFF_FFFF; // 40 bits
        Self {
            value: permissions | (pfn << 12),
        }
    }

    pub fn read_allowed(&self) -> bool { self.value & Self::READ != 0 }
    pub fn write_allowed(&self) -> bool { self.value & Self::WRITE != 0 }
    pub fn execute_allowed(&self) -> bool { self.value & Self::EXECUTE != 0 }

    /// Altera o endereço físico alvo (page frame number)
    pub fn set_pfn(&mut self, physical_addr: u64) {
        let pfn = (physical_addr >> 12) & 0xF_FFFF_FFFF;
        self.value = (self.value & 0xFFF) | (pfn << 12);
    }

    /// Remove permissão de leitura (trigger EPT violation em reads)
    pub fn remove_read(&mut self) { self.value &= !Self::READ; }

    /// Remove permissão de execução (trigger EPT violation em exec)
    pub fn remove_execute(&mut self) { self.value &= !Self::EXECUTE; }
}
```

### 2. Dual-View Manager

```rust
/// Gerenciador de visão dupla de memória via EPT
///
/// # Camada 1: SINTAXE
/// Mantém duas páginas para cada hook: uma "limpa" e uma "real".
/// Quando o AC lê a memória, vê a limpa. Quando o CPU executa, usa a real.
///
/// # Camada 2: MEMÓRIA
/// Cada hook consome 2 páginas física (4KB × 2 = 8KB).
/// A shadow_pages HashMap reside no heap do hypervisor.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// O HashMap possui ownership das páginas shadow.
/// Quando o DualViewManager é dropped, as páginas são liberadas.
pub struct DualViewManager {
    /// Mapa: guest physical address → shadow page info
    shadow_pages: std::collections::HashMap<u64, ShadowPage>,
}

pub struct ShadowPage {
    /// Página com código original (para leitura pelo AC)
    pub clean_page: u64,   // Host physical address
    /// Página com código hookado (para execução)
    pub hooked_page: u64,  // Host physical address
    /// Estado atual (qual view está ativa)
    pub current_view: PageView,
}

#[derive(PartialEq)]
pub enum PageView {
    Clean,  // AC vê esta
    Hooked, // CPU executa esta
}

impl DualViewManager {
    pub fn new() -> Self {
        Self {
            shadow_pages: std::collections::HashMap::new(),
        }
    }

    /// Instala hook invisível em página de memória
    ///
    /// 1. Copia página original para clean_page
    /// 2. Cria hooked_page com o código modificado
    /// 3. Configura EPT: Read → clean, Execute → hooked
    pub unsafe fn install_stealth_hook(
        &mut self,
        guest_physical: u64,
        hook_data: &[u8],
        hook_offset: usize,
    ) -> Result<(), String> {
        // Alocar duas páginas físicas no host
        let clean_page = self.alloc_host_page()?;
        let hooked_page = self.alloc_host_page()?;

        // Copiar conteúdo original para ambas
        self.copy_guest_page(guest_physical, clean_page);
        self.copy_guest_page(guest_physical, hooked_page);

        // Aplicar hook na hooked_page
        let hooked_ptr = hooked_page as *mut u8;
        std::ptr::copy_nonoverlapping(
            hook_data.as_ptr(),
            hooked_ptr.add(hook_offset),
            hook_data.len(),
        );

        // Configurar EPT split:
        // - Leitura (R) → clean_page
        // - Execução (X) → hooked_page
        // Isso requer EPT violation handler no hypervisor
        self.configure_ept_split(guest_physical, clean_page, hooked_page)?;

        self.shadow_pages.insert(guest_physical, ShadowPage {
            clean_page,
            hooked_page,
            current_view: PageView::Hooked,
        });

        Ok(())
    }

    // Implementações internas (platform-specific)
    unsafe fn alloc_host_page(&self) -> Result<u64, String> { todo!() }
    unsafe fn copy_guest_page(&self, src: u64, dst: u64) { todo!() }
    unsafe fn configure_ept_split(&self, gpa: u64, clean: u64, hooked: u64)
        -> Result<(), String> { todo!() }
}
```

### 3. EPT Violation Handler

```rust
/// Handler chamado quando ocorre EPT violation
///
/// O hypervisor intercepta violações e decide qual view mostrar.
/// Isso é o coração da técnica dual-view.
pub unsafe fn ept_violation_handler(
    manager: &mut DualViewManager,
    guest_physical: u64,
    access_type: AccessType,
) {
    if let Some(shadow) = manager.shadow_pages.get_mut(&(guest_physical & !0xFFF)) {
        match access_type {
            AccessType::Read => {
                // AC está lendo memória → mostrar página limpa
                if shadow.current_view != PageView::Clean {
                    // Trocar EPT entry para clean_page
                    switch_ept_page(guest_physical, shadow.clean_page);
                    shadow.current_view = PageView::Clean;
                }
            },
            AccessType::Execute => {
                // CPU vai executar → mostrar página hookada
                if shadow.current_view != PageView::Hooked {
                    switch_ept_page(guest_physical, shadow.hooked_page);
                    shadow.current_view = PageView::Hooked;
                }
            },
            AccessType::Write => {
                // Propagar write para ambas as cópias (manter sync)
            },
        }
    }
}

pub enum AccessType { Read, Write, Execute }

unsafe fn switch_ept_page(gpa: u64, new_hpa: u64) { todo!() }
```

## 📊 Comparação com Outras Técnicas de Ocultação

| Técnica | Nível | Detecção VAC | Detecção Faceit | Complexidade |
|---------|-------|-------------|-----------------|-------------|
| **IAT Hooking** | Ring 3 | 🔴 Fácil | 🔴 Fácil | Baixa |
| **Inline Hooking** | Ring 3 | 🟠 Médio | 🔴 Fácil | Média |
| **SSDT Hooking** | Ring 0 | 🟡 Médio | 🟠 Médio | Alta |
| **EPT Manipulation** | Ring -1 | 🟢 Mínimo | 🟢 Baixo | Muito Alta |

> [!CAUTION]
> EPT manipulation requer um **hypervisor custom** rodando ANTES
> do boot do Windows. Erros no código do hypervisor causam BSoD
> ou corrupção de dados. Requer conhecimento profundo de Intel VT-x.

## 📖 Ver Também
- [[Code_Virtualization]]
- [[DMA_Attack]]
- [[Técnica 044 - Anti-VM Techniques]]

---
<p align="center">REDFLAG © 2026</p>
