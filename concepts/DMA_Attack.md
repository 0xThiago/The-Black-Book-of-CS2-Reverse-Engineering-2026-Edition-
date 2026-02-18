# 🔧 DMA Attack

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #hardware #dma #fpga #elite #2026

## 📌 Definição

**DMA Attack** (Direct Memory Access Attack) utiliza dispositivos de hardware externos (tipicamente FPGAs como PCILeech/Screamer) conectados via PCIe para ler e escrever na memória física do sistema alvo **sem qualquer interação com o CPU ou sistema operacional**. É a técnica de leitura de memória mais segura em 2026, pois opera completamente fora do alcance de Anti-Cheats baseados em software.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[EPT_Manipulation]]
- [[Hardware_Input_Methods]]

## 📚 Arquitetura DMA

### Acesso Normal vs. DMA
```
Leitura Normal (via CPU):
───────────────────────────────────────────
CPU → Page Tables (CR3) → TLB → RAM
 ↑                                  ↓
 └── AC monitora via hooks ←────────┘
     (ObRegisterCallbacks, ETW)
───────────────────────────────────────────

Leitura via DMA:
───────────────────────────────────────────
FPGA Device ──(PCIe bus)──→ RAM
                              ↓
                         Dados lidos
                              ↓
                     FPGA ──(USB)──→ PC Secundário

CPU e OS do PC alvo NÃO SÃO ENVOLVIDOS.
Anti-Cheat NÃO TEM VISIBILIDADE sobre DMA.
───────────────────────────────────────────
```

### Setup Típico (2026)
```
┌──────────────┐         ┌──────────────┐
│ PC de Gaming  │  PCIe   │  FPGA Board   │
│ (CS2 rodando) │◄───────►│  (Screamer/    │
│               │  M.2    │   LeetDMA)    │
└──────────────┘  slot    └──────┬───────┘
                                 │ USB 3.0
                                 ▼
                        ┌──────────────┐
                        │ PC Secundário │
                        │ (Cheat roda   │
                        │  aqui)        │
                        └──────────────┘
```

## 🛠️ Implementação em Rust (2026)

### 1. PCILeech/MemProcFS Wrapper

```rust
/// ⚠️ RISCO DE ESTABILIDADE/DETECÇÃO:
/// DMA é seguro contra AC de software, mas IOMMU (VT-d)
/// pode bloquear acesso DMA não autorizado. Verificar
/// se VT-d está desabilitado na BIOS.

/// Wrapper seguro para leitura de memória via DMA
///
/// # Camada 1: SINTAXE
/// Encapsula a API do MemProcFS (vmmdll.dll) que é a
/// biblioteca padrão para comunicação com FPGAs PCILeech.
///
/// # Camada 2: MEMÓRIA
/// O VMM_HANDLE é um ponteiro opaco para o estado interno
/// do MemProcFS. A memória do jogo alvo é lida diretamente
/// da RAM física via PCIe — sem intermediários.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Implementamos Drop para VMM_HANDLE (VMMDLL_Close).
/// Reads retornam T por valor (copy), não referência.
///
/// **Ponte C++**: Em C++, VMMDLL_MemRead recebe void*.
/// Em Rust, usamos generics para type-safe reads.
pub struct DmaReader {
    vmm_handle: *mut std::ffi::c_void,
    target_pid: u32,
    client_dll_base: u64,
}

impl DmaReader {
    /// Inicializa conexão com FPGA device
    pub unsafe fn new(device_type: &str) -> Result<Self, String> {
        // Argumentos para VMMDLL_Initialize
        let args: Vec<String> = vec![
            String::new(),
            "-device".to_string(),
            device_type.to_string(),  // "fpga://algo=0" ou "fpga://algo=1"
        ];

        let c_args: Vec<std::ffi::CString> = args.iter()
            .map(|a| std::ffi::CString::new(a.as_str()).unwrap())
            .collect();

        let mut ptrs: Vec<*const i8> = c_args.iter()
            .map(|a| a.as_ptr())
            .collect();

        let vmm = vmmdll_initialize(
            ptrs.len() as i32,
            ptrs.as_mut_ptr() as *mut *mut i8,
        );

        if vmm.is_null() {
            return Err("VMMDLL_Initialize falhou — FPGA não conectada?".to_string());
        }

        Ok(Self {
            vmm_handle: vmm,
            target_pid: 0,
            client_dll_base: 0,
        })
    }

    /// Encontra o processo do CS2
    pub unsafe fn attach_to_cs2(&mut self) -> Result<(), String> {
        self.target_pid = vmmdll_pid_get_from_name(self.vmm_handle, "cs2.exe\0".as_ptr());

        if self.target_pid == 0 {
            return Err("CS2 não encontrado".to_string());
        }

        // Encontrar base de client.dll
        self.client_dll_base = vmmdll_module_base(
            self.vmm_handle,
            self.target_pid,
            "client.dll\0".as_ptr(),
        );

        if self.client_dll_base == 0 {
            return Err("client.dll não encontrada".to_string());
        }

        Ok(())
    }

    /// Lê valor da memória do jogo via DMA
    ///
    /// PERFORMANCE-CHECK:
    /// Latência típica: 2-5μs por read (via FPGA a 75MHz)
    /// Throughput: ~150MB/s (suficiente para game hacking)
    pub unsafe fn read<T: Copy>(&self, address: u64) -> Option<T> {
        let mut value: T = std::mem::zeroed();
        let success = vmmdll_mem_read(
            self.vmm_handle,
            self.target_pid,
            address,
            &mut value as *mut T as *mut u8,
            std::mem::size_of::<T>() as u32,
        );

        if success { Some(value) } else { None }
    }

    /// Lê buffer da memória do jogo
    pub unsafe fn read_buffer(&self, address: u64, buffer: &mut [u8]) -> bool {
        vmmdll_mem_read(
            self.vmm_handle,
            self.target_pid,
            address,
            buffer.as_mut_ptr(),
            buffer.len() as u32,
        )
    }

    /// Scatter read — lê múltiplos endereços em uma operação PCIe
    ///
    /// PERFORMANCE-CHECK:
    /// Scatter read de 64 endereços: ~10μs (vs 320μs sequencial)
    /// Essencial para ler entity list completa em um frame.
    pub unsafe fn scatter_read(&self, reads: &[(u64, usize)]) -> Vec<Vec<u8>> {
        let mut results = Vec::with_capacity(reads.len());

        // Criar scatter handle
        let scatter = vmmdll_scatter_initialize(self.vmm_handle, self.target_pid);

        // Preparar todas as leituras
        for (addr, size) in reads {
            vmmdll_scatter_prepare(scatter, *addr, *size as u32);
        }

        // Executar todas em um batch PCIe
        vmmdll_scatter_execute(scatter);

        // Coletar resultados
        for (addr, size) in reads {
            let mut buf = vec![0u8; *size];
            vmmdll_scatter_read(scatter, *addr, buf.as_mut_ptr(), *size as u32);
            results.push(buf);
        }

        vmmdll_scatter_close(scatter);
        results
    }
}

impl Drop for DmaReader {
    fn drop(&mut self) {
        unsafe {
            if !self.vmm_handle.is_null() {
                vmmdll_close(self.vmm_handle);
            }
        }
    }
}

// FFI bindings (simplificado)
extern "C" {
    fn vmmdll_initialize(argc: i32, argv: *mut *mut i8) -> *mut std::ffi::c_void;
    fn vmmdll_close(vmm: *mut std::ffi::c_void);
    fn vmmdll_pid_get_from_name(vmm: *mut std::ffi::c_void, name: *const u8) -> u32;
    fn vmmdll_module_base(vmm: *mut std::ffi::c_void, pid: u32, name: *const u8) -> u64;
    fn vmmdll_mem_read(vmm: *mut std::ffi::c_void, pid: u32, addr: u64, buf: *mut u8, size: u32) -> bool;
    fn vmmdll_scatter_initialize(vmm: *mut std::ffi::c_void, pid: u32) -> *mut std::ffi::c_void;
    fn vmmdll_scatter_prepare(scatter: *mut std::ffi::c_void, addr: u64, size: u32);
    fn vmmdll_scatter_execute(scatter: *mut std::ffi::c_void);
    fn vmmdll_scatter_read(scatter: *mut std::ffi::c_void, addr: u64, buf: *mut u8, size: u32);
    fn vmmdll_scatter_close(scatter: *mut std::ffi::c_void);
}
```

## 🎯 Uso em CS2 (2026)

```rust
/// Ler entity list completa via DMA scatter read
pub unsafe fn read_entities(dma: &DmaReader) -> Vec<PlayerData> {
    let entity_list = dma.read::<u64>(
        dma.client_dll_base + offsets::client::DW_ENTITY_LIST
    ).unwrap_or(0);

    // Preparar scatter read para 64 entidades
    let mut addrs = Vec::new();
    for i in 0..64 {
        let entry_addr = entity_list + (i * 0x78);
        addrs.push((entry_addr, 8)); // Ponteiro para entity
    }

    let results = dma.scatter_read(&addrs);
    // ... processar resultados
    Vec::new()
}
```

## 📊 Hardware Comparativo (2026)

| Dispositivo | Preço | Interface | Throughput | Latência | FPGA |
|-------------|-------|-----------|-----------|---------|------|
| **Screamer M.2** | ~$300 | M.2 PCIe | ~150MB/s | 2-5μs | Artix-7 |
| **LeetDMA** | ~$250 | M.2 PCIe | ~150MB/s | 2-5μs | Artix-7 |
| **PCILeech FPGA** | ~$400 | Thunderbolt | ~200MB/s | 3-8μs | Kintex-7 |
| **USB3380 EVB** | ~$50 | PCIe x1 | ~50MB/s | 10-20μs | N/A |

> [!IMPORTANT]
> **IOMMU (VT-d)** bloqueia DMA não autorizado. O dispositivo deve
> emular um device PCIe legítimo (ex: NIC Intel) para bypass.
> FPGAs modernos incluem firmware de spoof de device ID.

## 📖 Ver Também
- [[EPT_Manipulation]]
- [[Hardware_Input_Methods]]

---
<p align="center">REDFLAG © 2026</p>
