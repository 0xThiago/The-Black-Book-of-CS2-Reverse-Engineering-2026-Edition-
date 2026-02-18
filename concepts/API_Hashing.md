# 🔐 API Hashing

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #obfuscation #anti-analysis #evasion

## 📌 Definição

**API Hashing** é uma técnica de ofuscação onde funções da Windows API são resolvidas dinamicamente em runtime utilizando valores de hash ao invés de nomes em plain-text. Isso oculta quais APIs o malware/cheat utiliza, dificultando análise estática e evitando assinaturas baseadas em import tables.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[DLL_Injection]]
- [[Manual_Mapping]]
- [[String Encryption and Obfuscation]]
- [[Compile_Time_Obfuscation]]

## 📚 Por Que API Hashing é Efetivo (2026)

### Análise Estática Tradicional
```
Análise de imports (IDA Pro, PE-bear):
├─ IAT revela: kernel32!CreateFileA
├─ IAT revela: ntdll!NtReadVirtualMemory  
├─ IAT revela: user32!SetWindowsHookExA
└─ Conclusão: Provavelmente malware/cheat ❌
```

### Com API Hashing
```
IAT contém apenas:
├─ kernel32!LoadLibraryA
└─ kernel32!GetProcAddress

Código resolve funções via hash em runtime:
├─ hash(0x7C0DFCAA) → CreateFileA     ✅
├─ hash(0x5FC8D902) → NtReadVirtualMemory  ✅
└─ hash(0xE553A458) → SetWindowsHookExA  ✅
```

## 🛠️ Implementação em Rust (2026)

### 1. Algoritmo de Hashing (ROL13 + XOR)

```rust
/// Calcula hash de um nome de API (case-insensitive)
pub fn hash_api_name(name: &str) -> u32 {
    let mut hash: u32 = 0;
    
    for byte in name.bytes() {
        // Convert to uppercase
        let c = if byte >= b'a' && byte <= b'z' {
            byte - 32
        } else {
            byte
        };
        
        // ROL13: rotate left 13 bits
        hash = hash.rotate_left(13);
        
        // Add character
        hash = hash.wrapping_add(c as u32);
    }
    
    hash
}

// Pré-calcular hashes em compile-time
pub const HASH_NTREADVIRTUALMEMORY: u32 = 0x5FC8D902;
pub const HASH_CREATEREMOTETHREAD: u32 = 0x3F9287AA;
pub const HASH_VIRTUALALLOCEX: u32 = 0x6E1A959C;

#[test]
fn test_hashing() {
    assert_eq!(hash_api_name("NtReadVirtualMemory"), HASH_NTREADVIRTUALMEMORY);
    assert_eq!(hash_api_name("CreateRemoteThread"), HASH_CREATEREMOTETHREAD);
}
```

**Análise Rust Sentinel**:

> **CAMADA 1: SINTAXE**  
> Iteramos sobre bytes do nome da API, convertendo para uppercase e aplicando ROL13 (rotate left 13 bits) + adição.
> 
> **CAMADA 2: MEMÓRIA**  
> O hash é um `u32` na stack (apenas 4 bytes). Operação é extremamente rápida (sem alocações). String original não é armazenada no binário após compilação com const.
> 
> **CAMADA 3: SEGURANÇA & OWNERSHIP**  
> Rust garante que `name` é uma referência válida. `wrapping_add` evita undefined behavior em overflow.

### 2. API Resolver Dinâmico

```rust
use windows::Win32::System::{LibraryLoader::*, SystemServices::*, Diagnostics::Debug::*};
use std::ffi::CString;

/// Resolve API via hash caminhando o Export Address Table
pub unsafe fn get_proc_address_by_hash(
    module_name: &str,
    api_hash: u32,
) -> Option<*const ()> {
    // 1. Carregar módulo
    let module_cstr = CString::new(module_name).ok()?;
    let module_handle = LoadLibraryA(windows::core::PCSTR(module_cstr.as_ptr() as *const u8))
        .ok()?;
    
    // 2. Obter base do módulo
    let module_base = module_handle.0 as *const u8;
    
    // 3. Parsear PE headers
    let dos_header = module_base as *const IMAGE_DOS_HEADER;
    let nt_headers = module_base.add((*dos_header).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    
    // 4. Obter Export Directory
    let export_dir_rva = (*nt_headers).OptionalHeader.DataDirectory[0].VirtualAddress;
    if export_dir_rva == 0 {
        return None;
    }
    
    let export_dir = module_base.add(export_dir_rva as usize) as *const IMAGE_EXPORT_DIRECTORY;
    
    // 5. Obter arrays de exports
    let names_rva = (*export_dir).AddressOfNames;
    let functions_rva = (*export_dir).AddressOfFunctions;
    let ordinals_rva = (*export_dir).AddressOfNameOrdinals;
    
    let names = module_base.add(names_rva as usize) as *const u32;
    let functions = module_base.add(functions_rva as usize) as *const u32;
    let ordinals = module_base.add(ordinals_rva as usize) as *const u16;
    
    // 6. Iterar sobre exports e comparar hashes
    for i in 0..(*export_dir).NumberOfNames {
        let name_rva = *names.add(i as usize);
        let name_ptr = module_base.add(name_rva as usize) as *const i8;
        let name_cstr = std::ffi::CStr::from_ptr(name_ptr);
        let name_str = name_cstr.to_str().ok()?;
        
        // Calcular hash do nome
        if hash_api_name(name_str) == api_hash {
            // Encontrado! Obter endereço da função
            let ordinal = *ordinals.add(i as usize);
            let func_rva = *functions.add(ordinal as usize);
            let func_addr = module_base.add(func_rva as usize);
            
            return Some(func_addr as *const ());
        }
    }
    
    None
}

#[repr(C)]
struct IMAGE_DOS_HEADER {
    e_magic: u16,
    _reserved: [u16; 29],
    e_lfanew: i32,
}

#[repr(C)]
struct IMAGE_NT_HEADERS64 {
    Signature: u32,
    FileHeader: IMAGE_FILE_HEADER,
    OptionalHeader: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
struct IMAGE_FILE_HEADER {
    _reserved: [u16; 10],
}

#[repr(C)]
struct IMAGE_OPTIONAL_HEADER64 {
    _reserved: [u8; 112],
    DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
struct IMAGE_DATA_DIRECTORY {
    VirtualAddress: u32,
    Size: u32,
}

#[repr(C)]
struct IMAGE_EXPORT_DIRECTORY {
    _reserved1: [u32; 3],
    Name: u32,
    Base: u32,
    NumberOfFunctions: u32,
    NumberOfNames: u32,
    AddressOfFunctions: u32,
    AddressOfNames: u32,
    AddressOfNameOrdinals: u32,
}
```

### 3. Uso Prático

```rust
/// Exemplo: Injetar DLL usando apenas API hashing
pub unsafe fn stealth_dll_injection(target_pid: u32, dll_path: &str) -> Result<(), String> {
    // Resolver APIs via hash (não aparecem no IAT)
    let virtual_alloc_ex = get_proc_address_by_hash("kernel32.dll", HASH_VIRTUALALLOCEX)
        .ok_or("Failed to resolve VirtualAllocEx")?;
    
    let write_process_memory = get_proc_address_by_hash("kernel32.dll", 0x1234ABCD)
        .ok_or("Failed to resolve WriteProcessMemory")?;
    
    let create_remote_thread = get_address_by_hash("kernel32.dll", HASH_CREATEREMOTETHREAD)
        .ok_or("Failed to resolve CreateRemoteThread")?;
    
    // Casting para function pointers
    let virtual_alloc_ex_fn: unsafe extern "system" fn(
        HANDLE, *const std::ffi::c_void, usize, u32, u32
    ) -> *mut std::ffi::c_void = std::mem::transmute(virtual_alloc_ex);
    
    // ... usar funções normalmente
    
    Ok(())
}
```

## 🎯 Variações de Algoritmos (2026)

### 1. CRC32

```rust
pub fn hash_api_crc32(name: &str) -> u32 {
    let mut crc: u32 = 0xFFFFFFFF;
    
    for byte in name.bytes().map(|b| b.to_ascii_uppercase()) {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB88320
            } else {
                crc >> 1
            };
        }
    }
    
    !crc
}
```

### 2. FNV-1a (Fast Non-cryptographic Hash)

```rust
pub fn hash_api_fnv1a(name: &str) -> u32 {
    const FNV_OFFSET_BASIS: u32 = 0x811C9DC5;
    const FNV_PRIME: u32 = 0x01000193;
    
    let mut hash = FNV_OFFSET_BASIS;
    
    for byte in name.bytes().map(|b| b.to_ascii_uppercase()) {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    
    hash
}
```

### 3. Custom Polymorphic (2026)

```rust
// build.rs - gera algoritmo único por build
fn generate_custom_hash_algorithm() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    let rotate_amount = rng.gen_range(7..19);
    let xor_key = rng.gen::<u32>();
    
    format!(r#"
        pub fn hash_api_name(name: &str) -> u32 {{
            let mut hash: u32 = 0x{:08X};
            for byte in name.bytes() {{
                let c = if byte >= b'a' && byte <= b'z' {{ byte - 32 }} else {{ byte }};
                hash = hash.rotate_left({});
                hash = hash.wrapping_add(c as u32);
            }}
            hash ^ 0x{:08X}
        }}
    "#, rng.gen::<u32>(), rotate_amount, xor_key)
}
```

## ⚠️ Detecção e Contramedidas (2026)

### Como Anti-Cheats Detectam API Hashing

```
1. Behavioral analysis
   ├─ Processo enumera módulos sem motivo aparente
   ├─ Acesso frequente a Export Address Tables
   └─ Solução: Cachear resultados, limitar enumerações

2. Heurística de padrões de código
   ├─ Código que caminha EAT manualmente
   ├─ Loops comparando hashes
   └─ Solução: Ofuscar lógica de hashing via [[Control_Flow_Flattening]]

3. Hooking de GetProcAddress
   ├─ Anti-cheat hook e monitora resoluções dinâmicas
   └─ Solução: Bypass hook via syscall direto ou unhook

4. Assinaturas de algoritmos conhecidos
   ├─ ROL13, CRC32, FNV-1a são bem conhecidos
   └─ Solução: Algoritmo customizado por build (polimorfismo)

5. Hash databases
   ├─ Comunidades mantém DBs de hashes conhecidos
   └─ Solução: Randomizar salt/XOR keys por build
```

### Defesa: Layered Hashing

```rust
/// Combinar múltiplos algoritmos
pub fn layered_hash(name: &str, build_seed: u32) -> u32 {
    let h1 = hash_api_fnv1a(name);
    let h2 = hash_api_crc32(name);
    let h3 = custom_hash(name, build_seed);
    
    // Combinar hashes de forma única por build
    (h1 ^ h2).wrapping_add(h3)
}
```

## 📊 Performance vs. Segurança

| Aspecto | Direct Import | API Hashing | Layered Hashing |
|---------|---------------|-------------|-----------------|
| **Velocidade de resolução** | Instantânea | 50-500µs | 100-1000µs |
| **Overhead** | 0% | \u003c1% | 1-2% |
| **Análise estática** | 🔴 Trivial | 🟢 Difícil | 🟢 Muito difícil |
| **Reversão via emulação** | N/A | 🟡 Possível | 🟡 Possível |

> [!TIP]
> **Recomendação 2026**: Cachear APIs resolvidas após primeira resolução para evitar overhead contínuo

## 🔬 Pesquisa 2026

### Mal ware Real-World

Segundo pesquisas de 2026:
- **OysterLoader**: Usa custom hashing algorithms que variam entre samples
- **Chrysalis**: Emprega API hashing + layered obfuscation (shellcode encryption, process hollowing)
- **Cobalt Strike**: Randomiza API hashes por build para bypass detection logic

### Defesa

- **Dynamic Analysis**: Ferramentas como IDA Pro com IDAPython podem chamar funções de hashing do próprio malware como "hash oracle"
- **Behavioral Anomaly Detection**: ML-powered detection foca em padrões comportamentais ao invés de signatures
- **Automated Deobfuscation**: Inspetores de DLL memory que extraem program slices de hashing

## 📖 Ver Também
- [[String Encryption and Obfuscation]]
- [[DLL_Injection]]
- [[Manual_Mapping]]
- [[Compile_Time_Obfuscation]]

---
<p align="center">REDFLAG © 2026</p>
