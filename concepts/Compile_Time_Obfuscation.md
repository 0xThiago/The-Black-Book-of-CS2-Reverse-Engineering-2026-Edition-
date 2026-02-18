# 🔒 Compile Time Obfuscation

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #obfuscation #build-time #llvm

## 📌 Definição

**Compile-Time Obfuscation** refere-se a transformações de código aplicadas durante o processo de compilação, antes que o binário final seja gerado. Diferente de ofuscação em runtime, estas técnicas têm **zero overhead**, pois o código já está transformado quando executa.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Control_Flow_Flattening]]
- [[Metamorphic_Code_Generation]]
- [[Runtime_Code_Generation]]
- [[Code_Virtualization]]

## 📚 Vantagens sobre Runtime Obfuscation

| Aspecto | Compile-Time | Runtime |
|---------|--------------|---------|
| **Performance** | 🟢 Zero overhead | 🟠 5-15% overhead |
| **Detecção em memória** | 🟡 Código fixo | 🟢 Código muda |
| **Complexidade** | 🟢 Configurar uma vez | 🔴 Manter engine |
| **Efetividade vs. análise estática** | 🟢 Alta | 🟢 Muito alta |
| **Reversibilidade** | 🟠 Média | 🟡 Baixa |

## 🛠️ Técnicas de Implementação (Rust 2026)

### 1. String Encryption com Goldberg

```rust
use goldberg::goldberg_obfuscate;

/// Strings sensíveis criptografadas em compile-time
#[goldberg_obfuscate(strings)]
pub fn init_cheat_config() -> Config {
    Config {
        // Strings são criptografadas no binário
        // Decryptadas apenas em runtime
        license_server: "https://cheat-api.example.com",
        api_key: "sk_live_abc123def456",
        version: "2.0.1",
    }
}

// No assembly resultante:
// .rodata:
// encrypted_string_1: db 0x8A, 0x3F, 0x92, 0xE1, ...  ; XOR + shuffle
// decrypt_stub_1: push rbp; mov rbp, rsp; ...
```

**Resultado**: `strings cheat.exe` não revela nada útil ✅

### 2. Integer Literal Obfuscation

```rust
use goldberg::goldberg_obfuscate;

#[goldberg_obfuscate(integers)]
pub fn check_critical_values() -> bool {
    const MAX_HEALTH: i32 = 100;      // Ofuscado para: (0xDEAD ^ 0xDFAD)
    const MAX_ARMOR: i32 = 200;        // Ofuscado para: (0xCAFE - 0xC8FE)
    const HEADSHOT_MULTIPLIER: f32 = 4.0; // Ofuscado via bitwise ops
    
    // Código gerado contém expressões complexas ao invés de constantes
    get_player_health() < (0xDEAD ^ 0xDFAD)
}
```

### 3. LLVM Pass Customizado

```toml
# Cargo.toml
[profile.release]
opt-level = 3
lto = "fat"              # Link-Time Optimization
codegen-units = 1        # Melhor otimização
strip = true             # Remover símbolos

[build]
rustflags = [
    "-C", "llvm-args=-obfuscate-cfg",     # Control flow
    "-C", "llvm-args=-flatten-cfg",       # Flattening
    "-C", "llvm-args=-split-basic-blocks", # Quebrar blocos
]
```

**Efeito**: LLVM aplica transformações profundas no IR antes de gerar assembly.

## 🎯 Build-Time Code Generation

### 1. Build Script para Polimorfismo

```rust
// build.rs
use std::fs;
use std::path::Path;
use rand::Rng;

fn main() {
    let mut rng = rand::thread_rng();
    
    // Gerar constantes únicas por build
    let magic_number: u64 = rng.gen();
    let xor_key: u32 = rng.gen();
    
    let generated_code = format!(r#"
        // AUTO-GENERATED - NÃO EDITAR
        pub const BUILD_MAGIC: u64 = 0x{:016X};
        pub const XOR_KEY: u32 = 0x{:08X};
        
        pub fn decrypt_config(data: &[u8]) -> Vec<u8> {{
            data.iter()
                .map(|b| b ^ (XOR_KEY as u8))
                .collect()
        }}
    "#, magic_number, xor_key);
    
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest_path = Path::new(&out_dir).join("generated.rs");
    fs::write(&dest_path, generated_code).unwrap();
    
    println!("cargo:rerun-if-changed=build.rs");
}

// Em src/lib.rs:
include!(concat!(env!("OUT_DIR"), "/generated.rs"));
```

**Resultado**: Cada compilação tem assinatura binária única 🎲

### 2. Conditional Compilation com Features

```rust
// Cargo.toml
[features]
default = ["variant_a"]
variant_a = []
variant_b = []
variant_c = []

// src/aimbot.rs
#[cfg(feature = "variant_a")]
pub fn calculate_angle(/*...*/) -> Vec2 {
    // Implementação via arctan2
    Vec2::new(
        atan2(delta.z, hyp),
        atan2(delta.y, delta.x),
    )
}

#[cfg(feature = "variant_b")]
pub fn calculate_angle(/*...*/) -> Vec2 {
    // Implementação via lookup table
    let idx = ((delta.y.abs() * 1000.0) as usize) % LUT_SIZE;
    ANGLE_LUT[idx]
}

#[cfg(feature = "variant_c")]
pub fn calculate_angle(/*...*/) -> Vec2 {
    // Implementação via série de Taylor
    taylor_approx_atan2(delta.y, delta.x)
}
```

**Uso**: `cargo build --release --features variant_b`  
Cada variante tem assembly completamente diferente ✅

## 🛡️ Macro-Based Obfuscation

### 1. Procedural Macro para Instruction Shuffling

```rust
// obfuscate_macro/src/lib.rs
use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn};

#[proc_macro_attribute]
pub fn shuffle_instructions(_attr: TokenStream, item: TokenStream) -> TokenStream {
    let input = parse_macro_input!(item as ItemFn);
    
    // Extrair statements do corpo da função
    let stmts = &input.block.stmts;
    
    // Embaralhar (mantendo dependências)
    let shuffled = shuffle_preserving_deps(stmts);
    
    // Reconstruir função
    let sig = &input.sig;
    let vis = &input.vis;
    
    TokenStream::from(quote! {
        #vis #sig {
            #(#shuffled)*
        }
    })
}

// Uso:
#[shuffle_instructions]
pub fn process_aim_data(player: Vec3, enemy: Vec3) -> Vec2 {
    let delta = enemy - player;
    let distance = delta.length();
    let angle = calculate_angle(delta);
    let smoothed = apply_smoothing(angle);
    return smoothed;
}

// Após macro, a ordem das instruções é randomizada (quando possível)
```

### 2. Compile-Time Function Inline/Outline

```rust
/// Forçar inline de função crítica (evita call tracing)
#[inline(always)]
pub fn read_player_position() -> Vec3 {
    // Código será copiado para cada call site
    // Não aparece como função distinta no assembly
    unsafe { *(PLAYER_BASE as *const Vec3) }
}

/// Forçar NO inline para confundir (parecer importante)
#[inline(never)]
pub fn dummy_antidebug_check() -> bool {
    // Parece importante, mas é só noise
    // Anti-cheats podem perder tempo analisando
    xor_shuffle(&[0xDE, 0xAD, 0xBE, 0xEF]) == 0x42
}
```

## 📊 Exemplo Completo: Aimbot Ofuscado

```rust
// Cargo.toml
[dependencies]
goldberg = "0.3"

[profile.release]
opt-level = "z"  # Otimizar para tamanho (mais difícil de analisar)
lto = true
strip = true
panic = "abort"

// src/aimbot.rs
use goldberg::goldberg_obfuscate;

#[goldberg_obfuscate(control_flow, strings, integers)]
#[inline(never)]
pub fn aim_at_enemy(
    player_view: Vec3,
    enemy_head: Vec3,
    smoothing_factor: f32
) -> Vec2 {
    // Strings criptografadas
    let debug_msg = "Aiming at target";
    
    // Integers ofuscados
    const MAX_FOV: f32 = 10.0;  // Vira expressão complexa
    
    // Control flow flattenizado
    let delta = enemy_head - player_view;
    
    if delta.length() > 1000.0 {
        return Vec2::zero();
    }
    
    let raw_angle = calculate_angle(delta);
    let smoothed = raw_angle * smoothing_factor;
    
    return smoothed;
}

// No binário final:
// - Strings são encrypted blobs
// - Constantes são (X ^ Y) + Z - W
// - Fluxo é state machine com 8+ estados
// - Nenhum símbolo de debug
```

## ⚠️ Limitações e Trade-offs

### O Que Compile-Time NÃO Pode Fazer

```diff
- ❌ Mudar código a cada execução (fixo no binário)
- ❌ Reagir a debugging em runtime
- ❌ Esconder comportamento (apenas implementação)
+ ✅ Zero overhead de performance
+ ✅ Dificultar análise estática extremamente
+ ✅ Forçar trabalho manual de engenharia reversa
```

### Quando Usar Cada Tipo

| Cenário | Recomendação |
|---------|--------------|
| **Hot path** (aim calculation 240 FPS) | Compile-time APENAS |
| **Anti-debug checks** | Runtime (adaptive) |
| **String de API keys** | Compile-time encryption |
| **Algoritmo crítico de detecção** | Compile-time + [[Control_Flow_Flattening]] |
| **Proteção de licença** | Runtime + server-side |

## 🔬 Pesquisa 2026

### Goldberg Macro Library
- **Endurance**: Transformações sobrevivem a `-O3` do LLVM
- **Zero overhead**: Confirmado em benchmarks
- **Combinável**: Pode empilhar múltiplas técnicas

### LLVM Obfuscator
O projeto OLLVM (Obfuscator-LLVM) para Rust em 2026 suporta:
- Control Flow Flattening
- Bogus Control Flow (código morto falso)
- Instruction Substitution (trocar ADD por XOR+XOR)
- String Encryption

## 📖 Ver Também
- [[Control_Flow_Flattening]]
- [[Runtime_Code_Generation]]
- [[String Encryption and Obfuscation]]
- [[Code_Virtualization]]

---
<p align="center">REDFLAG © 2026</p>
