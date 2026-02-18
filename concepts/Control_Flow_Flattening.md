# 🌀 Control Flow Flattening

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #obfuscation #anti-analysis #rust

## 📌 Definição

**Control Flow Flattening (CFF)** é uma técnica de ofuscação que transforma o fluxo de controle de um programa em uma **state machine**, substituindo estruturas condicionais e loops aninhados por um dispatcher central com switch statement. Isso torna a análise estática extremamente difícil, pois o grafo de fluxo de controle original é destruído.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Code_Virtualization]]
- [[Metamorphic_Code_Generation]]
- [[Compile_Time_Obfuscation]]
- [[Técnica 049 - Anti-Reverse Engineering Techniques]]

## 📚 Como Funciona

### Código Original (Fluxo Linear)
```rust
fn check_enemy_visible(player: Vec3, enemy: Vec3) -> bool {
    let distance = (player - enemy).length();
    
    if distance > 500.0 {
        return false;
    }
    
    if !line_of_sight(player, enemy) {
        return false;
    }
    
    return true;
}
```

### Código Flattenizado (State Machine)
```rust
fn check_enemy_visible_obfuscated(player: Vec3, enemy: Vec3) -> bool {
    let mut state: u32 = 0x3A2F1B;  // Estado inicial randômico
    let mut distance = 0.0f32;
    let mut result = false;
    
    loop {
        match state {
            0x3A2F1B => {  // Bloco 1: Calcular distância
                distance = (player - enemy).length();
                state = 0x9C4E82;  // Próximo estado
            },
            
            0x9C4E82 => {  // Bloco 2: Verificar distância
                if distance > 500.0 {
                    state = 0x1F7A3D;  // Jump para return false
                } else {
                    state = 0x5B8C91;  // Jump para próximo check
                }
            },
            
            0x5B8C91 => {  // Bloco 3: Line of sight
                if !line_of_sight(player, enemy) {
                    state = 0x1F7A3D;  // return false
                } else {
                    state = 0x6D2E4F;  // return true
                }
            },
            
            0x1F7A3D => {  // Return false
                result = false;
                break;
            },
            
            0x6D2E4F => {  // Return true
                result = true;
                break;
            },
            
            _ => unreachable!(),
        }
    }
    
    result
}
```

**Efeito**: Um dissasembler vê apenas um `loop` gigante com `match` sem padrão claro de fluxo.

## 🛠️ Implementação em Rust (2026)

### 1. CFF com Goldberg Procedural Macro

```rust
// Cargo.toml
// [dependencies]
// goldberg = "0.3"

use goldberg::goldberg_obfuscate;

/// Aimbot com controle de fluxo ofuscado
#[goldberg_obfuscate(control_flow)]
pub fn calculate_aim_angle(player_view: Vec3, enemy_head: Vec3) -> Vec2 {
    let delta = enemy_head - player_view;
    let hyp = (delta.x * delta.x + delta.y * delta.y).sqrt();
    
    let pitch = -(delta.z / hyp).atan() * 180.0 / std::f32::consts::PI;
    let yaw = delta.y.atan2(delta.x) * 180.0 / std::f32::consts::PI;
    
    Vec2::new(pitch, yaw)
}

// Código gerado após compilação:
// - Cada linha de código vira um "basic block"
// - Blocks são embaralhados e conectados via dispatcher
// - Estado inicial é randomizado a cada build
```

### 2. Manual CFF Generator

```rust
/// Gerador de state machine a partir de AST
pub struct CFlatteningEngine {
    /// Mapa de blocos básicos para estados
    block_states: HashMap<usize, u32>,
    /// Seed para randomização de estados
    seed: u64,
}

impl CFlatteningEngine {
    /// Cria uma nova engine com seed aleatória
    pub fn new() -> Self {
        use std::time::SystemTime;
        let seed = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            block_states: HashMap::new(),
            seed,
        }
    }
    
    /// Transforma função em state machine
    /// 
    /// # Camada 1: SINTAXE
    /// Recebe código como entrada, extrai basic blocks,
    /// e gera switch statement com estados randomizados
    /// 
    /// # Camada 2: MEMÓRIA
    /// A variável `state` reside na stack (local variable)
    /// Cada transição é um simples move/assignment (rápido)
    /// 
    /// # Camada 3: SEGURANÇA & OWNERSHIP
    /// O Rust garante que não há race conditions no state
    /// Mutable borrow exclusivo de `state` por thread
    pub fn flatten(&mut self, blocks: Vec<BasicBlock>) -> FlattenedFunction {
        let mut flattened = FlattenedFunction::new();
        
        // Gerar estado único para cada bloco
        for (idx, block) in blocks.iter().enumerate() {
            let state = self.generate_state(idx);
            self.block_states.insert(idx, state);
        }
        
        // Criar dispatcher loop
        flattened.add_state_variable();
        flattened.add_loop_start();
        
        for (idx, block) in blocks.iter().enumerate() {
            let curr_state = self.block_states[&idx];
            let next_state = if idx + 1 < blocks.len() {
                Some(self.block_states[&(idx + 1)])
            } else {
                None  // Estado final
            };
            
            flattened.add_case(curr_state, block.code.clone(), next_state);
        }
        
        flattened.add_loop_end();
        flattened
    }
    
    /// Gera estado randomizado mas determinístico
    fn generate_state(&self, block_idx: usize) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.seed.hash(&mut hasher);
        block_idx.hash(&mut hasher);
        
        (hasher.finish() & 0xFFFFFFFF) as u32
    }
}

#[derive(Clone)]
pub struct BasicBlock {
    pub code: String,
}

pub struct FlattenedFunction {
    pub code: String,
}

impl FlattenedFunction {
    fn new() -> Self {
        Self { code: String::new() }
    }
    
    fn add_state_variable(&mut self) {
        self.code.push_str("let mut state: u32 = INITIAL_STATE;\n");
    }
    
    fn add_loop_start(&mut self) {
        self.code.push_str("loop {\n    match state {\n");
    }
    
    fn add_case(&mut self, state: u32, code: String, next_state: Option<u32>) {
        self.code.push_str(&format!("        0x{:08X} => {{\n", state));
        self.code.push_str(&format!("            {}\n", code));
        if let Some(next) = next_state {
            self.code.push_str(&format!("            state = 0x{:08X};\n", next));
        } else {
            self.code.push_str("            break;\n");
        }
        self.code.push_str("        },\n");
    }
    
    fn add_loop_end(&mut self) {
        self.code.push_str("        _ => unreachable!(),\n");
        self.code.push_str("    }\n}\n");
    }
}
```

## 🎯 Aplicação em CS2

### Triggerbot com CFF

```rust
#[goldberg_obfuscate(control_flow)]
pub fn should_fire(crosshair: Vec2, enemy_bbox: BoundingBox) -> bool {
    // Código original simples
    if !crosshair_in_bbox(crosshair, enemy_bbox) {
        return false;
    }
    
    let reaction_delay = humanize_reaction_time();
    sleep(reaction_delay);
    
    return can_see_enemy();
}

// Após ofuscação, se torna:
// - 15+ estados diferentes
// - Switch com condições embaralhadas
// - Dificulta análise de "quando dispara"
```

## ⚠️ Deobfuscation e Contramedidas (2026)

### Como Reverters Atacam CFF

**Binary Ninja Plugin**: Ferramentas de 2026 conseguem detectar CFF automaticamente:
1. Identificam o dispatcher (loop + switch)
2. Extraem a variável de estado
3. Constroem grafo de transições
4. Reconstroem CFG original via graph theory

### Defesa: Opaque Predicates

```rust
/// Adicionar transições falsas que nunca são tomadas
fn generate_opaque_transitions() -> Vec<(u32, u32)> {
    vec![
        (0x3A2F1B, 0xDEADBEEF),  // Falsa transição
        (0x9C4E82, 0xCAFEBABE),  // Nunca alcançada
    ]
}

// No match, adicionar:
match state {
    0x3A2F1B => {
        // ...código real...
        
        // Opaque predicate (sempre falso)
        if (ptr as usize) % 2 == 3 {  // Impossível!
            state = 0xDEADBEEF;  // Confunde ferramentas
        } else {
            state = 0x9C4E82;
        }
    },
    // ...
}
```

### Defesa: Dynamic State Calculation

```rust
/// Estados calculados em runtime (não constantes)
fn calculate_next_state(current: u32, input: &[u8]) -> u32 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    
    let mut hasher = DefaultHasher::new();
    current.hash(&mut hasher);
    input.hash(&mut hasher);
    
    (hasher.finish() & 0xFFFFFFFF) as u32
}

// Uso:
match state {
    s if s == calculate_next_state(prev_state, b"block1") => {
        // Agora ferramentas não podem mapear estados estaticamente!
    },
}
```

## 📊 Impacto vs. Performance

| Métrica | Original | CFF | CFF + Opaques |
|---------|----------|-----|---------------|
| **Tamanho do binário** | 100% | 150% | 200% |
| **Execução (latência)** | 1.0x | 1.05x | 1.15x |
| **Análise estática** | ✅ Fácil | ❌ Difícil | ❌ Muito difícil |
| **Deobfuscação automatizada** | N/A | 🟡 Possível | 🔴 Difícil |

**Overhead aceitável**: 5-15% para código não-critical path

> [!CAUTION]
> **Não use CFF em hot paths** como cálculo de ângulo de aimbot executado 240 vezes por segundo. CFF é ideal para:
> - Inicialização do cheat
> - Leitura de configuração
> - Verificações de anti-debug
> - Lógica de licenciamento

## 🔬 Pesquisa 2026

### Ferramentas Rust para CFF

**Goldberg** (github.com):
- Procedural macro para code-flow obfuscation
- String literal encryption
- Sobrevive a otimizações do compilador LLVM
- Uso: `#[goldberg_obfuscate(control_flow)]`

**rust-obfuscator**:
- Manipulação direta de source code
- Control-flow flattening automática
- Integração com build.rs

### Estado da Arte em Deobfuscation

**Sophos Research** (2026) mostra que:
- CFF básico é quebrado por análise de grafo
- CFF + opaque predicates + dynamic states = 85% mais difícil
- Combinação com [[Code_Virtualization]] é quase inquebrável

## 📖 Ver Também
- [[Code_Virtualization]]
- [[Compile_Time_Obfuscation]]
- [[Metamorphic_Code_Generation]]
- [[Runtime_Code_Generation]]

---
<p align="center">REDFLAG © 2026</p>
