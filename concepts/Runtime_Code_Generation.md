# 🔄 Runtime Code Generation

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #evasion #runtime #dynamic-code

## 📌 Definição

**Runtime Code Generation (RCG)** é uma técnica avançada de evasão onde código malicioso é gerado ou modificado **dinamicamente durante a execução** do programa. Diferente de ofuscação estática, o código não existe em forma analisável no disco, sendo criado na memória apenas quando necessário.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Code_Virtualization]]
- [[JIT_Compilation]]
- [[Polymorphic_Code]]
- [[Metamorphic_Code_Generation]]
- [[Encrypted_Memory_Management]]

## 📚 Por Que RCG é Efetivo em 2026

### Evolução dos Anti-Cheats
Anti-cheats modernos como VAC Live, BattlEye e VACnet 4.x focam em:
1. **Análise estática** de binários (assinaturas, hashes)
2. **Scanning de memória** em busca de padrões conhecidos
3. **Behavioral analysis** via Machine Learning

RCG contorna **todos os três**:
- ❌ Não há binário fixo para assinar
- ❌ Código em memória muda constantemente
- ✅ Comportamento pode ser humanizado dinamicamente

## 🛠️ Técnicas de Implementação (2026)

### 1. Dynamic Obfuscation & Polymorphism

```rust
use rand::Rng;

/// Engine de geração dinâmica de código para evasão
pub struct DynamicCodeEngine {
    code_variants: Vec<fn() -> bool>,
    current_variant: usize,
}

impl DynamicCodeEngine {
    /// Gera uma nova variante do código a cada chamada
    /// 
    /// # Camada 1: SINTAXE
    /// Utilizamos um enum de instruções para representar opcodes customizados
    /// que são traduzidos para código nativo em runtime
    /// 
    /// # Camada 2: MEMÓRIA
    /// O código gerado reside em páginas RWX (Read-Write-Execute) temporárias
    /// alocadas via VirtualAlloc com proteção PAGE_EXECUTE_READWRITE
    /// 
    /// # Camada 3: SEGURANÇA & OWNERSHIP
    /// Rust força que gerenciemos o lifetime das páginas executáveis
    /// Usamos RAII para garantir que páginas sejam liberadas (VirtualFree)
    pub fn generate_variant(&mut self) -> Result<Vec<u8>, String> {
        let mut rng = rand::thread_rng();
        let variant_type = rng.gen_range(0..3);
        
        match variant_type {
            0 => self.generate_add_variant(),
            1 => self.generate_xor_variant(),
            2 => self.generate_sub_variant(),
            _ => unreachable!(),
        }
    }
    
    /// Variante 1: Implementa verificação como adição
    fn generate_add_variant(&self) -> Result<Vec<u8>, String> {
        // Gera código x86-64 dinamicamente
        // Exemplo: verificar se jogador está perto do inimigo
        Ok(vec![
            0x48, 0x8B, 0x45, 0x10,  // mov rax, [rbp+0x10]  ; player_x
            0x48, 0x8B, 0x4D, 0x18,  // mov rcx, [rbp+0x18]  ; enemy_x
            0x48, 0x29, 0xC8,        // sub rax, rcx         ; delta
            0x48, 0x3D, 0x64, 0x00, 0x00, 0x00,  // cmp rax, 100
            0x0F, 0x9C, 0xC0,        // setl al             ; return al
            0xC3,                    // ret
        ])
    }
    
    /// Variante 2: Mesma lógica via XOR
    fn generate_xor_variant(&self) -> Result<Vec<u8>, String> {
        // Lógica equivalente porém estrutura de assembly diferente
        Ok(vec![
            0x48, 0x8B, 0x55, 0x10,  // mov rdx, [rbp+0x10]
            0x48, 0x8B, 0x45, 0x18,  // mov rax, [rbp+0x18]
            0x48, 0x31, 0xD0,        // xor rax, rdx         ; diferente!
            0x48, 0x83, 0xF8, 0x64,  // cmp rax, 100
            0x0F, 0x9C, 0xC0,        // setl al
            0xC3,                    // ret
        ])
    }
    
    /// Variante 3: Via subtração invertida
    fn generate_sub_variant(&self) -> Result<Vec<u8>, String> {
        Ok(vec![
            0x48, 0x8B, 0x4D, 0x18,  // mov rcx, [rbp+0x18]  ; ordem invertida
            0x48, 0x8B, 0x45, 0x10,  // mov rax, [rbp+0x10]
            0x48, 0x2B, 0xC1,        // sub rax, rcx
            0x48, 0xF7, 0xD8,        // neg rax              ; negar resultado
            0x48, 0x3D, 0x64, 0x00, 0x00, 0x00,  // cmp rax, 100
            0x0F, 0x9C, 0xC0,        // setl al
            0xC3,                    // ret
        ])
    }
}
```

### 2. Memory Allocation Safe Wrapper

```rust
use windows::Win32::System::Memory::*;
use std::ptr::null_mut;

/// Wrapper RAII para páginas executáveis
pub struct ExecutablePage {
    address: *mut u8,
    size: usize,
}

impl ExecutablePage {
    /// Aloca página RWX para código gerado
    /// 
    /// ⚠️ RISCO DE ESTABILIDADE
    /// Páginas RWX são monitoradas por anti-cheats modernos
    /// Use técnicas de split permissions (RW→RX) para evitar detecção
    pub unsafe fn new(size: usize) -> Result<Self, String> {
        let address = VirtualAlloc(
            Some(null_mut()),
            size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );
        
        if address.is_null() {
            return Err("Failed to allocate executable memory".to_string());
        }
        
        Ok(Self {
            address: address as *mut u8,
            size,
        })
    }
    
    /// Escreve código gerado na página
    pub unsafe fn write_code(&mut self, code: &[u8]) -> Result<(), String> {
        if code.len() > self.size {
            return Err("Code exceeds page size".to_string());
        }
        
        std::ptr::copy_nonoverlapping(
            code.as_ptr(),
            self.address,
            code.len(),
        );
        
        Ok(())
    }
    
    /// Executa código gerado (casting para function pointer)
    pub unsafe fn execute<R>(&self) -> R {
        let func: fn() -> R = std::mem::transmute(self.address);
        func()
    }
}

impl Drop for ExecutablePage {
    /// RAII: Garantir liberação de memória
    fn drop(&mut self) {
        unsafe {
            VirtualFree(self.address as *mut _, 0, MEM_RELEASE);
        }
    }
}
```

### 3. JIT-Style Code Morphing

```rust
/// Sistema de "mutação" de código a cada frame do jogo
pub struct MorphingAimbot {
    engine: DynamicCodeEngine,
    last_morph: std::time::Instant,
    morph_interval: std::time::Duration,
}

impl MorphingAimbot {
    pub fn new() -> Self {
        Self {
            engine: DynamicCodeEngine::default(),
            last_morph: std::time::Instant::now(),
            morph_interval: std::time::Duration::from_secs(5), // Mutar a cada 5s
        }
    }
    
    /// Verifica se deve mirar, gerando novo código se necessário
    pub unsafe fn should_aim(&mut self, player_pos: (f32, f32), enemy_pos: (f32, f32)) -> bool {
        // Re-gerar código a cada intervalo
        if self.last_morph.elapsed() > self.morph_interval {
            let new_code = self.engine.generate_variant().unwrap();
            
            // Alocar nova página executável
            let mut page = ExecutablePage::new(4096).unwrap();
            page.write_code(&new_code).unwrap();
            
            self.last_morph = std::time::Instant::now();
            
            // Executar código gerado
            return page.execute();
        }
        
        // Fallback para código estático (menos seguro)
        let dx = player_pos.0 - enemy_pos.0;
        let dy = player_pos.1 - enemy_pos.1;
        (dx * dx + dy * dy).sqrt() < 100.0
    }
}
```

## 🎯 Aplicações em CS2 (2026)

### Caso 1: Aimbot Polimórfico
**Problema**: Signaturas estáticas de aimbot são detectadas instantaneamente  
**Solução**: Gerar nova implementação de cálculo de ângulo a cada execução

```rust
pub fn polymorphic_angle_calc() {
    // Versão 1 (Segunda-feira)
    let angle = atan2(delta_y, delta_x);
    
    // Versão 2 (Terça-feira) - gerada em runtime
    let angle = {
        let hyp = sqrt(delta_x.powi(2) + delta_y.powi(2));
        asin(delta_y / hyp)
    };
    
    // Versão 3 (Quarta-feira) - completamente diferente
    // ... gerada via lookup table + interpolação
}
```

### Caso 2: Triggerbot com Lógica Variável
**Problema**: Padrão de "disparar instantaneamente ao ver inimigo" é detectável  
**Solução**: RCG muda condições e delays aleatoriamente

```rust
// Gerado em runtime: às vezes checa HP, às vezes distância, às vezes ambos
if randomly_generated_condition(enemy) {
    sleep(randomly_generated_delay());  // 0-200ms
    fire();
}
```

## ⚠️ Detecção e Contramedidas (2026)

### Como Anti-Cheats Detectam RCG

```
1. Monitoramento de VirtualAlloc (RWX pages)
   ├─ Solução: Alocar como RW, escrever código, mudar para RX
   └─ API: VirtualProtect(PAGE_EXECUTE_READ)

2. Scanning de páginas executáveis sem módulos associados
   ├─ Solução: "Assinar" páginas como pertencentes a DLL legítima
   └─ Técnica: Memory section hijacking

3. Análise de call stacks anômalos
   ├─ Solução: Return-oriented programming (ROP) para disfarçar origem
   └─ Técnica: Stack spoofing

4. Behavioral: Código que "muda demais"
   ├─ Solução: Limitar frequência de morphing (máx 1x/minuto)
   └─ Técnica: Selective morphing (apenas funções críticas)
```

### Bypass Moderno (2026)

> [!TIP]
> **Split Permissions Pattern**: Nunca mantenha páginas como RWX permanentemente
> ```rust
> // 1. Alocar como RW
> let page = VirtualAlloc(null_mut(), size, MEM_COMMIT, PAGE_READWRITE);
> // 2. Escrever código
> write_generated_code(page);
> // 3. Mudar para RX
> VirtualProtect(page, size, PAGE_EXECUTE_READ, &mut old_protect);
> // 4. Executar (sem permissão de write)
> execute_code(page);
> ```

## 📊 Efetividade vs. Overhead

| Aspecto | Impacto |
|---------|---------|
| **Detecção Estática** | 🟢 Impossível (código não existe no disco) |
| **Detecção Comportamental** | 🟡 Médio (padrões ainda existem) |
| **Performance** | 🟠 Overhead de 5-15% (geração + execução) |
| **Complexidade** | 🔴 Alta (requer conhecimento de assembly) |
| **Manutenção** | 🔴 Difícil (debugging complexo) |

## 📖 Ver Também
- [[JIT_Compilation]]
- [[Compile_Time_Obfuscation]]
- [[Memory_Obfuscation_Engine]]
- [[Encrypted_Memory_Management]]
- [[Polymorphic_Code]]

## 🔬 Pesquisa 2026

Segundo análises recentes de fóruns especializados:
- **Promon.io** documenta que ofuscação dinâmica com código que "move, muta e auto-repara" em runtime representa um "alvo móvel" difícil de atacar, mesmo para sistemas AI-driven
- **Zimperium** confirma que código polimórfico força anti-cheats a criar novas estratégias para cada build
- **Emergent Mind** reporta que JIT exploitation continua sendo um vetor de ataque confiável e rápido

---
<p align="center">REDFLAG © 2026</p>
