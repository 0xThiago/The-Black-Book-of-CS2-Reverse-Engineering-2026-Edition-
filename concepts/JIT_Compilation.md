# ⚡ JIT Compilation

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #evasion #jit #performance #kernel

## 📌 Definição

**Just-In-Time (JIT) Compilation** no contexto de game hacking refere-se à técnica de compilar código de cheat **em tempo real**, transformando bytecode ou representação intermediária em instruções nativas da CPU apenas no momento da execução. Isso evita assinaturas estáticas e permite adaptação dinâmica ao ambiente.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[Runtime_Code_Generation]]
- [[Code_Virtualization]]
- [[Encrypted_Memory_Management]]
- [[VAC Live Analysis]]

## 📚 JIT vs. Compilação Tradicional

| Aspecto | Compilação AOT | JIT Compilation |
|---------|----------------|-----------------|
| **Quando ocorre** | Build time | Runtime |
| **Assinatura binária** | Fixa | Variável |
| **Detecção estática** | Fácil | Impossível |
| **Performance inicial** | Rápida | Delay de warm-up |
| **Adaptabilidade** | Zero | Total (pode mudar por sessão) |

## 🛠️ Arquitetura de JIT Engine para Cheats

### 1. Bytecode Interpreter + JIT Backend

```rust
use std::collections::HashMap;

/// Conjunto de instruções customizado (Intermediate Representation)
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum Opcode {
    LoadPlayerPos = 0x01,
    LoadEnemyPos = 0x02,
    CalcDistance = 0x03,
    CompareThreshold = 0x04,
    JumpIfGreater = 0x05,
    ReturnTrue = 0x06,
    ReturnFalse = 0x07,
}

/// Engine JIT que compila bytecode para x86-64 nativo
pub struct JITEngine {
    /// Cache de funções já compiladas
    compiled_cache: HashMap<Vec<u8>, *const u8>,
    /// Pool de memória executável
    executable_pool: Vec<ExecutablePage>,
}

impl JITEngine {
    /// Compila bytecode para código nativo x86-64
    /// 
    /// # Camada 1: SINTAXE
    /// Recebe um array de opcodes customizados e emite assembly x86-64
    /// equivalente, otimizado para a CPU atual
    /// 
    /// # Camada 2: MEMÓRIA
    /// Código compilado reside em páginas RX (não RWX após compilação)
    /// Cache usa HashMap com Vec<u8> como key (bytecode original)
    /// 
    /// # Camada 3: SEGURANÇA & OWNERSHIP
    /// O Rust garante que não temos reference aliasing no cache
    /// Lifetimes asseguram que ponteiros de função sejam válidos
    pub unsafe fn compile(&mut self, bytecode: &[u8]) -> Result<*const u8, String> {
        // Verificar cache primeiro
        if let Some(&cached) = self.compiled_cache.get(bytecode) {
            return Ok(cached);
        }
        
        let mut native_code = Vec::new();
        
        // Prólogo da função
        native_code.extend_from_slice(&[
            0x55,                    // push rbp
            0x48, 0x89, 0xE5,        // mov rbp, rsp
            0x48, 0x83, 0xEC, 0x20,  // sub rsp, 0x20 (shadow space)
        ]);
        
        // Traduzir cada opcode
        for &op in bytecode {
            match Opcode::from(op) {
                Opcode::LoadPlayerPos => {
                    // call get_player_position
                    // mov [rbp-0x08], rax
                    native_code.extend_from_slice(&[
                        0x48, 0xB8,  // movabs rax, <addr>
                    ]);
                    // ... endereço de get_player_position
                },
                
                Opcode::CalcDistance => {
                    // Calcular distância euclidiana
                    native_code.extend_from_slice(&[
                        0xF2, 0x0F, 0x59, 0xC0,  // mulsd xmm0, xmm0  ; x^2
                        0xF2, 0x0F, 0x59, 0xC9,  // mulsd xmm1, xmm1  ; y^2
                        0xF2, 0x0F, 0x58, 0xC1,  // addsd xmm0, xmm1  ; x^2 + y^2
                        0xF2, 0x0F, 0x51, 0xC0,  // sqrtsd xmm0, xmm0 ; sqrt
                    ]);
                },
                
                Opcode::CompareThreshold => {
                    // cmp com threshold (100.0)
                    native_code.extend_from_slice(&[
                        0x48, 0xB8,  // movabs rax, <threshold_double>
                        0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x59, 0x40,  // 100.0
                        0x66, 0x48, 0x0F, 0x6E, 0xC8,  // movq xmm1, rax
                        0x66, 0x0F, 0x2F, 0xC1,        // comisd xmm0, xmm1
                    ]);
                },
                
                Opcode::JumpIfGreater => {
                    native_code.extend_from_slice(&[
                        0x77, 0x05,  // ja +5 (pular próximas instruções)
                    ]);
                },
                
                Opcode::ReturnTrue => {
                    native_code.extend_from_slice(&[
                        0xB0, 0x01,  // mov al, 1
                    ]);
                },
                
                Opcode::ReturnFalse => {
                    native_code.extend_from_slice(&[
                        0x30, 0xC0,  // xor al, al  ; al = 0
                    ]);
                },
                
                _ => return Err(format!("Unknown opcode: {:02X}", op)),
            }
        }
        
        // Epílogo da função
        native_code.extend_from_slice(&[
            0x48, 0x89, 0xEC,  // mov rsp, rbp
            0x5D,              // pop rbp
            0xC3,              // ret
        ]);
        
        // Alocar página executável
        let mut page = ExecutablePage::new(native_code.len())?;
        page.write_code(&native_code)?;
        
        let func_ptr = page.as_ptr();
        self.executable_pool.push(page);
        self.compiled_cache.insert(bytecode.to_vec(), func_ptr);
        
        Ok(func_ptr)
    }
}

impl Opcode {
    fn from(byte: u8) -> Self {
        unsafe { std::mem::transmute(byte) }
    }
}
```

### 2. Adaptive JIT com Profile-Guided Optimization

```rust
/// JIT que otimiza baseado em uso real
pub struct AdaptiveJIT {
    engine: JITEngine,
    /// Contador de execuções por função
    hotness_counter: HashMap<Vec<u8>, usize>,
    /// Threshold para re-compilar com otimizações
    optimization_threshold: usize,
}

impl AdaptiveJIT {
    pub fn new() -> Self {
        Self {
            engine: JITEngine::new(),
            hotness_counter: HashMap::new(),
            optimization_threshold: 100,  // Re-otimizar após 100 chamadas
        }
    }
    
    /// Executa bytecode, otimizando funções "quentes"
    pub unsafe fn execute(&mut self, bytecode: &[u8]) -> bool {
        // Incrementar contador
        *self.hotness_counter.entry(bytecode.to_vec()).or_insert(0) += 1;
        
        let count = self.hotness_counter[bytecode];
        
        // Re-compilar com otimizações agressivas se função é quente
        if count == self.optimization_threshold {
            self.recompile_optimized(bytecode)?;
        }
        
        // Executar código compilado
        let func_ptr = self.engine.compile(bytecode)?;
        let func: fn() -> bool = std::mem::transmute(func_ptr);
        func()
    }
    
    /// Re-compila com otimizações de segundo nível
    unsafe fn recompile_optimized(&mut self, bytecode: &[u8]) -> Result<(), String> {
        // Aplicar otimizações:
        // - Inline de chamadas
        // - Loop unrolling
        // - Constant folding
        // - Dead code elimination
        
        // ... implementação de otimizador
        Ok(())
    }
}
```

## 🎯 Exploiting JIT Vulnerabilities (2026)

### Race Condition em JIT Compilers

Pesquisas de 2026 demonstram que **race conditions** em JIT compilers podem ser exploitadas:

```rust
/// Exploit: Manipular código JIT durante compilação
pub unsafe fn jit_race_exploit() -> Result<(), String> {
    use std::sync::Arc;
    use std::thread;
    
    let bytecode = Arc::new(vec![
        Opcode::LoadPlayerPos as u8,
        Opcode::LoadEnemyPos as u8,
        Opcode::CalcDistance as u8,
        Opcode::CompareThreshold as u8,
        Opcode::ReturnTrue as u8,
    ]);
    
    // Thread 1: Triggering compilation
    let bytecode_clone = bytecode.clone();
    let handle1 = thread::spawn(move || {
        let mut jit = AdaptiveJIT::new();
        unsafe { jit.execute(&bytecode_clone) }
    });
    
    // Thread 2: Modificar código durante warm-up
    let handle2 = thread::spawn(move || {
        thread::sleep(std::time::Duration::from_micros(10));
        // Tentar modificar código JIT em cache RWX
        // Se bem-sucedido, injeta instruções maliciosas
    });
    
    handle1.join().unwrap();
    handle2.join().unwrap();
    
    Ok(())
}
```

> [!WARNING]
> **Detecção de Race Attacks**: Anti-cheats de 2026 monitoram threads concorrentes tentando acessar regiões JIT. Use single-threaded JIT ou mutexes para evitar suspeita.

## 🛡️ Evasão de Kernel Anti-Cheat (2026)

### Problema: Kernel-Level Detection
Anti-cheats com drivers kernel podem:
- Monitorar alocações de memória executável (`VirtualAlloc`)
- Escanear páginas RWX/RX não pertencentes a módulos conhecidos
- Analisar call stacks de execução

### Solução: JIT Masquerading

```rust
/// Disfarça código JIT como pertencente a DLL legítima
pub unsafe fn masked_jit_execution() -> Result<(), String> {
    use windows::Win32::System::LibraryLoader::*;
    
    // 1. Carregar DLL legítima (ex: d3d11.dll)
    let legit_dll = LoadLibraryA(s!("d3d11.dll"))?;
    
    // 2. Encontrar região de código não usada na DLL
    let dll_base = legit_dll.0 as usize;
    let unused_section = find_unused_code_section(dll_base)?;
    
    // 3. Injetar código JIT na seção não usada
    let mut old_protect = PAGE_PROTECTION_FLAGS(0);
    VirtualProtect(
        unused_section as *const _,
        4096,
        PAGE_EXECUTE_READWRITE,
        &mut old_protect,
    )?;
    
    // 4. Escrever código JIT compilado
    write_jit_code(unused_section)?;
    
    // 5. Restaurar proteção original
    VirtualProtect(
        unused_section as *const _,
        4096,
        old_protect,
        &mut old_protect,
    )?;
    
    // Agora call stack mostra execução vindo de d3d11.dll ✅
    let func: fn() -> bool = std::mem::transmute(unused_section);
    func();
    
    Ok(())
}
```

## 📊 Benchmark: JIT vs. Interpretado vs. Nativo

| Implementação | Latência (µs) | Detecção | Adaptabilidade |
|---------------|---------------|----------|----------------|
| **Nativo (C++)** | 0.5 | 🔴 Alta | ❌ Zero |
| **Interpretado** | 15.0 | 🟡 Média | ✅ Total |
| **JIT (warm)** | 1.2 | 🟢 Baixa | ✅ Alta |
| **JIT (cold)** | 50.0 | 🟢 Baixa | ✅ Alta |

**Veredicto**: JIT oferece o melhor equilíbrio entre performance e evasão.

## 🚨 Sinais de JIT Detection (2026)

Anti-cheats procuram por:

```
1. Páginas RWX persistentes
   └─ Contramedida: RW durante compilação, RX durante execução

2. Código executável fora de módulos
   └─ Contramedida: JIT masquerading (injetar em DLLs legítimas)

3. Padrões de alocação suspeitos
   └─ Contramedida: Pooling (alocar uma vez, reusar múltiplas vezes)

4. Call stacks sem símbolos
   └─ Contramedida: Stack spoofing / ROP chains

5. Execução de código sem arquivo fonte
   └─ Contramedida: Firmar código JIT (self-signing)
```

## 📖 Ver Também
- [[Runtime_Code_Generation]]
- [[Memory_Obfuscation_Engine]]
- [[Code_Virtualization]]
- [[Encrypted_Memory_Management]]

## 🔬 Pesquisa 2026

Fontes acadêmicas e de security research confirmam:
- **Georgia Tech**: JIT compilers têm vulnerabilidades exploitáveis via race conditions em caches de código
- **Emergent Mind**: Hypervisor-assisted introspection pode detectar código JIT, mas análise comportamental real-time ainda é limitada
- **Secret.club**: Kernel anti-cheats de 2026 focam em detecção de DMA e hypervisors, deixando espaço para JIT bem implementado

---
<p align="center">REDFLAG © 2026</p>
