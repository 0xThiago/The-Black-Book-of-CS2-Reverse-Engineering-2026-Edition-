# 🔀 Polymorphic Anti Debugging

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #anti-debug #polymorphism #evasion

## 📌 Definição

**Polymorphic Anti-Debugging** combina técnicas tradicionais de anti-debugging com **polimorfismo de código**, gerando checks de debug que mudam sua estrutura a cada build ou execução. Isso dificulta que ferramentas de análise automatizadas identifiquem e desabilitem as proteções.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Polymorphic_Code]]
- [[Runtime_Code_Generation]]
- [[Técnica 047 - Anti-Debugging Techniques]]
- [[ML_Based_Anti_Debugging]]

## 📚 Técnicas Clássicas vs. Polimórficas

### Técnica Clássica (Estática)
```rust
// ❌ DETECTÁVEL: Sempre no mesmo local, mesmo assembly
fn classic_anti_debug() -> bool {
    use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
    unsafe { IsDebuggerPresent().as_bool() }
}
```

### Técnica Polimórfica (Dinâmica)
```rust
// ✅ EVASIVO: Muda a cada build
#[goldberg_obfuscate(control_flow)]
fn polymorphic_anti_debug() -> bool {
    // Gera uma das 5 implementações randomicamente
    match BUILD_VARIANT {
        0 => check_via_isdebuggerpresent(),
        1 => check_via_nt_query_information(),
        2 => check_via_peb_beingdebugged(),
        3 => check_via_hardware_breakpoints(),
        4 => check_via_timing_analysis(),
        _ => unreachable!(),
    }
}

const BUILD_VARIANT: u8 = include!(concat!(env!("OUT_DIR"), "/variant.txt"));
```

## 🛠️ Implementação em Rust (2026)

### 1. Build-Time Polymorphic Generator

```rust
// build.rs
fn main() {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    
    // Escolher variante aleatória
    let variant = rng.gen_range(0..10);
    
    let out_dir = std::env::var("OUT_DIR").unwrap();
    std::fs::write(
        format!("{}/variant.txt", out_dir),
        variant.to_string(),
    ).unwrap();
    
    // Gerar função de anti-debug polimórfica
    let anti_debug_code = generate_anti_debug_variant(variant);
    std::fs::write(
        format!("{}/anti_debug.rs", out_dir),
        anti_debug_code,
    ).unwrap();
}

fn generate_anti_debug_variant(variant: u8) -> String {
    match variant {
        0 => r#"
            pub fn is_debugged() -> bool {
                unsafe { windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent().as_bool() }
            }
        "#.to_string(),
        
        1 => r#"
            pub fn is_debugged() -> bool {
                use windows::Win32::System::Threading::*;
                let mut info: i32 = 0;
                unsafe {
                    NtQueryInformationProcess(
                        GetCurrentProcess(),
                        ProcessDebugPort,
                        &mut info as *mut _ as *mut _,
                        std::mem::size_of::<i32>() as u32,
                        std::ptr::null_mut(),
                    );
                    info != 0
                }
            }
        "#.to_string(),
        
        2 => r#"
            pub fn is_debugged() -> bool {
                unsafe {
                    let peb = __readgsqword(0x60) as * const PEB;
                    (*peb).BeingDebugged != 0
                }
            }
        "#.to_string(),
        
        _ => r#"
            pub fn is_debugged() -> bool {
                // Timing-based detection
                let start = std::time::Instant::now();
                std::hint::black_box(42);
                let elapsed = start.elapsed().as_micros();
                elapsed > 1000  // Debugger causa delay
            }
        "#.to_string(),
    }
}

// src/main.rs
include!(concat!(env!("OUT_DIR"), "/anti_debug.rs"));
```

### 2. Runtime Morphing Anti-Debug

```rust
/// Anti-debug que muda sua implementação durante execução
pub struct MorphingAntiDebug {
    current_method: u8,
    morph_counter: usize,
    morph_interval: usize,
}

impl MorphingAntiDebug {
    pub fn new() -> Self {
        Self {
            current_method: 0,
            morph_counter: 0,
            morph_interval: 1000,  // Mudar a cada 1000 checks
        }
    }
    
    /// Verifica se debugger está presente, morfando implementação
    pub unsafe fn is_debugged(&mut self) -> bool {
        self.morph_counter += 1;
        
        // Mudar método a cada intervalo
        if self.morph_counter >= self.morph_interval {
            self.current_method = (self.current_method + 1) % 10;
            self.morph_counter = 0;
        }
        
        match self.current_method {
            0 => self.check_isdebuggerpresent(),
            1 => self.check_nt_query_info(),
            2 => self.check_peb_flag(),
            3 => self.check_debug_port(),
            4 => self.check_hardware_breakpoints(),
            5 => self.check_software_breakpoints(),
            6 => self.check_timing_attack(),
            7 => self.check_parent_process(),
            8 => self.check_thread_context(),
            9 => self.check_exception_handling(),
            _ => unreachable!(),
        }
    }
    
    unsafe fn check_isdebuggerpresent(&self) -> bool {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    }
    
    unsafe fn check_nt_query_info(&self) -> bool {
        use windows::Win32::System::Threading::*;
        let mut debug_port: usize = 0;
        let status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &mut debug_port as *mut _ as *mut _,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
        status.is_ok() && debug_port != 0
    }
    
    unsafe fn check_peb_flag(&self) -> bool {
        #[cfg(target_arch = "x86_64")]
        {
            let peb = __readgsqword(0x60) as *const PEB;
            (*peb).BeingDebugged != 0
        }
        #[cfg(not(target_arch = "x86_64"))]
        false
    }
    
    unsafe fn check_debug_port(&self) -> bool {
        use windows::Win32::System::Threading::*;
        let mut port: i32 = 0;
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugPort,
            &mut port as *mut _ as *mut _,
            4,
            std::ptr::null_mut(),
        );
        port != 0
    }
    
    unsafe fn check_hardware_breakpoints(&self) -> bool {
        // Verificar registradores DR0-DR7
        use std::arch::asm;
        let dr0: u64;
        let dr1: u64;
        let dr2: u64;
        let dr3: u64;
        
        asm!(
            "mov {}, dr0",
            "mov {}, dr1",
            "mov {}, dr2",
            "mov {}, dr3",
            out(reg) dr0,
            out(reg) dr1,
            out(reg) dr2,
            out(reg) dr3,
        );
        
        (dr0 | dr1 | dr2 | dr3) != 0
    }
    
    unsafe fn check_software_breakpoints(&self) -> bool {
        // Verificar INT3 (0xCC) em código crítico
        let critical_func = is_debugged as *const u8;
        for i in 0..20 {
            if *critical_func.add(i) == 0xCC {
                return true;  // Breakpoint detectado
            }
        }
        false
    }
    
    unsafe fn check_timing_attack(&self) -> bool {
        let start = std::time::Instant::now();
        
        // Operação que deve ser rápida
        for _ in 0..1000 {
            std::hint::black_box(std::ptr::null::<u8>());
        }
        
        let elapsed = start.elapsed().as_micros();
        elapsed > 10000  // Se \u003e 10ms, provável debugger
    }
    
    unsafe fn check_parent_process(&self) -> bool {
        // Verificar se parent é debugger conhecido
        use windows::Win32::System::Threading::*;
        let mut pbi: PROCESS_BASIC_INFORMATION = std::mem::zeroed();
        
        NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessBasicInformation,
            &mut pbi as *mut _ as *mut _,
            std::mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
            std::ptr::null_mut(),
        );
        
        // Verificar se PPID é x64dbg, IDA, etc.
        let parent_pid = pbi.InheritedFromUniqueProcessId as u32;
        is_known_debugger_pid(parent_pid)
    }
    
    unsafe fn check_thread_context(&self) -> bool {
        use windows::Win32::System::Threading::*;
        let mut context: CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        
        GetThreadContext(GetCurrentThread(), &mut context);
        
        // Verificar DR flags
        (context.Dr0 | context.Dr1 | context.Dr2 | context.Dr3) != 0
    }
    
    unsafe fn check_exception_handling(&self) -> bool {
        // Trigger exception e verificar comportamento
        let mut caught = false;
        
        std::panic::catch_unwind(|| {
            std::ptr::write_volatile(0x0 as *mut u8, 0x42);
        }).is_err()
    }
}

#[repr(C)]
struct PEB {
    // Simplified PEB structure
    _reserved1: [u8; 2],
    BeingDebugged: u8,
    // ... outros campos
}

#[repr(C)]
struct PROCESS_BASIC_INFORMATION {
    Reserved1: *mut std::ffi::c_void,
    PebBaseAddress: *mut PEB,
    Reserved2: [*mut std::ffi::c_void; 2],
    UniqueProcessId: usize,
    InheritedFromUniqueProcessId: usize,
}

fn is_known_debugger_pid(pid: u32) -> bool {
    // Verificar contra lista de PIDs conhecidos
    // Implementação simplificada
    false
}
```

## 🎯 Integração com AI (2026)

### AI-Enhanced Polymorphic Detection

Segundo pesquisas de 2026, malware AI-powered pode:
- Gerar código polimórfico automaticamente via LLMs
- Adaptar técnicas de anti-debug baseado em ambiente detectado
- Evoluir autonomamente para bypass novos debuggers

```rust
/// Exemplo conceitual: AI-generated anti-debug
pub struct AIPolymorphicAntiDebug {
    llm_client: LLMClient,
    previous_detections: Vec<DetectionMethod>,
}

impl AIPolymorphicAntiDebug {
    pub async fn generate_next_check(&mut self) -> String {
        let prompt = format!(
            "Gere uma função Rust para detectar debuggers. \
            Métodos já tentados: {:?}. \
            Crie algo novo e não detectável.",
            self.previous_detections
        );
        
        let code = self.llm_client.generate_code(&prompt).await;
        self.compile_and_execute(&code)
    }
}
```

## ⚠️ Contramedidas (Anti-Anti-Debug)

### Como Debuggers Detectam Polimorfismo

1. **Behavioral Analysis**: Mesmo com código diferente, comportamento é similar
2. **API Hooking**: Hook calls conhecidas (`IsDebuggerPresent`, `NtQueryInformationProcess`)
3. **Hardware Virtualization**: Hypervisor-based debuggers (HyperDbg) não são detectáveis por software

### Defesa em Profundidade

```rust
/// Combinar múltiplos métodos + ofuscação
#[goldberg_obfuscate(control_flow)]
pub fn deep_anti_debug() -> bool {
    let mut detector = MorphingAntiDebug::new();
    
    // Combinar 3 checks aleatórios
    let check1 = unsafe { detector.is_debugged() };
    let check2 = timing_based_check();
    let check3 = seh_based_check();
    
    // Majority vote
    [check1, check2, check3].iter().filter(|&&x| x).count() >= 2
}
```

## 📊 Efetividade (2026)

| Técnica | Detecção por x64dbg | Detecção por HyperDbg | Overhead |
|---------|---------------------|----------------------|----------|
| **IsDebuggerPresent** | 🔴 Trivial | 🔴 Trivial | 0% |
| **Polymorphic (build)** | 🟡 Médio | 🔴 Fácil | 0% |
| **Morphing (runtime)** | 🟢 Difícil | 🟡 Médio | 2-5% |
| **AI-generated** | 🟢 Muito difícil | 🟡 Médio | Variável |

## 📖 Ver Também
- [[Context_Aware_Anti_Debugging]]
- [[ML_Based_Anti_Debugging]]
- [[Runtime_Code_Generation]]
- [[Polymorphic_Code]]

## 🔬 Pesquisa 2026

- **Medium/SASA Software**: AI-enhanced polymorphic malware pode autonomamente evoluir técnicas de evasão
- **SentinelOne**: Foco em análise comportamental, não signatures, para counter polimorfismo
- **Out flank**: HVCI (Hypervisor-protected Code Integrity) torna kernel read-execute only, dificultando muito bypass

---
<p align="center">REDFLAG © 2026</p>
