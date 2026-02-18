# 🧠 Context Aware Anti Debugging

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #anti-debug #adaptive #context

## 📌 Definição

**Context-Aware Anti-Debugging** são técnicas que adaptam seu comportamento baseado no **contexto de execução** detectado. Ao invés de simplesmente detectar e abortar, essas técnicas analisam o ambiente e decidem a melhor resposta: continuar normalmente, executar código honeypot, ou crashar seletivamente.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Polymorphic_Anti_Debugging]]
- [[ML_Based_Anti_Debugging]]
- [[Dynamic_Behavior_Analysis]]
- [[Context_Aware_Detection]]

## 📚 Níveis de Context Awareness

### Nível 1: Detecção Binária (Clássico)
```rust
// ❌ SIMPLES: Apenas sabe se está debugado ou não
if is_debugged() {
    exit(1);  // Abortar
}
```

### Nível 2: Contexto Básico
```rust
// 🟡 MELHOR: Entende tipo de debugger
match detect_debugger_type() {
    DebuggerType::UserMode(name) => fake_execution(),
    DebuggerType::KernelMode => crash_gracefully(),
    DebuggerType::Hypervisor => /* Não há escape */ {},
    DebuggerType::None => normal_execution(),
}
```

### Nível 3: Context-Aware Completo (2026)
```rust
// ✅ AVANÇADO: Decisão baseada em múltiplos fatores
let context = ExecutionContext::analyze();

match context.threat_level() {
    ThreatLevel::Low => {
        // Análise estática, não executando
        // Fornecer código honeypot que parece real
        execute_decoy_logic();
    },
    ThreatLevel::Medium => {
        // Debugger user-mode ativo
        // Executar com funcionalidades limitadas
        execute_limited_cheat(disable_aimbot: true);
    },
    ThreatLevel::High => {
        // Kernel debugger ou anti-cheat ativo
        // Self-delete e crash
        secure_wipe();
        crash();
    },
    ThreatLevel::Critical => {
        // Honeypot/Sandbox detectado
        // Executar comportamento benigno perfeito
        behave_like_legitimate_software();
    },
}
```

## 🛠️ Implementação em Rust (2026)

### 1. Análise de Contexto Multidimensional

```rust
use std::collections::HashMap;

/// Estrutura que captura contexto completo de execução
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Presença de debugger
    pub debugger_present: bool,
    /// Tipo de debugger detectado
    pub debugger_type: Option<DebuggerType>,
    /// Análise de timing (delays anormais)
    pub timing_anomaly: bool,
    /// Verificação de hooks em APIs críticas
    pub api_hooks_detected: Vec<String>,
    /// Processos suspeitos rodando
    pub suspicious_processes: Vec<String>,
    /// Está rodando em VM?
    pub virtual_machine: bool,
    /// Está em sandbox?
    pub sandbox_detected: bool,
    /// Hardware info (HWID)
    pub hardware_id: String,
    /// Geolocalização
    pub country_code: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum DebuggerType {
    UserMode(String),    // x64dbg, OllyDbg, IDA
    KernelMode(String),  // WinDbg Kernel, SoftICE
    Hypervisor(String),  // HyperDbg, QEMU/KVM
}

impl ExecutionContext {
    /// Analisa contexto completo do ambiente
    pub unsafe fn analyze() -> Self {
        Self {
            debugger_present: Self::check_debugger(),
            debugger_type: Self::identify_debugger(),
            timing_anomaly: Self::check_timing(),
            api_hooks_detected: Self::scan_hooks(),
            suspicious_processes: Self::enum_processes(),
            virtual_machine: Self::detect_vm(),
            sandbox_detected: Self::detect_sandbox(),
            hardware_id: Self::get_hwid(),
            country_code: Self::get_geolocation(),
        }
    }
    
    /// Calcula nível de ameaça baseado em contexto
    pub fn threat_level(&self) -> ThreatLevel {
        let mut score = 0;
        
        // Debugger presente
        if self.debugger_present {
            score += match &self.debugger_type {
                Some(DebuggerType::UserMode(_)) => 30,
                Some(DebuggerType::KernelMode(_)) => 50,
                Some(DebuggerType::Hypervisor(_)) => 70,
                None => 20,
            };
        }
        
        // Timing anomaly
        if self.timing_anomaly {
            score += 20;
        }
        
        // API hooks
        score += (self.api_hooks_detected.len() * 10) as u32;
        
        // VM detection
        if self.virtual_machine {
            score += 40;
        }
        
        // Sandbox
        if self.sandbox_detected {
            score += 60;  // Provável análise automatizada
        }
        
        // Avaliar score
        match score {
            0..=20 => ThreatLevel::Low,
            21..=50 => ThreatLevel::Medium,
            51..=80 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }
    
    unsafe fn check_debugger() -> bool {
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        IsDebuggerPresent().as_bool()
    }
    
    unsafe fn identify_debugger() -> Option<DebuggerType> {
        // Verificar janelas de debuggers conhecidos
        use windows::Win32::UI::WindowsAndMessaging::FindWindowA;
        
        let debuggers = [
            ("Qt5QWindowIcon", "x64dbg"),
            ("OLLYDBG", "OllyDbg"),
            ("ID", "IDA Pro"),
            ("WinDbgFrameClass", "WinDbg"),
        ];
        
        for (class, name) in &debuggers {
            let window = FindWindowA(
                windows::core::PCSTR(class.as_ptr()),
                windows::core::PCSTR::null(),
            );
            if !window.is_invalid() {
                return Some(DebuggerType::UserMode(name.to_string()));
            }
        }
        
        // Verificar kernel debugger
        if Self::check_kernel_debugger() {
            return Some(DebuggerType::KernelMode("Unknown".to_string()));
        }
        
        None
    }
    
    unsafe fn check_kernel_debugger() -> bool {
        use windows::Win32::System::SystemInformation::*;
        
        let mut info: SYSTEM_KERNEL_DEBUGGER_INFORMATION = std::mem::zeroed();
        let status = NtQuerySystemInformation(
            SystemKernelDebuggerInformation,
            &mut info as *mut _ as *mut _,
            std::mem::size_of_val(&info) as u32,
            std::ptr::null_mut(),
        );
        
        status.is_ok() && info.KernelDebuggerEnabled != 0
    }
    
    unsafe fn check_timing() -> bool {
        let iterations = 1000;
        let mut timings = Vec::with_capacity(iterations);
        
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            std::hint::black_box(42);  // Operação trivial
            let elapsed = start.elapsed().as_nanos();
            timings.push(elapsed);
        }
        
        // Calcular média e desvio padrão
        let mean = timings.iter().sum::<u128>() / timings.len() as u128;
        let variance: u128 = timings.iter()
            .map(|&x| {
                let diff = (x as i128) - (mean as i128);
                (diff * diff) as u128
            })
            .sum::<u128>() / timings.len() as u128;
        let std_dev = (variance as f64).sqrt();
        
        // Se desvio padrão muito alto, provável debugger
        std_dev > (mean as f64 * 2.0)
    }
    
    unsafe fn scan_hooks() -> Vec<String> {
        let mut hooked_apis = Vec::new();
        
        // APIs críticas para verificar
        let critical_apis = [
            ("kernel32.dll", "CreateFileA"),
            ("ntdll.dll", "NtReadVirtualMemory"),
            ("user32.dll", "SetWindowsHookExA"),
        ];
        
        for (dll, func) in &critical_apis {
            if Self::is_api_hooked(dll, func) {
                hooked_apis.push(format!("{}!{}", dll, func));
            }
        }
        
        hooked_apis
    }
    
    unsafe fn is_api_hooked(dll: &str, func: &str) -> bool {
        use windows::Win32::System::LibraryLoader::*;
        
        let dll_cstr = std::ffi::CString::new(dll).unwrap();
        let func_cstr = std::ffi::CString::new(func).unwrap();
        
        let module = GetModuleHandleA(windows::core::PCSTR(dll_cstr.as_ptr() as *const u8));
        if module.is_err() {
            return false;
        }
        
        let addr = GetProcAddress(module.unwrap(), windows::core::PCSTR(func_cstr.as_ptr() as *const u8));
        if addr.is_none() {
            return false;
        }
        
        let func_ptr = addr.unwrap() as *const u8;
        
        // Verificar primeiros bytes (comum hook coloca JMP)
        let first_bytes = std::slice::from_raw_parts(func_ptr, 5);
        
        // JMP absoluto: E9 XX XX XX XX
        // JMP relativo: EB XX
        // PUSH + RET: 68 XX XX XX XX C3
        first_bytes[0] == 0xE9 || first_bytes[0] == 0xEB || first_bytes[0] == 0x68
    }
    
    unsafe fn enum_processes() -> Vec<String> {
        use windows::Win32::System::ProcessStatus::*;
        
        let mut processes = Vec::new();
        let mut pids = vec![0u32; 1024];
        let mut bytes_returned = 0u32;
        
        EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut bytes_returned,
        );
        
        // Lista de processos suspeitos
        let suspicious = [
            "x64dbg.exe", "x32dbg.exe", "ollydbg.exe", 
            "ida.exe", "ida64.exe", "windbg.exe",
            "processhacker.exe", "procexp.exe", "wireshark.exe"
        ];
        
        // Verificar (implementação simplificada)
        // Na prática, precisaria abrir cada processo e ler o nome
        processes
    }
    
    unsafe fn detect_vm() -> bool {
        // Verificar artefatos de VM
        
        // 1. CPUID - Hypervisor bit
        let cpuid_result = std::arch::x86_64::__cpuid(1);
        let hypervisor_bit = (cpuid_result.ecx >> 31) & 1;
        
        if hypervisor_bit == 1 {
            return true;
        }
        
        // 2. Verificar strings de VM em registry
        // 3. Verificar MAC addresses de VMs conhecidas
        // 4. Verificar artifacts de VMware/VirtualBox
        
        false
    }
    
    unsafe fn detect_sandbox() -> bool {
        // Verificações comuns de sandbox
        
        // 1. Número de processadores \u003c 2
        let num_cpus = num_cpus::get();
        if num_cpus \u003c 2 {
            return true;
        }
        
        // 2. RAM total \u003c 4GB
        use windows::Win32::System::SystemInformation::*;
        let mut memstatus: MEMORYSTATUSEX = std::mem::zeroed();
        memstatus.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut memstatus);
        
        let total_ram_gb = memstatus.ullTotalPhys / (1024 * 1024 * 1024);
        if total_ram_gb \u003c 4 {
            return true;
        }
        
        // 3. Tempo de uptime muito baixo
        let uptime_ms = GetTickCount64();
        if uptime_ms \u003c 600_000 {  // \u003c 10 minutos
            return true;
        }
        
        false
    }
    
    unsafe fn get_hwid() -> String {
        // Gerar hardware ID único
        use windows::Win32::System::SystemInformation::*;
        
        let mut computer_name = vec![0u16; 256];
        let mut size = computer_name.len() as u32;
        GetComputerNameW(&mut computer_name, &mut size);
        
        String::from_utf16_lossy(&computer_name[..size as usize])
    }
    
    unsafe fn get_geolocation() -> Option<String> {
        // Via IP geolocation API (simplificado)
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[repr(C)]
struct SYSTEM_KERNEL_DEBUGGER_INFORMATION {
    KernelDebuggerEnabled: u8,
    KernelDebuggerNotPresent: u8,
}
```

### 2. Resposta Adaptativa

```rust
/// Engine de resposta baseado em contexto
pub struct AdaptiveResponse {
    context: ExecutionContext,
}

impl AdaptiveResponse {
    pub fn new() -> Self {
        Self {
            context: unsafe { ExecutionContext::analyze() },
        }
    }
    
    /// Decide ação apropriada para o contexto
    pub fn respond(&self) -> ResponseAction {
        match self.context.threat_level() {
            ThreatLevel::Low => ResponseAction::Normal,
            
            ThreatLevel::Medium => {
                // Análise em progresso, executar decoy
                ResponseAction::Decoy {
                    disable_features: vec!["aimbot", "esp"],
                    fake_data: true,
                }
            },
            
            ThreatLevel::High => {
                // Debugger ativo, crashar gracefully
                ResponseAction::Crash {
                    secure_wipe: true,
                    fake_error: "Access violation at 0x00000000",
                }
            },
            
            ThreatLevel::Critical => {
                // Sandbox/Honeypot, comportamento benigno
                ResponseAction::Honeypot {
                    fake_legitimate_behavior: true,
                    report_fake_telemetry: true,
                }
            },
        }
    }
}

#[derive(Debug)]
pub enum ResponseAction {
    Normal,
    Decoy {
        disable_features: Vec<&'static str>,
        fake_data: bool,
    },
    Crash {
        secure_wipe: bool,
        fake_error: &'static str,
    },
    Honeypot {
        fake_legitimate_behavior: bool,
        report_fake_telemetry: bool,
    },
}
```

## 🎯 Aplicação em CS2

```rust
/// Integração com cheat de CS2
pub fn initialize_cheat() -> Result<(), String> {
    let response = AdaptiveResponse::new();
    
    match response.respond() {
        ResponseAction::Normal => {
            // Ambiente seguro, carregar cheat completo
            load_full_cheat()?;
        },
        
        ResponseAction::Decoy { disable_features, .. } => {
            // Carregar apenas features seguras
            load_limited_cheat(&disable_features)?;
        },
        
        ResponseAction::Crash { secure_wipe, fake_error } => {
            if secure_wipe {
                secure_delete_files()?;
            }
            panic!("{}", fake_error);
        },
        
        ResponseAction::Honeypot { .. } => {
            // Simular software legítimo
            behave_like_overlay_app()?;
        },
    }
    
    Ok(())
}
```

## 📊 Efetividade vs. Overhead

| Aspecto | Clássico | Context-Aware |
|---------|----------|---------------|
| **Detecção** | Binária | Multi-fatorial |
| **Resposta** | Abort | Adaptativa |
| **Evasão** | Baixa | Alta |
| **Overhead** | \u003c1% | 3-5% (inicial) |

## 📖 Ver Também
- [[Polymorphic_Anti_Debugging]]
- [[ML_Based_Anti_Debugging]]
- [[Dynamic_Behavior_Analysis]]

---
<p align="center">REDFLAG © 2026</p>
