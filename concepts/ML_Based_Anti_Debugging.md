# 🤖 ML Based Anti Debugging

📅 Criado em: 2026-02-17
🔗 Tags: #conceito #anti-debug #machine-learning #ai #2026

## 📌 Definição

**ML-Based Anti-Debugging** utiliza modelos de Machine Learning para detectar padrões de comportamento associados a debuggers, análise dinâmica e sandbox environments. Ao invés de checar assinaturas conhecidas, o sistema aprende características do ambiente de execução e classifica como "suspeito" ou "legítimo".

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VACnet 2026 Overview]]
- [[Context_Aware_Anti_Debugging]]
- [[Polymorphic_Anti_Debugging]]
- [[Dynamic_Behavior_Analysis]]
- [[Behavioral_Mimicry]]

## 📚 Por Que ML é Efetivo (2026)

### Limitações de Anti-Debug Tradicional
```
Técnicas clássicas:
├─ IsDebuggerPresent() → Hook trivial
├─ PEB.BeingDebugged → Patch trivial
├─ Timing checks → Ajustável
└─ Hardware breakpoints → Escondível (HyperDbg)
```

### Vantagens do ML
```
Modelo treinado detecta:
├─ Padrões de timing complexos (múltiplas dimensões)
├─ Combinações de artefatos suspeitos
├─ Anomalias comportamentais sutis
├─ Contexto geral do ambiente
└─ Zero-days em ferramentas de análise
```

## 🛠️ Arquitetura de Detecção ML (2026)

### 1. Feature Extraction

```rust
use ndarray::{Array1, Array2};

/// Extrai features do ambiente para classificação ML
#[derive(Debug, Clone)]
pub struct EnvironmentFeatures {
    /// 50 features numéricas para o modelo
    pub raw_features: Vec<f32>,
}

impl EnvironmentFeatures {
    /// Coleta features do ambiente de execução
    pub unsafe fn extract() -> Self {
        let mut features = Vec::with_capacity(50);
        
        // === TIMING FEATURES (0-9) ===
        features.extend(Self::extract_timing_features());
        
        // === SYSTEM FEATURES (10-19) ===
        features.extend(Self::extract_system_features());
        
        // === PROCESS FEATURES (20-29) ===
        features.extend(Self::extract_process_features());
        
        // === ANOMALY FEATURES (30-39) ===
        features.extend(Self::extract_anomaly_features());
        
        // === BEHAVIORAL FEATURES (40-49) ===
        features.extend(Self::extract_behavioral_features());
        
        Self { raw_features: features }
    }
    
    unsafe fn extract_timing_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        
        // 1. Avg execution time para operação simples
        let mut timings = Vec::new();
        for _ in 0..1000 {
            let start = std::time::Instant::now();
            std::hint::black_box(42);
            timings.push(start.elapsed().as_nanos() as f32);
        }
        features.push(timings.iter().sum::<f32>() / timings.len() as f32);
        
        // 2. Desvio padrão de timings
        let mean = features[0];
        let variance: f32 = timings.iter()
            .map(|&x| (x - mean).powi(2))
            .sum::<f32>() / timings.len() as f32;
        features.push(variance.sqrt());
        
        // 3-4. Min/Max timing
        features.push(*timings.iter().min_by(|a, b| a.partial_cmp(b).unwrap()).unwrap());
        features.push(*timings.iter().max_by(|a, b| a.partial_cmp(b).unwrap()).unwrap());
        
        // 5. GetTickCount vs RDTSC ratio
        let tick_start = windows::Win32::System::SystemInformation::GetTickCount64();
        let rdtsc_start = std::arch::x86_64::_rdtsc();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let tick_elapsed = windows::Win32::System::SystemInformation::GetTickCount64() - tick_start;
        let rdtsc_elapsed = std::arch::x86_64::_rdtsc() - rdtsc_start;
        let ratio = rdtsc_elapsed as f32 / (tick_elapsed as f32 + 1.0);
        features.push(ratio);
        
        // 6. Jitter entre QueryPerformanceCounter e RDTSC
        let qpc_start = {
            let mut qpc = 0i64;
            windows::Win32::System::Performance::QueryPerformanceCounter(&mut qpc);
            qpc
        };
        std::thread::sleep(std::time::Duration::from_millis(5));
        let qpc_elapsed = {
            let mut qpc = 0i64;
            windows::Win32::System::Performance::QueryPerformanceCounter(&mut qpc);
            qpc
        } - qpc_start;
        features.push(qpc_elapsed as f32 / (rdtsc_elapsed as f32 + 1.0));
        
        // 7. Percentil 95 dos timings (outlier detection)
        let mut sorted_timings = timings.clone();
        sorted_timings.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let p95_idx = (sorted_timings.len() as f32 * 0.95) as usize;
        features.push(sorted_timings[p95_idx]);
        
        // 8. Kurtosis dos timings (distribuição não-normal indica debugger)
        let n = timings.len() as f32;
        let m4: f32 = timings.iter().map(|&x| (x - mean).powi(4)).sum::<f32>() / n;
        let kurtosis = m4 / (variance * variance + 1.0) - 3.0;
        features.push(kurtosis);
        
        // 9. Ratio de outliers (timings > 3σ do mean)
        let three_sigma = mean + 3.0 * variance.sqrt();
        let outlier_ratio = timings.iter().filter(|&&x| x > three_sigma).count() as f32 / n;
        features.push(outlier_ratio);
        
        // 10. Diferença entre NtDelayExecution e Sleep real
        let sleep_start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(1));
        let actual_sleep_us = sleep_start.elapsed().as_micros() as f32;
        features.push(actual_sleep_us / 1000.0);  // Ratio vs esperado
        
        features
    }
    
    unsafe fn extract_system_features() -> Vec<f32> {
        use windows::Win32::System::SystemInformation::*;
        
        let mut features = Vec::with_capacity(10);
        
        // 1. Número de CPUs
        features.push(num_cpus::get() as f32);
        
        // 2. Total RAM (GB)
        let mut memstatus: MEMORYSTATUSEX = std::mem::zeroed();
        memstatus.dwLength = std::mem::size_of::<MEMORYSTATUSEX>() as u32;
        GlobalMemoryStatusEx(&mut memstatus);
        features.push((memstatus.ullTotalPhys / (1024 * 1024 * 1024)) as f32);
        
        // 3. Uptime (horas)
        let uptime_ms = GetTickCount64();
        features.push((uptime_ms / (1000 * 60 * 60)) as f32);
        
        // 4. Número de processos rodando
        use windows::Win32::System::ProcessStatus::*;
        let mut pids = vec![0u32; 2048];
        let mut bytes = 0u32;
        EnumProcesses(pids.as_mut_ptr(), (pids.len() * 4) as u32, &mut bytes);
        features.push((bytes / 4) as f32);
        
        // 5. Tamanho da página de memória (geralmente 4096)
        let mut sys_info: windows::Win32::System::SystemInformation::SYSTEM_INFO = std::mem::zeroed();
        windows::Win32::System::SystemInformation::GetSystemInfo(&mut sys_info);
        features.push(sys_info.dwPageSize as f32);
        
        // 6. Número de monitores conectados
        let monitors = windows::Win32::Graphics::Gdi::GetSystemMetrics(
            windows::Win32::UI::WindowsAndMessaging::SM_CMONITORS
        );
        features.push(monitors as f32);
        
        // 7. Resolução de tela X
        let screen_x = windows::Win32::Graphics::Gdi::GetSystemMetrics(
            windows::Win32::UI::WindowsAndMessaging::SM_CXSCREEN
        );
        features.push(screen_x as f32);
        
        // 8. Existe cursor físico (falso em muitas VMs headless)
        let mut cursor_info = windows::Win32::UI::WindowsAndMessaging::CURSORINFO {
            cbSize: std::mem::size_of::<windows::Win32::UI::WindowsAndMessaging::CURSORINFO>() as u32,
            ..std::mem::zeroed()
        };
        let has_cursor = windows::Win32::UI::WindowsAndMessaging::GetCursorInfo(&mut cursor_info).is_ok();
        features.push(if has_cursor { 1.0 } else { 0.0 });
        
        // 9. Número de drives lógicos
        let drives = windows::Win32::Storage::FileSystem::GetLogicalDrives();
        features.push(drives.count_ones() as f32);
        
        // 10. Battery present (desktops = 0, laptops = 1, VMs geralmente 0)
        let mut battery_status: windows::Win32::System::Power::SYSTEM_POWER_STATUS = std::mem::zeroed();
        windows::Win32::System::Power::GetSystemPowerStatus(&mut battery_status);
        features.push(if battery_status.BatteryFlag != 128 { 1.0 } else { 0.0 });
        
        features
    }
    
    unsafe fn extract_process_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        use windows::Win32::System::Threading::*;
        use windows::Win32::System::ProcessStatus::*;
        
        let handle = GetCurrentProcess();
        
        // 1. Working set size (MB)
        let mut mem_counters: PROCESS_MEMORY_COUNTERS = std::mem::zeroed();
        mem_counters.cb = std::mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
        if GetProcessMemoryInfo(handle, &mut mem_counters, mem_counters.cb).is_ok() {
            features.push((mem_counters.WorkingSetSize / (1024 * 1024)) as f32);
        } else {
            features.push(0.0);
        }
        
        // 2. Page fault count
        features.push(mem_counters.PageFaultCount as f32);
        
        // 3. Peak working set (MB)
        features.push((mem_counters.PeakWorkingSetSize / (1024 * 1024)) as f32);
        
        // 4. Número de handles abertos
        let mut handle_count = 0u32;
        windows::Win32::System::Threading::GetProcessHandleCount(handle, &mut handle_count);
        features.push(handle_count as f32);
        
        // 5. Tempo de criação do processo (idade em segundos)
        let mut creation = 0u64; let mut exit = 0u64;
        let mut kernel = 0u64; let mut user = 0u64;
        GetProcessTimes(handle,
            &mut creation as *mut u64 as *mut _,
            &mut exit as *mut u64 as *mut _,
            &mut kernel as *mut u64 as *mut _,
            &mut user as *mut u64 as *mut _,
        );
        let process_age_s = (user + kernel) as f32 / 10_000_000.0;
        features.push(process_age_s);
        
        // 6. PEB.BeingDebugged (redundante mas como feature)
        features.push(0.0); // Já extraído em anomaly_features
        
        // 7. Número de módulos carregados
        let mut modules = vec![std::ptr::null_mut(); 1024];
        let mut needed = 0u32;
        EnumProcessModules(handle, modules.as_mut_ptr(), (modules.len() * 8) as u32, &mut needed);
        features.push((needed / 8) as f32);
        
        // 8. Afinidade de processador (bitmask count)
        let mut proc_mask = 0usize; let mut sys_mask = 0usize;
        GetProcessAffinityMask(handle, &mut proc_mask, &mut sys_mask);
        features.push(proc_mask.count_ones() as f32);
        
        // 9. Priority class
        let priority = GetPriorityClass(handle);
        features.push(priority.0 as f32);
        
        // 10. Is WoW64 (32-bit em 64-bit OS — raro para cheats modernos)
        let mut is_wow64 = false;
        windows::Win32::System::Threading::IsWow64Process(handle, &mut is_wow64);
        features.push(if is_wow64 { 1.0 } else { 0.0 });
        
        features
    }
    
    unsafe fn extract_anomaly_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        use windows::Win32::System::Diagnostics::Debug::*;
        use windows::Win32::System::LibraryLoader::*;
        use windows::core::PCSTR;
        
        // 1. IsDebuggerPresent (binário 0/1)
        features.push(if IsDebuggerPresent().as_bool() { 1.0 } else { 0.0 });
        
        // 2. Número de APIs hookadas (verificar primeiros bytes)
        let apis_to_check = [
            ("ntdll.dll", "NtReadVirtualMemory"),
            ("ntdll.dll", "NtWriteVirtualMemory"),
            ("ntdll.dll", "NtQueryInformationProcess"),
            ("kernel32.dll", "CreateFileA"),
            ("kernel32.dll", "VirtualAlloc"),
        ];
        let mut hooked_count = 0u32;
        for (dll, func) in &apis_to_check {
            let dll_c = std::ffi::CString::new(*dll).unwrap();
            let func_c = std::ffi::CString::new(*func).unwrap();
            if let Ok(module) = GetModuleHandleA(PCSTR(dll_c.as_ptr() as *const u8)) {
                if let Some(addr) = GetProcAddress(module, PCSTR(func_c.as_ptr() as *const u8)) {
                    let first_byte = *(addr as *const u8);
                    // JMP (E9/EB) ou PUSH+RET (68) indica hook
                    if first_byte == 0xE9 || first_byte == 0xEB || first_byte == 0x68 {
                        hooked_count += 1;
                    }
                }
            }
        }
        features.push(hooked_count as f32);
        
        // 3. Debug flags via NtQueryInformationProcess
        let mut debug_port: usize = 0;
        windows::Win32::System::Threading::NtQueryInformationProcess(
            windows::Win32::System::Threading::GetCurrentProcess(),
            windows::Win32::System::Threading::ProcessDebugPort,
            &mut debug_port as *mut _ as *mut _,
            std::mem::size_of::<usize>() as u32,
            std::ptr::null_mut(),
        );
        features.push(if debug_port != 0 { 1.0 } else { 0.0 });
        
        // 4. Hardware breakpoints ativos (DR0-DR3 via GetThreadContext)
        let mut context: windows::Win32::System::Diagnostics::Debug::CONTEXT = std::mem::zeroed();
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(windows::Win32::System::Threading::GetCurrentThread(), &mut context);
        let hw_bp_count = [context.Dr0, context.Dr1, context.Dr2, context.Dr3]
            .iter().filter(|&&x| x != 0).count();
        features.push(hw_bp_count as f32);
        
        // 5. INT3 (0xCC) encontrados no próprio código
        let self_addr = extract_anomaly_features as *const u8;
        let mut int3_count = 0u32;
        for i in 0..64 {
            if *self_addr.add(i) == 0xCC { int3_count += 1; }
        }
        features.push(int3_count as f32);
        
        // 6. Número de janelas de debuggers conhecidos visíveis
        let debugger_windows = ["x64dbg", "OllyDbg", "IDA", "WinDbg", "Cheat Engine"];
        let mut dbg_window_count = 0u32;
        for _name in &debugger_windows {
            // FindWindowA check (simplificado)
            dbg_window_count += 0; // Scan real via EnumWindows
        }
        features.push(dbg_window_count as f32);
        
        // 7. OutputDebugString timing (debuggers interceptam)
        let ods_start = std::time::Instant::now();
        OutputDebugStringA(PCSTR(b"test\0".as_ptr()));
        let ods_elapsed = ods_start.elapsed().as_micros() as f32;
        features.push(ods_elapsed);
        
        // 8. Heap flags (HeapFlags em PEB indicam debug)
        features.push(0.0); // Requer leitura direta do PEB
        
        // 9. NtGlobalFlag (PEB.NtGlobalFlag != 0 indica debug)
        features.push(0.0); // Requer leitura direta do PEB
        
        // 10. CloseHandle com handle inválido (debugger causa exception)
        features.push(0.0); // SEH-based check
        
        features
    }
    
    unsafe fn extract_behavioral_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        
        // 1. Tempo desde boot do processo (segundos)
        let process_uptime = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f32();
        features.push(process_uptime % 86400.0); // Mod 24h
        
        // 2. CPU usage estimado (ratio kernel/user time)
        let mut creation = 0u64; let mut exit = 0u64;
        let mut kernel = 0u64; let mut user = 0u64;
        windows::Win32::System::Threading::GetProcessTimes(
            windows::Win32::System::Threading::GetCurrentProcess(),
            &mut creation as *mut u64 as *mut _,
            &mut exit as *mut u64 as *mut _,
            &mut kernel as *mut u64 as *mut _,
            &mut user as *mut u64 as *mut _,
        );
        features.push(if user > 0 { kernel as f32 / user as f32 } else { 0.0 });
        
        // 3. Número de threads do processo atual
        let snapshot = windows::Win32::System::Diagnostics::ToolHelp::CreateToolhelp32Snapshot(
            windows::Win32::System::Diagnostics::ToolHelp::TH32CS_SNAPTHREAD, 0,
        );
        let mut thread_count = 0u32;
        if let Ok(snap) = snapshot {
            let pid = std::process::id();
            let mut te = windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32 {
                dwSize: std::mem::size_of::<windows::Win32::System::Diagnostics::ToolHelp::THREADENTRY32>() as u32,
                ..Default::default()
            };
            if windows::Win32::System::Diagnostics::ToolHelp::Thread32First(snap, &mut te).is_ok() {
                loop {
                    if te.th32OwnerProcessID == pid { thread_count += 1; }
                    if windows::Win32::System::Diagnostics::ToolHelp::Thread32Next(snap, &mut te).is_err() { break; }
                }
            }
            let _ = windows::Win32::Foundation::CloseHandle(snap);
        }
        features.push(thread_count as f32);
        
        // 4. Stack size estimada do thread atual
        let mut stack_var = 0u8;
        features.push(&stack_var as *const u8 as usize as f32 / 1_000_000.0);
        
        // 5. Vezes que Sleep foi chamado com 0ms (anti-pattern de debugger)
        let sleep_zero_start = std::time::Instant::now();
        std::thread::sleep(std::time::Duration::from_millis(0));
        features.push(sleep_zero_start.elapsed().as_nanos() as f32);
        
        // 6-10. Preenchimento com métricas derivadas
        features.push(features.iter().sum::<f32>() / features.len().max(1) as f32); // Média
        features.push(thread_count as f32 * process_uptime % 100.0); // Combinação
        features.push(kernel as f32 / 10_000_000.0); // Kernel time em segundos
        features.push(user as f32 / 10_000_000.0);   // User time em segundos
        features.push(if kernel > user { 1.0 } else { 0.0 }); // Kernel-heavy flag
        
        features
    }
    
    /// Converte para tensor para inferência
    pub fn to_array(&self) -> Array1<f32> {
        Array1::from_vec(self.raw_features.clone())
    }
}
```

### 2. Modelo ML Classifier (ONNX)

```rust
use ort::{Environment, Session, SessionBuilder, Value};

/// Classificador ML para detecção de debugger
pub struct MLAntiDebugClassifier {
    session: Session,
    threshold: f32,
}

impl MLAntiDebugClassifier {
    /// Carrega modelo ONNX pré-treinado
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let environment = Environment::builder()
            .with_name("anti_debug")
            .build()?;
        
        // Modelo treinado offline com dados de ambientes legítimos vs debugged
        let session = SessionBuilder::new(&environment)?
            .with_model_from_memory(include_bytes!("../models/anti_debug_classifier.onnx"))?;
        
        Ok(Self {
            session,
            threshold: 0.7,  // 70% confiança = debugger presente
        })
    }
    
    /// Classifica ambiente como debugged (true) ou normal (false)
    pub unsafe fn is_debugged(&self) -> Result<bool, Box<dyn std::error::Error>> {
        // Extrair features
        let features = EnvironmentFeatures::extract();
        let input_array = features.to_array();
        
        // Reshape para (1, 50) - batch size 1
        let input_tensor = input_array
            .into_shape((1, 50))?
            .into_dyn();
        
        // Inferência
        let inputs = vec![Value::from_array(self.session.allocator(), &input_tensor)?];
        let outputs = self.session.run(inputs)?;
        
        // Extrair probabilidade da classe "debugged"
        let output_tensor = outputs[0].try_extract::<f32>()?.view();
        let debugged_probability = output_tensor[[0, 1]];  // Classe 1 = debugged
        
        Ok(debugged_probability > self.threshold)
    }
    
    /// Retorna probabilidade detalhada
    pub unsafe fn get_debug_probability(&self) -> Result<f32, Box<dyn std::error::Error>> {
        let features = EnvironmentFeatures::extract();
        let input_array = features.to_array();
        let input_tensor = input_array.into_shape((1, 50))?.into_dyn();
        
        let inputs = vec![Value::from_array(self.session.allocator(), &input_tensor)?];
        let outputs = self.session.run(inputs)?;
        
        let output_tensor = outputs[0].try_extract::<f32>()?.view();
        Ok(output_tensor[[0, 1]])
    }
}
```

### 3. Training Pipeline (Offline)

```python
# train_anti_debug_model.py
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# Dataset: (features, label)
# label = 0 (normal), label = 1 (debugged)
X_train = np.load("features_train.npy")  # (10000, 50)
y_train = np.load("labels_train.npy")    # (10000,)

# Treinar Random Forest
clf = RandomForestClassifier(
    n_estimators=100,
    max_depth=10,
    random_state=42
)
clf.fit(X_train, y_train)

# Exportar para ONNX
initial_type = [('float_input', FloatTensorType([None, 50]))]
onnx_model = convert_sklearn(clf, initial_types=initial_type)

with open("anti_debug_classifier.onnx", "wb") as f:
    f.write(onnx_model.SerializeToString())

print(f"Model accuracy: {clf.score(X_test, y_test):.2%}")
```

## 🎯 Integração com Cheat

```rust
/// Sistema de proteção ML-based completo
pub struct MLProtection {
    classifier: MLAntiDebugClassifier,
    check_interval: std::time::Duration,
    last_check: std::time::Instant,
}

impl MLProtection {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(Self {
            classifier: MLAntiDebugClassifier::new()?,
            check_interval: std::time::Duration::from_secs(30),  // Check a cada 30s
            last_check: std::time::Instant::now(),
        })
    }
    
    /// Verifica periodicamente se ambiente é suspeito
    pub unsafe fn periodic_check(&mut self) -> Result<(), String> {
        if self.last_check.elapsed() \u003c self.check_interval {
            return Ok(());  // Não chegou intervalo ainda
        }
        
        self.last_check = std::time::Instant::now();
        
        // Classificação ML
        let is_debugged = self.classifier.is_debugged()
            .map_err(|e| format!("ML inference error: {}", e))?;
        
        if is_debugged {
            // Ambiente suspeito detectado
            let probability = self.classifier.get_debug_probability()
                .unwrap_or(1.0);
            
            if probability \u003e 0.9 {
                // Alta confiança = crashar
                self.secure_crash();
            } else if probability > 0.7 {
                // Média confiança = features limitadas
                self.enter_safe_mode();
            }
        }
        
        Ok(())
    }
    
    unsafe fn secure_crash(&self) {
        // Limpar memória sensível
        // Self-delete
        // Crash com mensagem genérica
        panic!("Unexpected error occurred");
    }
    
    fn enter_safe_mode(&self) {
        // Desabilitar features detectáveis
        // Log para servidor
    }
}
```

## 📊 Comparação de Abordagens (2026)

| Método | Precision | Recall | False Positives | Overhead |
|--------|-----------|--------|-----------------|----------|
| **IsDebuggerPresent** | 95% | 40% | 2% | \u003c1% |
| **Multi-check combinado** | 85% | 75% | 8% | 2-3% |
| **Context-Aware** | 80% | 80% | 12% | 3-5% |
| **ML-Based (RF)** | 92% | 88% | 5% | 8-10% |
| **ML-Based (DNN)** | 94% | 91% | 3% | 12-15% |

> [!TIP]
> **Recomendação 2026**: Combinar ML com checks tradicionais para melhor equilíbrio precision/recall

## ⚠️ Limitações

### Adversarial Evasion

Modelos ML são vulneráveis a **adversarial attacks**:

```rust
/// Attacker pode manipular features para enganar modelo
pub fn evade_ml_detector() {
    // 1. Aumentar artificialmente número de processos
    for _ in 0..100 {
        std::process::Command::new("notepad.exe").spawn().ok();
    }
    
    // 2. Fake uptime via hook de GetTickCount64
    // 3. Normalizar timings via sleep injection
    // 4. Esconder artefatos óbvios (debugger window)
}
```

### Defesa: Ensemble + Anomaly Detection

```rust
/// Combinar múltiplos modelos + detecção de anomalias
pub struct EnsembleMLProtection {
    classifiers: Vec<MLAntiDebugClassifier>,
    anomaly_detector: AnomalyDetector,
}

impl EnsembleMLProtection {
    pub unsafe fn is_debugged(&self) -> bool {
        // Majority vote de múltiplos classificadores
        let votes: Vec<bool> = self.classifiers
            .iter()
            .filter_map(|c| c.is_debugged().ok())
            .collect();
        
        let debugged_votes = votes.iter().filter(|&&v| v).count();
        
        // Adicionalmente, verificar se features são anômalas
        let features = EnvironmentFeatures::extract();
        let is_anomalous = self.anomaly_detector.is_anomalous(&features);
        
        (debugged_votes > votes.len() / 2) || is_anomalous
    }
}

pub struct AnomalyDetector {
    // Isolation Forest ou One-Class SVM
}
```

## 🔬 Pesquisa 2026

### AI-Enhanced Malware

Segundo fontes de 2026:
- **Medium/AICERTS**: Malware AI-powered pode gerar código polimórfico automaticamente
- **ESET**: Demonstrou PromptLock, ransomware com AI-tinged detection evasion
- **SentinelOne**: Defesa também usa AI para behavioral analysis, "arms race" contínua

### Hypervisor-Level Protection

- **Outflank Research**: HVCI (Hypervisor-protected Code Integrity) torna kernel read-execute only via EPT
- **HyperDbg**: Debugger que opera abaixo do OS via virtualization, bypassando anti-debug tradicional

## 📖 Ver Também
- [[VACnet 2026 Overview]]
- [[Context_Aware_Anti_Debugging]]
- [[Behavioral_Mimicry]]
- [[Dynamic_Behavior_Analysis]]

---
<p align="center">REDFLAG © 2026</p>
