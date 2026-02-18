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
        
        // 6-10. Timing jitter em diferentes níveis
        features.extend(vec![0.0; 5]);  // Placeholder para mais timing checks
        
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
        
        // 5-10. Mais features de sistema
        features.extend(vec![0.0; 6]);
        
        features
    }
    
    unsafe fn extract_process_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        
        // 1. Número de threads
        use windows::Win32::System::Threading::*;
        let handle = GetCurrentProcess();
        features.push(0.0);  // Implementação completa requer query
        
        // 2. Tamanho do working set
        let mut mem_counters: std::mem::MaybeUninit<windows::Win32::System::ProcessStatus::PROCESS_MEMORY_COUNTERS> = std::mem::MaybeUninit::uninit();
        features.push(0.0);
        
        // 3-10. Features de processo
        features.extend(vec![0.0; 8]);
        
        features
    }
    
    unsafe fn extract_anomaly_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        
        // 1. Debugger present (binário 0/1)
        use windows::Win32::System::Diagnostics::Debug::IsDebuggerPresent;
        features.push(if IsDebuggerPresent().as_bool() { 1.0 } else { 0.0 });
        
        // 2. Número de APIs hookadas
        features.push(0.0);  // Scan hooks implementation
        
        // 3-10. Anomalias diversas
        features.extend(vec![0.0; 8]);
        
        features
    }
    
    unsafe fn extract_behavioral_features() -> Vec<f32> {
        let mut features = Vec::with_capacity(10);
        
        // Behavioral features requerem histórico
        // Por simplicidade, placeholder
        features.extend(vec![0.0; 10]);
        
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
