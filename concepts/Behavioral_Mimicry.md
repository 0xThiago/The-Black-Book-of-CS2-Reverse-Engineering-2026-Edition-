# 🎭 Behavioral Mimicry

📅 Criado em: 2026-02-18
🔗 Tags: #conceito #ai #ml #evasion #behavioral #2026

## 📌 Definição

**Behavioral Mimicry** é uma técnica avançada de evasão que faz com que um cheat imite o comportamento de um jogador humano real, incluindo padrões de mira, tempo de reação, erros naturais e degradação por fadiga. O objetivo é tornar a atividade do cheat **estatisticamente indistinguível** de um jogador legítimo, evitando detecção por sistemas de análise comportamental como o **VACnet**.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[DATABASE]]
- [[VACnet 2026 Overview]]
- [[ML_Based_Anti_Debugging]]
- [[ML_Based_Detection]]
- [[Dynamic_Behavior_Analysis]]

## 📚 Por Que Behavioral Mimicry é Essencial (2026)

### Evolução da Detecção
```
2020: Detecção por assinatura (hash do binário)
├─ Contorno: Polimorfismo

2022: Detecção por padrão (timing de inputs)
├─ Contorno: Jitter aleatório

2024: VACnet ML v3 — Análise comportamental multi-dimensional
├─ Contorno: Behavioral Mimicry

2026: VACnet ML v4 — Deep learning com temporal patterns
├─ Contorno: GAN-based movement + Profile Cloning
```

### O que VACnet Analisa
```
Métricas comportamentais monitoradas:
├─ Reaction time distribution (média, desvio, kurtosis)
├─ Aim trajectory shape (curva vs. linear vs. snap)
├─ Headshot % por distância e arma
├─ Kill-to-death timing patterns
├─ Movement patterns (strafe, peek, pre-aim)
├─ Fatigue degradation ao longo da partida
└─ Crosshair placement antes de ver inimigo
```

## 🛠️ Implementação em Rust (2026)

### 1. Player Profile System

```rust
use rand::Rng;
use rand_distr::{Normal, Distribution};
use std::time::Instant;

/// Perfil comportamental de um jogador real
///
/// # Camada 1: SINTAXE
/// Struct que armazena todas as métricas comportamentais
/// de um jogador real, capturadas via replay analysis.
///
/// # Camada 2: MEMÓRIA
/// ~128 bytes na stack. Todos os campos são tipos primitivos
/// com alinhamento natural (f32 = 4 bytes, sem padding).
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Ownership move semantics — quando passamos o perfil para
/// o BehavioralEngine, ele toma posse exclusiva.
#[derive(Debug, Clone)]
pub struct PlayerProfile {
    /// Tempo de reação médio em milissegundos (humano: 150-300ms)
    pub avg_reaction_time_ms: f32,
    /// Desvio padrão do tempo de reação (humano: 20-60ms)
    pub reaction_std_dev: f32,
    /// Taxa de headshot (humano: 25-55% dependendo do rank)
    pub headshot_rate: f32,
    /// Suavidade do movimento de mira (0.0 = robótico, 1.0 = humano)
    pub aim_smoothness: f32,
    /// Taxa de degradação por hora de jogo
    pub fatigue_rate: f32,
    /// Taxa base de erros (overshoots, undershoots)
    pub error_rate: f32,
    /// Velocidade máxima de flick (graus/segundo, humano: 800-2000)
    pub max_flick_speed: f32,
    /// Rank do jogador (para calibração)
    pub skill_rank: SkillRank,
}

#[derive(Debug, Clone, Copy)]
pub enum SkillRank {
    Silver,       // Reaction: ~280ms, HS: ~25%
    Gold,         // Reaction: ~230ms, HS: ~35%
    MasterGuardian, // Reaction: ~200ms, HS: ~42%
    LEM,          // Reaction: ~180ms, HS: ~48%
    Global,       // Reaction: ~160ms, HS: ~55%
    FaceitLevel10, // Reaction: ~150ms, HS: ~58%
}

impl PlayerProfile {
    /// Cria perfil calibrado para rank específico
    pub fn from_rank(rank: SkillRank) -> Self {
        match rank {
            SkillRank::Gold => Self {
                avg_reaction_time_ms: 230.0,
                reaction_std_dev: 45.0,
                headshot_rate: 0.35,
                aim_smoothness: 0.7,
                fatigue_rate: 0.02,
                error_rate: 0.15,
                max_flick_speed: 1200.0,
                skill_rank: rank,
            },
            SkillRank::LEM => Self {
                avg_reaction_time_ms: 180.0,
                reaction_std_dev: 30.0,
                headshot_rate: 0.48,
                aim_smoothness: 0.85,
                fatigue_rate: 0.015,
                error_rate: 0.08,
                max_flick_speed: 1600.0,
                skill_rank: rank,
            },
            SkillRank::Global => Self {
                avg_reaction_time_ms: 160.0,
                reaction_std_dev: 25.0,
                headshot_rate: 0.55,
                aim_smoothness: 0.9,
                fatigue_rate: 0.012,
                error_rate: 0.05,
                max_flick_speed: 1800.0,
                skill_rank: rank,
            },
            _ => Self {
                avg_reaction_time_ms: 250.0,
                reaction_std_dev: 50.0,
                headshot_rate: 0.30,
                aim_smoothness: 0.6,
                fatigue_rate: 0.025,
                error_rate: 0.20,
                max_flick_speed: 1000.0,
                skill_rank: rank,
            },
        }
    }
}
```

### 2. Behavioral Engine

```rust
/// Motor de mimetismo comportamental
///
/// # Camada 1: SINTAXE
/// Engine que aplica o perfil humano a todas as ações do cheat,
/// transformando inputs perfeitos em outputs humanizados.
///
/// # Camada 2: MEMÓRIA
/// ~256 bytes na stack. O RNG interno usa estado de 128 bits.
/// `session_start` usa Instant que internamente é um u64.
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// &mut self garante acesso exclusivo ao estado — impossível
/// ter dois threads aplicando behavioral mimicry simultaneamente
/// sem Arc<Mutex<>>.
pub struct BehavioralEngine {
    profile: PlayerProfile,
    session_start: Instant,
    kill_count: u32,
    death_count: u32,
    reaction_rng: Normal<f32>,
}

impl BehavioralEngine {
    pub fn new(profile: PlayerProfile) -> Self {
        let reaction_rng = Normal::new(
            profile.avg_reaction_time_ms,
            profile.reaction_std_dev,
        ).unwrap();

        Self {
            profile,
            session_start: Instant::now(),
            kill_count: 0,
            death_count: 0,
            reaction_rng,
        }
    }

    /// Retorna tempo de reação humanizado (ms)
    ///
    /// Inclui fadiga acumulada e variação natural.
    /// VACnet verifica se a distribuição de reaction times
    /// segue uma normal — esse método garante isso.
    pub fn get_reaction_time(&self) -> f32 {
        let mut rng = rand::thread_rng();

        // Base: amostra da distribuição normal calibrada
        let base_reaction = self.reaction_rng.sample(&mut rng);

        // Fadiga: +2-5% por hora jogada
        let hours_played = self.session_start.elapsed().as_secs_f32() / 3600.0;
        let fatigue_penalty = 1.0 + (hours_played * self.profile.fatigue_rate);

        // Micro-variação: ±5% adicional por round
        let micro_variation = 1.0 + rng.gen_range(-0.05..0.05);

        (base_reaction * fatigue_penalty * micro_variation).max(80.0)
    }

    /// Decide se deve mirar na cabeça ou corpo
    ///
    /// Respeita a headshot rate do perfil. VACnet flagga
    /// jogadores com HS% muito acima do rank.
    pub fn should_headshot(&self) -> bool {
        let mut rng = rand::thread_rng();

        // Fadiga reduz HS rate ao longo do tempo
        let hours_played = self.session_start.elapsed().as_secs_f32() / 3600.0;
        let adjusted_rate = self.profile.headshot_rate * (1.0 - hours_played * 0.03);

        rng.gen::<f32>() < adjusted_rate
    }

    /// Aplica erro humano ao ângulo de mira perfeito
    ///
    /// Tipos de erro:
    /// 1. Overshoot (passar do alvo) — mais comum em flicks rápidos
    /// 2. Undershoot (parar antes) — mais comum com fadiga
    /// 3. Offset lateral — "micro-adjust" humano
    pub fn apply_human_error(&self, perfect_angle: Vec2, distance: f32) -> Vec2 {
        let mut rng = rand::thread_rng();

        // Sem erro na maioria dos casos
        if rng.gen::<f32>() > self.profile.error_rate {
            return perfect_angle;
        }

        let hours_played = self.session_start.elapsed().as_secs_f32() / 3600.0;
        let fatigue_factor = 1.0 + hours_played * 0.1;

        // Escolher tipo de erro com pesos
        let error_type: f32 = rng.gen();

        if error_type < 0.4 {
            // Overshoot: 5-15% além do alvo
            let overshoot = 1.0 + rng.gen_range(0.05..0.15) * fatigue_factor;
            Vec2::new(perfect_angle.x * overshoot, perfect_angle.y * overshoot)
        } else if error_type < 0.7 {
            // Undershoot: para 85-95% do caminho
            let undershoot = rng.gen_range(0.85..0.95);
            Vec2::new(perfect_angle.x * undershoot, perfect_angle.y * undershoot)
        } else {
            // Offset lateral: ±2-8 pixels dependendo da distância
            let offset_scale = (distance / 500.0).min(1.0) * fatigue_factor;
            let offset_x = rng.gen_range(-8.0..8.0) * offset_scale;
            let offset_y = rng.gen_range(-4.0..4.0) * offset_scale;
            Vec2::new(perfect_angle.x + offset_x, perfect_angle.y + offset_y)
        }
    }

    /// Simula "whiff" ocasional (errar completamente)
    ///
    /// Jogadores profissionais erram ~5-10% dos sprays.
    /// VACnet detecta ausência total de whiffs.
    pub fn should_whiff(&self) -> bool {
        let mut rng = rand::thread_rng();
        let hours = self.session_start.elapsed().as_secs_f32() / 3600.0;
        let whiff_chance = 0.05 + hours * 0.01; // Aumenta com fadiga
        rng.gen::<f32>() < whiff_chance
    }
}

/// Vetor 2D simplificado para ângulos
#[derive(Debug, Clone, Copy)]
pub struct Vec2 {
    pub x: f32,
    pub y: f32,
}

impl Vec2 {
    pub fn new(x: f32, y: f32) -> Self { Self { x, y } }
}
```

### 3. GAN-Based Movement (Ponte C++)

```rust
use ort::{Session, SessionBuilder, Value};
use ndarray::Array2;

/// Gerador de trajetórias via GAN treinada em dados de jogadores reais
///
/// # Camada 1: SINTAXE
/// Usa modelo ONNX exportado de PyTorch GAN treinada
/// com 50.000+ trajetórias reais de jogadores profissionais.
///
/// # Camada 2: MEMÓRIA
/// O modelo ONNX (~2MB) é carregado na VRAM (GPU) via ort.
/// Inferência aloca tensor temporário de 240 bytes (30 pontos × 2 dims × f32).
///
/// # Camada 3: SEGURANÇA & OWNERSHIP
/// Session é Send + Sync, permitindo inferência multi-thread.
/// O tensor de saída é owned — sem risco de dangling pointer.
///
/// **Ponte C++**: Equivalente a `torch::jit::load()` em LibTorch,
/// mas com gerenciamento de memória automático via Rust ownership.
pub struct MovementGAN {
    session: Session,
}

impl MovementGAN {
    /// Carrega modelo ONNX pré-treinado
    pub fn new(model_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let session = Session::builder()?
            .with_optimization_level(ort::GraphOptimizationLevel::Level3)?
            .commit_from_file(model_path)?;

        Ok(Self { session })
    }

    /// Gera trajetória humanizada entre dois pontos
    ///
    /// Retorna 30 pontos (x,y) que formam uma curva
    /// indistinguível de movimento humano real.
    pub fn generate_path(
        &self,
        start: Vec2,
        end: Vec2,
        duration_ms: f32,
    ) -> Result<Vec<Vec2>, Box<dyn std::error::Error>> {
        // Input: [noise(100) + conditions(5)] = 105 features
        let mut rng = rand::thread_rng();
        let mut input_data = vec![0.0f32; 105];

        // Latent noise
        for i in 0..100 {
            input_data[i] = rng.gen_range(-1.0..1.0);
        }

        // Conditions: start_x, start_y, end_x, end_y, duration
        input_data[100] = start.x;
        input_data[101] = start.y;
        input_data[102] = end.x;
        input_data[103] = end.y;
        input_data[104] = duration_ms / 1000.0;

        let input_tensor = Array2::from_shape_vec((1, 105), input_data)?;
        let outputs = self.session.run(ort::inputs![input_tensor]?)?;

        // Output: (1, 30, 2) -> 30 pontos 2D
        let output = outputs[0].try_extract_tensor::<f32>()?;
        let view = output.view();

        let mut path = Vec::with_capacity(30);
        for i in 0..30 {
            let x = view[[0, i, 0]] * (end.x - start.x) + start.x;
            let y = view[[0, i, 1]] * (end.y - start.y) + start.y;
            path.push(Vec2::new(x, y));
        }

        Ok(path)
    }
}
```

## 🎯 Aplicação em CS2

### Integração com Aimbot

```rust
/// Aimbot com behavioral mimicry integrado
pub fn humanized_aim(
    engine: &BehavioralEngine,
    current_pos: Vec2,
    target_pos: Vec2,
    distance: f32,
) -> Option<Vec2> {
    // 1. Simular tempo de reação
    let reaction_ms = engine.get_reaction_time();
    std::thread::sleep(std::time::Duration::from_millis(reaction_ms as u64));

    // 2. Whiff check — errar de propósito ~5% das vezes
    if engine.should_whiff() {
        return None;  // Não atirar neste frame
    }

    // 3. Decidir headshot vs bodyshot
    let target = if engine.should_headshot() {
        target_pos  // Cabeça
    } else {
        Vec2::new(target_pos.x, target_pos.y + 15.0)  // Corpo (offset para baixo)
    };

    // 4. Aplicar erro humano
    let aimed = engine.apply_human_error(target, distance);

    Some(aimed)
}
```

## 📊 Comparação de Abordagens

| Abordagem | VACnet Detection | Naturalidade | Overhead |
|-----------|-----------------|-------------|----------|
| **Sem mimicry** | 🔴 1-3 partidas | ❌ Zero | 0% |
| **Jitter aleatório** | 🟠 5-10 partidas | 🟡 Baixa | <1% |
| **Profile cloning** | 🟢 Indetectável | 🟢 Alta | 2-3% |
| **GAN movement** | 🟢 Indetectável | 🟢 Máxima | 5-8% |

## ⚠️ Limitações

> [!CAUTION]
> **Temporal Analysis**: VACnet 2026 compara padrões ao longo de SEMANAS.
> Mesmo com mimicry perfeita, performance consistentemente acima do rank
> por muitas partidas é flaggada. Sempre calibrar o perfil para o rank atual.

> [!WARNING]
> **Dataset Quality**: A GAN é tão boa quanto o dataset de treinamento.
> Trajetórias devem ser coletadas de jogadores REAIS do mesmo rank,
> não de bots de treino.

## 📖 Ver Também
- [[VACnet 2026 Overview]]
- [[ML_Based_Anti_Debugging]]
- [[ML_Based_Detection]]
- [[Dynamic_Behavior_Analysis]]

---
<p align="center">REDFLAG © 2026</p>
