# 🎨 VACnet 2026 Overview

📅 Criado em: 2026-02-15
🔗 Tags: #anti-cheat #machine-learning #cs2

## 📌 Definição

**VACnet** é o sistema de Machine Learning da Valve que analisa demos de partidas do CS2 para detectar comportamento de cheat. Opera **server-side**, analisando dados de gameplay enviados após cada partida.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[ML_Based_Detection]]
- [[Context_Aware_Detection]]

## 📚 Como Funciona (2026)

### Pipeline de Dados
```
1. [Partida CS2] → Grava inputs do jogador
2. [Servidor Valve] → Envia demo para cluster de IA
3. [VACnet 3.0] → Analisa ~200 features comportamentais
4. [Scoring] → Confiança de cheat (0.0 - 1.0)
5. [Threshold] → Se > 0.85 → Overwatch manual
```

### Features Analisadas
```python
# Exemplo das features extraídas do demo
player_features = {
    # Aim
    "crosshair_placement_score": 0.92,  # Pré-aim suspeito
    "headshot_percentage": 0.68,
    "reaction_time_mean": 142,  # ms
    "reaction_time_std": 8,     # Muito consistente
    
    # Movement
    "bhop_success_rate": 0.95,  # Inumano
    "strafe_efficiency": 0.88,
    
    # Game Sense
    "wallbang_rate": 0.15,      # Muitos wallbangs "sortudos"
    "prefire_accuracy": 0.72,   # Atira antes de ver
    
    # Correlações
    "aim_movement_sync": 0.99,  # Perfeito = bot
}
```

## 🛡️ Bypass Strategies

### 1. Humanização Estatística
```rust
// Injetar variabilidade nas estatísticas
fn humanize_reaction_time() -> Duration {
    // Distribuição normal: média 200ms, desvio 50ms
    let mean = 200.0;
    let std_dev = 50.0;
    let sample = normal_distribution(mean, std_dev);
    Duration::from_millis(sample.max(100.0) as u64)
}
```

### 2. Evitar "Impossibilidades"
```rust
// Não faça coisas que humanos não fazem
fn is_humanly_possible(action: &Action) -> bool {
    match action {
        // Bhop perfeito sempre = bot
        Action::Bhop if bhop_streak > 10 => false,
        
        // 180° flick em <20ms = fisicamente impossível
        Action::AimFlick(degrees, time) 
            if degrees > 90.0 && time < 20 => false,
        
        // Spray control RCS perfeito = bot
        Action::Spray if pattern_accuracy > 0.95 => false,
        
        _ => true,
    }
}
```

### 3. Selective Usage
```rust
// Use cheat apenas quando necessário
fn should_enable_aimbot(context: &GameContext) -> bool {
    // Apenas em clutches críticos
    context.is_clutch_situation() && 
    context.round_importance > 0.7 &&
    context.your_performance_this_match < 1.5  // KD ratio
}
```

## ⚠️ Sinais de Flagging

> [!CAUTION]
> Você foi provavelmente flagged pelo VACnet se:
> - Recebe múltiplos votos de report em poucas partidas
> - Suas demos são requisitadas com frequência incomum
> - Delay artificial no matchmaking (sistema te isolando)
> - Ban após semanas/meses (tempo de análise do VACnet)

## 📖 Ver Também
- [[Dynamic_Behavior_Analysis]]
- [[Técnica 008 - Curvas de Bézier + Jitter de Tremor]]

---
<p align="center">REDFLAG © 2026</p>
