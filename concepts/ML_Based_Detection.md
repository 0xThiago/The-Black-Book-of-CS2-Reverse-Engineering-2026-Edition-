# 🤖 ML Based Detection

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #machine-learning #anti-cheat

## 📌 Definição

**ML-Based Detection** refere-se ao uso de Machine Learning para detectar comportamento anômalo de jogadores ou assinaturas de cheats. No CS2, o **VACnet 3.0** utiliza redes neurais para análise comportamental em tempo real.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[DATABASE]]
- [[Técnica 046 - Anti-Emulator Techniques]]
- [[Técnica 047 - Anti-Debugging Techniques]]
- [[Técnica 055 - High-Performance Rust ONNX Inference]]

## 📚 Como Funciona (VACnet Perspectiva)

### Inputs Coletados
O servidor do CS2 envia para o cluster de IA da Valve:
- **Coordenadas de mira** (yaw/pitch a cada tick)
- **Padrões de disparo** (timing entre tiros)
- **Movimentação** (WASD input patterns)
- **Tempo de reação** (tempo entre ver inimigo e atirar)
- **Precisão de headshot** (% acima da média humana)

### Modelo de Detecção
```python
# Simplified VACnet-like model
features = [
    aim_smoothness,      # Bezier vs linear
    reaction_time_std,   # Variabilidade humana
    crosshair_placement, # Pré-aim suspeito
    spray_pattern_acc,   # RCS perfeito = bot
    movement_correlation # WASD sync com aim
]

prediction = neural_network.predict(features)
if prediction > CHEAT_THRESHOLD:
    flag_for_overwatch()
```

## 🛡️ Contra-Medidas (Aimbot ML-Aware)

### 1. Humanização de Movimento
- [[Técnica 008 - Curvas de Bézier + Jitter de Tremor]]
- Adicionar **micro-overshoots** intencionais
- Variar tempo de reação (150-300ms com distribuição normal)

### 2. Feature Poisoning
```rust
// Injetar "erros humanos" propositais
fn humanize_aim(target: Vec3) -> Vec3 {
    let noise = perlin_noise(time);
    let overshoot = random_normal(0.0, 2.5); // pixels
    target + Vec3::new(noise, overshoot, 0.0)
}
```

### 3. Selective Activation
- **Não** use aimbot em todos os frames
- Ative apenas em situações críticas (1v1 clutch)
- Mantenha % de headshot próximo de jogadores legítimos (~25-30%)

## ⚙️ Detecção de ML-Based Anti-Cheat

Sinais de que você está sendo analisado por IA:
- ❌ Delay incomum entre ação e feedback do servidor
- ❌ Padrões de lag artificial (servidor amostrando seus inputs)
- ❌ Requisição de demos suspeitas

## 📖 Ver Também
- [[Dynamic_Behavior_Analysis]]
- [[Context_Aware_Detection]]
- [[Environmental_Awareness]]

---
<p align="center">REDFLAG © 2026</p>
