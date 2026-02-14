# 📖 Técnica 017: Input Spoofing

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 017: Input Spoofing]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Input & Spoofing  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Input Spoofing** manipula dados de entrada (mouse, teclado) para simular ações legítimas do usuário. É usado principalmente para aimbots e triggerbots que precisam parecer naturais.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO COM RISCO MODERADO
class InputSpoofer {
private:
    std::deque<INPUT_EVENT> inputQueue;
    std::mt19937 rng;
    
public:
    void Initialize() {
        rng.seed(std::random_device{}());
        
        // Instalar hooks de input
        InstallInputHooks();
        
        // Iniciar thread de spoofing
        StartSpoofingThread();
    }
    
    void SpoofMouseMovement(float targetX, float targetY, float currentX, float currentY) {
        // Calcular movimento necessário
        float deltaX = targetX - currentX;
        float deltaY = targetY - currentY;
        
        // Quebrar em movimentos pequenos
        std::vector<MOUSE_MOVEMENT> movements = GenerateNaturalMovements(deltaX, deltaY);
        
        // Queue movements
        for (auto& movement : movements) {
            INPUT_EVENT event = {INPUT_MOUSE, movement};
            inputQueue.push_back(event);
        }
    }
    
    void SpoofKeyPress(int keyCode, bool press) {
        // Adicionar delay humano
        int delay = GenerateHumanDelay();
        
        INPUT_EVENT event = {INPUT_KEYBOARD, {keyCode, press, delay}};
        inputQueue.push_back(event);
    }
    
private:
    std::vector<MOUSE_MOVEMENT> GenerateNaturalMovements(float deltaX, float deltaY) {
        std::vector<MOUSE_MOVEMENT> movements;
        
        // Número de steps (movimentos humanos não são instantâneos)
        int steps = std::max(3, std::min(10, (int)sqrt(deltaX * deltaX + deltaY * deltaY) / 20));
        
        // Curva de movimento (não linear)
        for (int i = 0; i < steps; i++) {
            float t = (float)i / (steps - 1);
            
            // Ease-in-out curve
            t = t < 0.5 ? 2 * t * t : -1 + (4 - 2 * t) * t;
            
            MOUSE_MOVEMENT move;
            move.x = deltaX * t;
            move.y = deltaY * t;
            move.delay = GenerateMovementDelay();
            
            movements.push_back(move);
        }
        
        return movements;
    }
    
    int GenerateHumanDelay() {
        // Distribuição normal para delays humanos
        std::normal_distribution<float> dist(50.0f, 25.0f);
        return std::max(10, (int)dist(rng));
    }
    
    int GenerateMovementDelay() {
        // Delays entre micro-movimentos
        std::uniform_int_distribution<int> dist(1, 5);
        return dist(rng);
    }
    
    void StartSpoofingThread() {
        std::thread([this]() {
            while (true) {
                if (!inputQueue.empty()) {
                    INPUT_EVENT event = inputQueue.front();
                    inputQueue.pop_front();
                    
                    // Aplicar delay
                    std::this_thread::sleep_for(std::chrono::milliseconds(event.delay));
                    
                    // Injetar input
                    InjectInput(event);
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
        }).detach();
    }
    
    void InjectInput(const INPUT_EVENT& event) {
        if (event.type == INPUT_MOUSE) {
            // Injetar movimento do mouse
            mouse_event(MOUSEEVENTF_MOVE, event.mouse.x, event.mouse.y, 0, 0);
        } else if (event.type == INPUT_KEYBOARD) {
            // Injetar tecla
            keybd_event(event.keyboard.keyCode, 0, 
                       event.keyboard.press ? 0 : KEYEVENTF_KEYUP, 0);
        }
    }
};

// Estruturas auxiliares
struct MOUSE_MOVEMENT {
    int x, y;
    int delay;
};

struct KEYBOARD_EVENT {
    int keyCode;
    bool press;
    int delay;
};

struct INPUT_EVENT {
    int type;
    union {
        MOUSE_MOVEMENT mouse;
        KEYBOARD_EVENT keyboard;
    };
};
```

### Por que é Detectado

> [!WARNING]
> **Input spoofing é detectável por análise de padrões e timing**

#### 1. Timing Analysis
```cpp
// Análise de timing de inputs
class InputTimingAnalyzer {
private:
    std::vector<INPUT_TIMESTAMP> inputHistory;
    
public:
    void OnInputEvent(INPUT_TYPE type, DWORD timestamp) {
        INPUT_TIMESTAMP event = {type, timestamp};
        inputHistory.push_back(event);
        
        AnalyzeTimingPatterns();
    }
    
    void AnalyzeTimingPatterns() {
        // Detectar padrões não-humanos
        if (HasBotPattern()) {
            ReportBotDetected();
        }
        
        // Verificar consistência de timing
        if (!HasHumanTiming()) {
            ReportSuspiciousTiming();
        }
    }
    
    bool HasBotPattern() {
        // Padrão 1: Inputs perfeitamente espaçados
        if (HasPerfectSpacing()) return true;
        
        // Padrão 2: Velocidade sobre-humana
        if (HasSuperhumanSpeed()) return true;
        
        // Padrão 3: Previsibilidade
        if (HasPredictablePattern()) return true;
        
        return false;
    }
    
    bool HasPerfectSpacing() {
        if (inputHistory.size() < 10) return false;
        
        // Calcular intervalos
        std::vector<DWORD> intervals;
        for (size_t i = 1; i < inputHistory.size(); i++) {
            intervals.push_back(inputHistory[i].timestamp - inputHistory[i-1].timestamp);
        }
        
        // Verificar se intervalos são muito consistentes
        float avgInterval = 0;
        for (DWORD interval : intervals) avgInterval += interval;
        avgInterval /= intervals.size();
        
        float variance = 0;
        for (DWORD interval : intervals) {
            float diff = interval - avgInterval;
            variance += diff * diff;
        }
        variance /= intervals.size();
        
        // Baixa variance = suspeito
        return variance < HUMAN_VARIANCE_THRESHOLD;
    }
    
    bool HasSuperhumanSpeed() {
        // Verificar velocidade de movimento/reação
        // Humanos têm limites físicos
        return false; // Implementação específica do jogo
    }
};
```

#### 2. Pattern Recognition
```cpp
// Reconhecimento de padrões de input
class InputPatternRecognizer {
private:
    std::vector<INPUT_SEQUENCE> knownPatterns;
    
public:
    void Initialize() {
        // Carregar padrões conhecidos de bots
        LoadBotPatterns();
    }
    
    void AnalyzeInputSequence(const std::vector<INPUT_EVENT>& sequence) {
        for (auto& pattern : knownPatterns) {
            if (MatchesPattern(sequence, pattern)) {
                ReportBotPattern(pattern.name);
            }
        }
    }
    
    bool MatchesPattern(const std::vector<INPUT_EVENT>& sequence, 
                       const INPUT_SEQUENCE& pattern) {
        if (sequence.size() < pattern.events.size()) return false;
        
        // Comparar sequência
        for (size_t i = 0; i < pattern.events.size(); i++) {
            if (!EventsMatch(sequence[i], pattern.events[i])) {
                return false;
            }
        }
        
        return true;
    }
    
    bool EventsMatch(const INPUT_EVENT& a, const INPUT_EVENT& b) {
        // Comparar tipos e parâmetros com tolerância
        if (a.type != b.type) return false;
        
        if (a.type == INPUT_MOUSE) {
            return abs(a.mouse.x - b.mouse.x) < POSITION_TOLERANCE &&
                   abs(a.mouse.y - b.mouse.y) < POSITION_TOLERANCE;
        } else if (a.type == INPUT_KEYBOARD) {
            return a.keyboard.keyCode == b.keyboard.keyCode &&
                   a.keyboard.press == b.keyboard.press;
        }
        
        return false;
    }
};
```

#### 3. Behavioral Analysis
```cpp
// Análise comportamental
class BehavioralAnalyzer {
public:
    void AnalyzePlayerBehavior() {
        // 1. Análise de precisão
        AnalyzeAccuracy();
        
        // 2. Análise de reações
        AnalyzeReactionTimes();
        
        // 3. Análise de padrões de movimento
        AnalyzeMovementPatterns();
        
        // 4. Análise de consistência
        AnalyzeConsistency();
    }
    
private:
    void AnalyzeAccuracy() {
        // Aimbots têm precisão perfeita
        // Humanos erram shots
        float accuracy = CalculateAccuracy();
        
        if (accuracy > HUMAN_ACCURACY_THRESHOLD) {
            ReportSuspiciousAccuracy();
        }
    }
    
    void AnalyzeReactionTimes() {
        // Reações instantâneas são suspeitas
        std::vector<DWORD> reactionTimes = GetReactionTimes();
        
        for (DWORD reaction : reactionTimes) {
            if (reaction < MIN_HUMAN_REACTION_TIME) {
                ReportInstantReaction();
            }
        }
    }
    
    void AnalyzeMovementPatterns() {
        // Movimentos perfeitamente suaves são suspeitos
        if (HasPerfectSmoothMovement()) {
            ReportBotMovement();
        }
    }
    
    void AnalyzeConsistency() {
        // Performance consistentemente perfeita é suspeita
        if (HasPerfectConsistency()) {
            ReportSuspiciousConsistency();
        }
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Timing analysis | < 30s | 75% |
| VAC Live | Pattern recognition | Imediato | 80% |
| BattlEye | Behavioral analysis | < 1 min | 85% |
| Faceit AC | AI analysis | < 30s | 90% |

---

## 🔄 Alternativas Seguras

### 1. Hardware-Level Input
```cpp
// ✅ Input via hardware (Arduino, etc)
class HardwareInputSpoofer {
private:
    SerialPort arduino;
    
public:
    void Initialize() {
        // Conectar ao Arduino
        arduino.Connect("COM3");
    }
    
    void SpoofMouseMovement(int x, int y) {
        // Enviar comando para Arduino
        std::string command = "MOUSE " + std::to_string(x) + " " + std::to_string(y);
        arduino.Send(command);
        
        // Arduino injeta input via hardware
    }
    
    void SpoofKeyPress(int keyCode) {
        std::string command = "KEY " + std::to_string(keyCode);
        arduino.Send(command);
    }
};

// Código Arduino correspondente
void setup() {
    Serial.begin(9600);
}

void loop() {
    if (Serial.available()) {
        String command = Serial.readStringUntil('\n');
        
        if (command.startsWith("MOUSE")) {
            // Parse coordinates
            int space1 = command.indexOf(' ');
            int space2 = command.indexOf(' ', space1 + 1);
            
            int x = command.substring(space1 + 1, space2).toInt();
            int y = command.substring(space2 + 1).toInt();
            
            // Move mouse via hardware
            Mouse.move(x, y);
        }
        else if (command.startsWith("KEY")) {
            int keyCode = command.substring(4).toInt();
            Keyboard.press(keyCode);
            delay(50);
            Keyboard.release(keyCode);
        }
    }
}
```

### 2. Kernel Input Injection
```cpp
// ✅ Injeção via kernel driver
class KernelInputInjector {
private:
    HANDLE hDriver;
    
public:
    void Initialize() {
        // Carregar driver
        hDriver = CreateFile("\\\\.\\InputInjector", GENERIC_READ | GENERIC_WRITE, 
                           0, NULL, OPEN_EXISTING, 0, NULL);
    }
    
    void InjectMouseMovement(int x, int y) {
        MOUSE_INPUT_DATA data = {x, y};
        
        DeviceIoControl(hDriver, IOCTL_INJECT_MOUSE, &data, sizeof(data), 
                       NULL, 0, NULL, NULL);
    }
    
    void InjectKeyPress(int keyCode) {
        KEYBOARD_INPUT_DATA data = {keyCode, TRUE};
        
        DeviceIoControl(hDriver, IOCTL_INJECT_KEYBOARD, &data, sizeof(data),
                       NULL, 0, NULL, NULL);
    }
};

// Driver kernel correspondente
NTSTATUS InjectMouse(PMOUSE_INPUT_DATA data) {
    // Usar MouClass para injetar input
    MOUSE_INPUT_DATA mid = {0};
    mid.LastX = data->x;
    mid.LastY = data->y;
    mid.ButtonFlags = MOUSE_MOVE_RELATIVE;
    
    // Enviar para mouse class driver
    return SendInputToMouse(&mid);
}

NTSTATUS InjectKeyboard(PKEYBOARD_INPUT_DATA data) {
    KEYBOARD_INPUT_DATA kid = {0};
    kid.MakeCode = data->keyCode;
    kid.Flags = data->press ? KEY_MAKE : KEY_BREAK;
    
    // Enviar para keyboard class driver
    return SendInputToKeyboard(&kid);
}
```

### 3. Direct Driver Manipulation
```cpp
// ✅ Manipulação direta de drivers
class DirectDriverManipulator {
public:
    void Initialize() {
        // Hook mouclass.sys ou kbdclass.sys
        HookInputDrivers();
    }
    
    void InjectInput() {
        // Modificar buffers de input diretamente
        ModifyInputBuffers();
    }
    
private:
    void HookInputDrivers() {
        // Instalar hooks nos drivers de input
        // Intercetar IRPs de input
    }
    
    void ModifyInputBuffers() {
        // Adicionar inputs aos buffers do driver
        // Inputs aparecem como legítimos
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Input Analyzer
```cpp
// VAC input pattern detection
class VAC_InputAnalyzer {
private:
    InputTimingAnalyzer timingAnalyzer;
    InputPatternRecognizer patternRecognizer;
    
public:
    void Initialize() {
        timingAnalyzer.Initialize();
        patternRecognizer.Initialize();
    }
    
    void OnInputEvent(INPUT_EVENT event) {
        // Analisar timing
        timingAnalyzer.OnInputEvent(event.type, event.timestamp);
        
        // Verificar padrões
        patternRecognizer.AnalyzeInputSequence(event);
        
        // Behavioral analysis
        AnalyzeBehavior(event);
    }
    
    void AnalyzeBehavior(INPUT_EVENT event) {
        // Track player behavior patterns
        // Flag suspicious activities
    }
};
```

### BattlEye Behavioral Engine
```cpp
// BE behavioral analysis
void BE_AnalyzeBehavior() {
    // Monitor player actions
    MonitorPlayerActions();
    
    // Analyze skill level
    AnalyzeSkillLevel();
    
    // Check for automation
    CheckForAutomation();
}

void MonitorPlayerActions() {
    // Track mouse movements
    // Monitor keyboard inputs
    // Analyze reaction times
}

void AnalyzeSkillLevel() {
    // Calculate accuracy
    // Check consistency
    // Verify human-like patterns
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | Timing |
| 2020-2024 | ⚠️ Risco | Patterns |
| 2025-2026 | ⚠️ Moderado | AI analysis |

---

## 🎯 Lições Aprendadas

1. **Timing é Crítico**: Inputs perfeitamente timed são detectáveis.

2. **Padrões São Analisados**: Sequências repetitivas revelam bots.

3. **Hardware é Mais Seguro**: Input via hardware evita detecção de software.

4. **Kernel Injection é Superior**: Operar em ring 0 produz inputs legítimos.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#17]]
- [[Hardware_Input_Spoofing]]
- [[Kernel_Input_Injection]]
- [[Direct_Driver_Manipulation]]

---

*Input spoofing é detectável por análise de padrões. Use hardware ou kernel injection para maior stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
