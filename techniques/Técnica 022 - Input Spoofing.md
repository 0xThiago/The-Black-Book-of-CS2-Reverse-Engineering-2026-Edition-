# Técnica 022 - Input Spoofing

> [!WARNING]
> **⚠️ NOTA DUPLICADA** — Esta nota é uma duplicata de [[Técnica 018 - Input Spoofing]].
> Consulte a nota canônica para conteúdo atualizado.

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2 #duplicata

## 📌 Resumo
> > **Status:** ❌ Defasado / Ineficaz

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[Técnica 018 - Input Spoofing]]
- [[DATABASE]]

## 🔍 Desenvolvimento
> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Input & Control  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Input Spoofing** simula entrada do usuário (teclado, mouse) para automatizar ações no jogo. Era usado para aimbots, triggerbots e macros, mas é facilmente detectado por anti-cheats modernos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
class InputSpoofer {
private:
    HANDLE hGameProcess;
    uintptr_t inputSystemAddr;
    
public:
    void Initialize(HANDLE process, uintptr_t inputAddr) {
        hGameProcess = process;
        inputSystemAddr = inputAddr;
    }
    
    // Spoof mouse movement
    void SpoofMouseMovement(float deltaX, float deltaY) {
        // Escrever movimento do mouse diretamente na memória
        WriteMouseDelta(deltaX, deltaY);
        
        // Ou usar SendInput (menos stealthy)
        SendInputSpoof(deltaX, deltaY);
    }
    
    // Spoof keyboard input
    void SpoofKeyPress(int keyCode) {
        // Simular pressionamento de tecla
        SimulateKeyPress(keyCode);
        
        // Ou modificar estado do teclado na memória
        WriteKeyState(keyCode, true);
    }
    
    // Aim assist via input spoofing
    void AimAssist(const Vector2D& targetScreenPos) {
        // Calcular delta necessário
        Vector2D center = GetScreenCenter();
        Vector2D delta = targetScreenPos - center;
        
        // Aplicar smoothing
        delta *= aimbotSmoothing;
        
        // Spoof movimento
        SpoofMouseMovement(delta.x, delta.y);
    }
    
    // Triggerbot via input spoofing
    void TriggerBot() {
        if (IsEnemyInCrosshair()) {
            // Simular clique do mouse
            SpoofMouseClick();
        }
    }
    
    // Macro via input spoofing
    void ExecuteMacro(const std::vector<INPUT_EVENT>& macro) {
        for (auto& event : macro) {
            switch (event.type) {
                case INPUT_KEYBOARD:
                    SpoofKeyPress(event.keyCode);
                    Sleep(event.delay);
                    break;
                    
                case INPUT_MOUSE:
                    SpoofMouseMovement(event.mouseDelta.x, event.mouseDelta.y);
                    Sleep(event.delay);
                    break;
            }
        }
    }
    
private:
    void WriteMouseDelta(float deltaX, float deltaY) {
        // Encontrar estrutura de input na memória
        uintptr_t mouseDeltaAddr = inputSystemAddr + MOUSE_DELTA_OFFSET;
        
        // Escrever deltas
        WriteProcessMemory(hGameProcess, (LPVOID)mouseDeltaAddr, 
                          &deltaX, sizeof(float), NULL);
        WriteProcessMemory(hGameProcess, (LPVOID)(mouseDeltaAddr + 4), 
                          &deltaY, sizeof(float), NULL);
    }
    
    void SendInputSpoof(float deltaX, float deltaY) {
        // Usar SendInput para simular movimento
        INPUT input = {0};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        input.mi.dx = (LONG)deltaX;
        input.mi.dy = (LONG)deltaY;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    void SimulateKeyPress(int keyCode) {
        // Simular pressionamento usando SendInput
        INPUT inputs[2] = {0};
        
        // Key down
        inputs[0].type = INPUT_KEYBOARD;
        inputs[0].ki.wVk = keyCode;
        
        // Key up
        inputs[1].type = INPUT_KEYBOARD;
        inputs[1].ki.wVk = keyCode;
        inputs[1].ki.dwFlags = KEYEVENTF_KEYUP;
        
        SendInput(2, inputs, sizeof(INPUT));
    }
    
    void WriteKeyState(int keyCode, bool pressed) {
        // Modificar estado do teclado na memória
        uintptr_t keyStateAddr = inputSystemAddr + KEY_STATE_OFFSET + keyCode;
        
        BYTE state = pressed ? 0x80 : 0x00;
        WriteProcessMemory(hGameProcess, (LPVOID)keyStateAddr, 
                          &state, sizeof(BYTE), NULL);
    }
    
    void SpoofMouseClick() {
        // Simular clique esquerdo
        INPUT inputs[2] = {0};
        
        // Mouse down
        inputs[0].type = INPUT_MOUSE;
        inputs[0].mi.dwFlags = MOUSEEVENTF_LEFTDOWN;
        
        // Mouse up
        inputs[1].type = INPUT_MOUSE;
        inputs[1].mi.dwFlags = MOUSEEVENTF_LEFTUP;
        
        SendInput(2, inputs, sizeof(INPUT));
    }
    
    Vector2D GetScreenCenter() {
        return Vector2D(SCREEN_WIDTH / 2.0f, SCREEN_HEIGHT / 2.0f);
    }
    
    bool IsEnemyInCrosshair() {
        // Verificar se há inimigo na mira
        // Implementar raycast ou verificação de hitbox
        return false; // Placeholder
    }
};
```

### Por que é Detectado

> [!DANGER]
> **Input spoofing deixa rastros óbvios no sistema de input e timing**

#### 1. Input Timing Analysis
```cpp
// Análise de timing de input
class InputTimingAnalyzer {
private:
    std::vector<INPUT_EVENT> inputHistory;
    DWORD lastInputTime;
    
public:
    void OnInputEvent(const INPUT_EVENT& event) {
        inputHistory.push_back(event);
        lastInputTime = GetTickCount();
        
        // Limpar histórico antigo
        CleanOldHistory();
        
        // Analisar padrões
        AnalyzeTimingPatterns();
    }
    
    void AnalyzeTimingPatterns() {
        if (inputHistory.size() < 10) return;
        
        // Verificar timing suspeito
        if (HasSuspiciousTiming()) {
            ReportInputSpoofing();
        }
        
        // Verificar padrões automáticos
        if (HasAutomatedPatterns()) {
            ReportMacroDetected();
        }
        
        // Verificar precisão perfeita
        if (HasPerfectAccuracy()) {
            ReportAimbotDetected();
        }
    }
    
    bool HasSuspiciousTiming() {
        // Verificar intervalos muito regulares
        std::vector<DWORD> intervals;
        
        for (size_t i = 1; i < inputHistory.size(); i++) {
            DWORD interval = inputHistory[i].timestamp - inputHistory[i-1].timestamp;
            intervals.push_back(interval);
        }
        
        // Calcular variância
        float variance = CalculateVariance(intervals);
        
        // Timing muito regular = suspeito
        return variance < SUSPICIOUS_VARIANCE_THRESHOLD;
    }
    
    bool HasAutomatedPatterns() {
        // Detectar padrões repetitivos
        if (inputHistory.size() < 20) return false;
        
        // Verificar se últimas N entradas se repetem
        size_t patternSize = 5;
        std::vector<INPUT_EVENT> lastPattern(inputHistory.end() - patternSize, 
                                           inputHistory.end());
        
        // Procurar por repetições
        int repeatCount = 0;
        for (size_t i = inputHistory.size() - patternSize * 2; 
             i < inputHistory.size() - patternSize; i++) {
            
            bool matches = true;
            for (size_t j = 0; j < patternSize; j++) {
                if (!EventsEqual(inputHistory[i + j], lastPattern[j])) {
                    matches = false;
                    break;
                }
            }
            
            if (matches) repeatCount++;
        }
        
        return repeatCount > 2; // Múltiplas repetições
    }
    
    bool HasPerfectAccuracy() {
        // Verificar precisão perfeita em movimentos
        std::vector<MOUSE_MOVE> mouseMoves;
        
        for (auto& event : inputHistory) {
            if (event.type == INPUT_MOUSE) {
                mouseMoves.push_back(event.mouseMove);
            }
        }
        
        if (mouseMoves.size() < 5) return false;
        
        // Calcular precisão
        float totalAccuracy = 0.0f;
        for (auto& move : mouseMoves) {
            totalAccuracy += CalculateMoveAccuracy(move);
        }
        
        float avgAccuracy = totalAccuracy / mouseMoves.size();
        
        // Precisão muito alta = suspeita
        return avgAccuracy > PERFECT_ACCURACY_THRESHOLD;
    }
    
private:
    void CleanOldHistory() {
        DWORD currentTime = GetTickCount();
        DWORD timeWindow = 30000; // 30 segundos
        
        inputHistory.erase(
            std::remove_if(inputHistory.begin(), inputHistory.end(),
                [currentTime, timeWindow](const INPUT_EVENT& event) {
                    return currentTime - event.timestamp > timeWindow;
                }),
            inputHistory.end()
        );
    }
    
    float CalculateVariance(const std::vector<DWORD>& values) {
        if (values.empty()) return 0.0f;
        
        float mean = 0.0f;
        for (DWORD val : values) mean += val;
        mean /= values.size();
        
        float variance = 0.0f;
        for (DWORD val : values) {
            float diff = val - mean;
            variance += diff * diff;
        }
        
        return variance / values.size();
    }
    
    bool EventsEqual(const INPUT_EVENT& a, const INPUT_EVENT& b) {
        // Comparar eventos (simplificado)
        return a.type == b.type && a.keyCode == b.keyCode;
    }
    
    float CalculateMoveAccuracy(const MOUSE_MOVE& move) {
        // Calcular quão "perfeito" é o movimento
        // Baseado em smoothness, target hitting, etc.
        return 0.0f; // Placeholder
    }
};
```

#### 2. API Call Monitoring
```cpp
// Monitorar chamadas de API de input
class InputAPIMonitor {
private:
    typedef UINT(WINAPI* SendInput_t)(UINT cInputs, LPINPUT pInputs, int cbSize);
    typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE hProcess, LPVOID lpBaseAddress, 
                                              LPCVOID lpBuffer, SIZE_T nSize, 
                                              SIZE_T* lpNumberOfBytesWritten);
    
    SendInput_t oSendInput;
    WriteProcessMemory_t oWriteProcessMemory;
    
public:
    void Initialize() {
        // Hook SendInput
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalSendInput, HookedSendInput);
        DetourTransactionCommit();
        
        // Hook WriteProcessMemory
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)OriginalWriteProcessMemory, HookedWriteProcessMemory);
        DetourTransactionCommit();
    }
    
    static UINT WINAPI HookedSendInput(UINT cInputs, LPINPUT pInputs, int cbSize) {
        // Log da chamada
        LogSendInputCall(cInputs, pInputs);
        
        // Verificar se é suspeito
        if (IsSuspiciousSendInput(cInputs, pInputs)) {
            ReportInputSpoofing();
        }
        
        return oSendInput(cInputs, pInputs, cbSize);
    }
    
    static BOOL WINAPI HookedWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress,
                                               LPCVOID lpBuffer, SIZE_T nSize,
                                               SIZE_T* lpNumberOfBytesWritten) {
        // Verificar se está escrevendo em áreas de input
        if (IsInputMemoryRegion(lpBaseAddress)) {
            ReportMemoryInputSpoofing();
        }
        
        return oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, 
                                 nSize, lpNumberOfBytesWritten);
    }
    
private:
    bool IsSuspiciousSendInput(UINT cInputs, LPINPUT pInputs) {
        // Múltiplas entradas de uma vez
        if (cInputs > SUSPICIOUS_INPUT_COUNT) {
            return true;
        }
        
        // Movimento muito preciso
        for (UINT i = 0; i < cInputs; i++) {
            if (pInputs[i].type == INPUT_MOUSE) {
                if (IsPerfectMouseMovement(pInputs[i].mi)) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool IsInputMemoryRegion(LPVOID address) {
        // Verificar se endereço é área de input conhecida
        uintptr_t addr = (uintptr_t)address;
        
        // Input system addresses
        return addr >= INPUT_SYSTEM_START && addr <= INPUT_SYSTEM_END;
    }
    
    bool IsPerfectMouseMovement(const MOUSEINPUT& mi) {
        // Movimento muito suave ou preciso
        return abs(mi.dx) < 1 && abs(mi.dy) < 1 && mi.dwFlags == MOUSEEVENTF_MOVE;
    }
    
    void LogSendInputCall(UINT cInputs, LPINPUT pInputs) {
        // Log para análise posterior
        // Incluir timestamp, processo, etc.
    }
};
```

#### 3. Hardware Input Validation
```cpp
// Validação de input via hardware
class HardwareInputValidator {
private:
    HANDLE hMouseDevice;
    HANDLE hKeyboardDevice;
    
public:
    void Initialize() {
        // Abrir dispositivos de input
        OpenInputDevices();
        
        // Instalar hooks de baixo nível
        InstallLowLevelHooks();
    }
    
    void ValidateInput(const INPUT_EVENT& gameInput) {
        // Comparar input do jogo com input real do hardware
        INPUT_EVENT hardwareInput = GetHardwareInput();
        
        if (!InputsMatch(gameInput, hardwareInput)) {
            ReportInputMismatch();
        }
    }
    
    INPUT_EVENT GetHardwareInput() {
        // Ler input diretamente do hardware
        // Bypassar camadas do sistema operacional
        return ReadRawInput();
    }
    
    bool InputsMatch(const INPUT_EVENT& game, const INPUT_EVENT& hardware) {
        // Comparar timestamps
        if (abs((int)(game.timestamp - hardware.timestamp)) > INPUT_DELAY_THRESHOLD) {
            return false;
        }
        
        // Comparar valores
        if (game.type != hardware.type) return false;
        
        switch (game.type) {
            case INPUT_MOUSE:
                return MouseInputsMatch(game.mouseMove, hardware.mouseMove);
            case INPUT_KEYBOARD:
                return KeyboardInputsMatch(game.keyEvent, hardware.keyEvent);
        }
        
        return true;
    }
    
    bool MouseInputsMatch(const MOUSE_MOVE& game, const MOUSE_MOVE& hardware) {
        // Tolerância para diferenças
        const float TOLERANCE = 0.1f;
        
        return abs(game.deltaX - hardware.deltaX) < TOLERANCE &&
               abs(game.deltaY - hardware.deltaY) < TOLERANCE;
    }
    
    bool KeyboardInputsMatch(const KEY_EVENT& game, const KEY_EVENT& hardware) {
        return game.keyCode == hardware.keyCode &&
               game.pressed == hardware.pressed;
    }
    
private:
    void OpenInputDevices() {
        // Abrir /dev/input/mouse0, /dev/input/event0, etc.
        // Ou usar Windows Raw Input API
    }
    
    void InstallLowLevelHooks() {
        // Instalar hooks WH_MOUSE_LL, WH_KEYBOARD_LL
    }
    
    INPUT_EVENT ReadRawInput() {
        // Ler input raw do dispositivo
        return INPUT_EVENT(); // Placeholder
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | API monitoring | Imediato | 90% |
| VAC Live | Timing analysis | < 30s | 85% |
| BattlEye | Hardware validation | < 1 min | 95% |
| Faceit AC | Pattern analysis | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Human Input Simulation
```cpp
// ✅ Simulação de input humano
class HumanInputSimulator {
private:
    std::random_device rd;
    std::mt19937 gen;
    
public:
    void Initialize() {
        gen = std::mt19937(rd());
    }
    
    void SimulateHumanMouseMovement(const Vector2D& start, const Vector2D& end) {
        // Calcular trajetória curva
        std::vector<Vector2D> path = GenerateHumanPath(start, end);
        
        // Simular movimento com variações humanas
        for (size_t i = 1; i < path.size(); i++) {
            Vector2D delta = path[i] - path[i-1];
            
            // Adicionar variação humana
            delta += GenerateHumanVariation();
            
            // Timing variável
            DWORD delay = GenerateHumanDelay();
            
            // Mover mouse
            MoveMouse(delta.x, delta.y);
            Sleep(delay);
        }
    }
    
    void SimulateHumanKeyPress(int keyCode) {
        // Timing humano para pressionamento
        DWORD pressDelay = GenerateKeyPressDelay();
        Sleep(pressDelay);
        
        // Pressionar tecla
        PressKey(keyCode);
        
        // Timing humano para release
        DWORD releaseDelay = GenerateKeyReleaseDelay();
        Sleep(releaseDelay);
        
        // Liberar tecla
        ReleaseKey(keyCode);
    }
    
private:
    std::vector<Vector2D> GenerateHumanPath(const Vector2D& start, const Vector2D& end) {
        std::vector<Vector2D> path;
        
        // Algoritmo de Bézier para movimento curvo
        Vector2D controlPoint = GenerateControlPoint(start, end);
        
        const int STEPS = 20;
        for (int i = 0; i <= STEPS; i++) {
            float t = (float)i / STEPS;
            Vector2D point = QuadraticBezier(start, controlPoint, end, t);
            path.push_back(point);
        }
        
        return path;
    }
    
    Vector2D GenerateControlPoint(const Vector2D& start, const Vector2D& end) {
        // Gerar ponto de controle para curva natural
        Vector2D mid = (start + end) * 0.5f;
        Vector2D perpendicular = Vector2D(end.y - start.y, start.x - end.x);
        
        // Adicionar variação aleatória
        std::uniform_real_distribution<> dist(-50.0, 50.0);
        perpendicular *= dist(gen);
        
        return mid + perpendicular;
    }
    
    Vector2D QuadraticBezier(const Vector2D& p0, const Vector2D& p1, const Vector2D& p2, float t) {
        float u = 1 - t;
        return u*u*p0 + 2*u*t*p1 + t*t*p2;
    }
    
    Vector2D GenerateHumanVariation() {
        // Adicionar tremor e imprecisão humanos
        std::normal_distribution<> dist(0.0, 2.0);
        return Vector2D(dist(gen), dist(gen));
    }
    
    DWORD GenerateHumanDelay() {
        // Delay entre 8-16ms (60-120Hz)
        std::uniform_int_distribution<> dist(8, 16);
        return dist(gen);
    }
    
    DWORD GenerateKeyPressDelay() {
        // Delay humano para pressionar tecla (50-200ms)
        std::uniform_int_distribution<> dist(50, 200);
        return dist(gen);
    }
    
    DWORD GenerateKeyReleaseDelay() {
        // Delay humano para liberar tecla (30-150ms)
        std::uniform_int_distribution<> dist(30, 150);
        return dist(gen);
    }
    
    void MoveMouse(float deltaX, float deltaY) {
        // Usar SendInput com movimento relativo
        INPUT input = {0};
        input.type = INPUT_MOUSE;
        input.mi.dwFlags = MOUSEEVENTF_MOVE;
        input.mi.dx = (LONG)deltaX;
        input.mi.dy = (LONG)deltaY;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    void PressKey(int keyCode) {
        INPUT input = {0};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = keyCode;
        
        SendInput(1, &input, sizeof(INPUT));
    }
    
    void ReleaseKey(int keyCode) {
        INPUT input = {0};
        input.type = INPUT_KEYBOARD;
        input.ki.wVk = keyCode;
        input.ki.dwFlags = KEYEVENTF_KEYUP;
        
        SendInput(1, &input, sizeof(INPUT));
    }
};
```

### 2. Game-Specific Input
```cpp
// ✅ Input específico do jogo
class GameInputHandler {
private:
    uintptr_t inputSystemAddr;
    
public:
    void Initialize(uintptr_t inputAddr) {
        inputSystemAddr = inputAddr;
    }
    
    void SendGameInput(const GAME_INPUT& input) {
        // Enviar input diretamente para o sistema de input do jogo
        // Bypassar APIs do Windows
        
        switch (input.type) {
            case GAME_INPUT_MOVE:
                SendMovementInput(input.movement);
                break;
                
            case GAME_INPUT_ATTACK:
                SendAttackInput(input.attack);
                break;
                
            case GAME_INPUT_RELOAD:
                SendReloadInput(input.reload);
                break;
        }
    }
    
private:
    void SendMovementInput(const MOVEMENT_INPUT& movement) {
        // Escrever diretamente na estrutura de input do jogo
        uintptr_t movementAddr = inputSystemAddr + MOVEMENT_OFFSET;
        
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)movementAddr,
                          &movement, sizeof(MOVEMENT_INPUT), NULL);
    }
    
    void SendAttackInput(const ATTACK_INPUT& attack) {
        // Simular ataque através do sistema de input do jogo
        uintptr_t attackAddr = inputSystemAddr + ATTACK_OFFSET;
        
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)attackAddr,
                          &attack, sizeof(ATTACK_INPUT), NULL);
    }
    
    void SendReloadInput(const RELOAD_INPUT& reload) {
        // Simular reload
        uintptr_t reloadAddr = inputSystemAddr + RELOAD_OFFSET;
        
        WriteProcessMemory(GetCurrentProcess(), (LPVOID)reloadAddr,
                          &reload, sizeof(RELOAD_INPUT), NULL);
    }
};
```

### 3. Kernel-Level Input
```cpp
// ✅ Input via kernel driver
class KernelInputDriver {
private:
    HANDLE hDriver;
    
public:
    void Initialize() {
        // Carregar driver
        hDriver = CreateFile(L"\\\\.\\InputDriver", GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, 0, NULL);
    }
    
    void SendInput(const RAW_INPUT& input) {
        // Enviar input via IOCTL para o driver
        DWORD bytesReturned;
        DeviceIoControl(hDriver, IOCTL_SEND_INPUT, &input, sizeof(input),
                       NULL, 0, &bytesReturned, NULL);
    }
    
    void SimulateMouseMovement(float deltaX, float deltaY) {
        RAW_INPUT input;
        input.type = INPUT_MOUSE;
        input.mouse.deltaX = deltaX;
        input.mouse.deltaY = deltaY;
        
        SendInput(input);
    }
    
    void SimulateKeyPress(int keyCode) {
        RAW_INPUT input;
        input.type = INPUT_KEYBOARD;
        input.keyboard.keyCode = keyCode;
        input.keyboard.pressed = true;
        
        SendInput(input);
        
        // Release
        input.keyboard.pressed = false;
        SendInput(input);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Input Protection
```cpp
// VAC input spoofing detection
class VAC_InputProtector {
private:
    InputTimingAnalyzer timingAnalyzer;
    InputAPIMonitor apiMonitor;
    HardwareInputValidator hwValidator;
    
public:
    void Initialize() {
        timingAnalyzer.Initialize();
        apiMonitor.Initialize();
        hwValidator.Initialize();
    }
    
    void OnInputReceived(const INPUT_EVENT& input) {
        // Analisar timing
        timingAnalyzer.OnInputEvent(input);
        
        // Validar com hardware
        hwValidator.ValidateInput(input);
        
        // Verificar anomalias
        if (IsAnomalousInput(input)) {
            ReportInputSpoofing();
        }
    }
    
    bool IsAnomalousInput(const INPUT_EVENT& input) {
        // Verificar velocidade suspeita
        if (input.type == INPUT_MOUSE) {
            return IsSuspiciousMouseSpeed(input.mouseMove);
        }
        
        // Verificar frequência
        return IsSuspiciousKeyFrequency(input.keyEvent);
    }
    
    bool IsSuspiciousMouseSpeed(const MOUSE_MOVE& move) {
        float speed = sqrt(move.deltaX * move.deltaX + move.deltaY * move.deltaY);
        return speed > MAX_HUMAN_SPEED;
    }
    
    bool IsSuspiciousKeyFrequency(const KEY_EVENT& key) {
        // Verificar se tecla está sendo pressionada muito rápido
        return false; // Implementação específica
    }
};
```

### BattlEye Input Analysis
```cpp
// BE input analysis
void BE_AnalyzeInput() {
    // Monitor all input sources
    MonitorInputSources();
    
    // Compare game input vs hardware input
    CompareInputs();
    
    // Analyze timing patterns
    AnalyzeTiming();
}

void MonitorInputSources() {
    // Hook Windows input APIs
    // Monitor raw input devices
}

void CompareInputs() {
    // Ensure game input matches hardware input
    // Detect spoofing attempts
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | API hooks |
| 2020-2024 | ⛔ Alto risco | Hardware validation |
| 2025-2026 | ⛔ Crítico | AI analysis |

---

## 🎯 Lições Aprendadas

1. **Timing é Analisado**: Padrões regulares são facilmente detectados.

2. **APIs São Monitoradas**: SendInput e WriteProcessMemory são rastreadas.

3. **Hardware é Validado**: Input deve corresponder ao hardware real.

4. **Simulação Humana é Melhor**: Curvas e variações naturais evitam detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#22]]
- [[Human_Input_Simulation]]
- [[Game_Specific_Input]]
- [[Kernel_Level_Input]]

---

*Input spoofing é completamente obsoleto. Use simulação humana ou input específico do jogo.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
