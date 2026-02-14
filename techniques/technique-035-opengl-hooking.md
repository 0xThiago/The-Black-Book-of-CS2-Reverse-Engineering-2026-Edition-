# 📖 Técnica 035: OpenGL Hooking

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 035: OpenGL Hooking]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Graphics & Rendering  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**OpenGL Hooking** intercepta chamadas OpenGL para modificar renderização, criando wallhack, ESP ou chams. Embora menos comum que Direct3D, ainda é usado em alguns jogos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class OpenGLHooker {
private:
    HMODULE hOpenGL;
    
    // Ponteiros originais
    typedef void(__stdcall* glDrawElements_t)(GLenum mode, GLsizei count, GLenum type, const GLvoid* indices);
    glDrawElements_t oglDrawElements;
    
    typedef void(__stdcall* glDrawArrays_t)(GLenum mode, GLint first, GLsizei count);
    glDrawArrays_t oglDrawArrays;
    
    typedef void(__stdcall* glClear_t)(GLbitfield mask);
    glClear_t oglClear;
    
public:
    void Initialize() {
        // Carregar OpenGL
        hOpenGL = LoadLibraryA("opengl32.dll");
        if (!hOpenGL) return;
        
        // Hook funções OpenGL
        HookOpenGLFunctions();
    }
    
    void Cleanup() {
        // Remover hooks
        UnhookOpenGLFunctions();
        
        if (hOpenGL) FreeLibrary(hOpenGL);
    }
    
private:
    void HookOpenGLFunctions() {
        // Hook glDrawElements
        oglDrawElements = (glDrawElements_t)HookFunction(
            GetProcAddress(hOpenGL, "glDrawElements"), 
            &hkglDrawElements
        );
        
        // Hook glDrawArrays
        oglDrawArrays = (glDrawArrays_t)HookFunction(
            GetProcAddress(hOpenGL, "glDrawArrays"), 
            &hkglDrawArrays
        );
        
        // Hook glClear para ESP
        oglClear = (glClear_t)HookFunction(
            GetProcAddress(hOpenGL, "glClear"), 
            &hkglClear
        );
    }
    
    void UnhookOpenGLFunctions() {
        if (oglDrawElements) UnhookFunction(GetProcAddress(hOpenGL, "glDrawElements"), oglDrawElements);
        if (oglDrawArrays) UnhookFunction(GetProcAddress(hOpenGL, "glDrawArrays"), oglDrawArrays);
        if (oglClear) UnhookFunction(GetProcAddress(hOpenGL, "glClear"), oglClear);
    }
    
    uintptr_t HookFunction(uintptr_t targetFunc, uintptr_t hkFunc) {
        // Usar MinHook ou similar para hooking
        MH_STATUS status = MH_CreateHook((LPVOID)targetFunc, (LPVOID)hkFunc, (LPVOID*)&targetFunc);
        if (status == MH_OK) {
            MH_EnableHook((LPVOID)targetFunc);
        }
        return targetFunc;
    }
    
    void UnhookFunction(uintptr_t targetFunc, uintptr_t originalFunc) {
        MH_RemoveHook((LPVOID)targetFunc);
    }
    
    // Hook functions
    static void __stdcall hkglDrawElements(GLenum mode, GLsizei count, GLenum type, const GLvoid* indices) {
        // Modificar renderização para wallhack
        if (ShouldApplyWallhack(mode, count)) {
            ApplyWallhackState();
        }
        
        // Chamar função original
        oglDrawElements(mode, count, type, indices);
        
        // Restaurar estado se necessário
        if (ShouldApplyWallhack(mode, count)) {
            RestoreOriginalState();
        }
    }
    
    static void __stdcall hkglDrawArrays(GLenum mode, GLint first, GLsizei count) {
        // Similar ao DrawElements
        if (ShouldApplyWallhack(mode, count)) {
            ApplyWallhackState();
        }
        
        oglDrawArrays(mode, first, count);
        
        if (ShouldApplyWallhack(mode, count)) {
            RestoreOriginalState();
        }
    }
    
    static void __stdcall hkglClear(GLbitfield mask) {
        // Renderizar ESP antes do clear
        if (mask & GL_COLOR_BUFFER_BIT) {
            DrawESP();
        }
        
        // Chamar função original
        oglClear(mask);
    }
    
    static bool ShouldApplyWallhack(GLenum mode, GLsizei count) {
        // Identificar chamadas de renderização de jogadores
        // Análise de padrões de count/mode
        
        // GL_TRIANGLES com count específico para jogadores
        if (mode == GL_TRIANGLES && count > 1000 && count < 50000) {
            return true;
        }
        
        return false;
    }
    
    static void ApplyWallhackState() {
        // Desabilitar depth test
        glDisable(GL_DEPTH_TEST);
        
        // Habilitar blend para chams
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        
        // Modificar cor para chams
        glColor4f(1.0f, 0.0f, 0.0f, 0.5f); // Vermelho semi-transparente
    }
    
    static void RestoreOriginalState() {
        // Restaurar depth test
        glEnable(GL_DEPTH_TEST);
        
        // Restaurar blend
        glDisable(GL_BLEND);
        
        // Restaurar cor
        glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
    }
    
    static void DrawESP() {
        // Salvar estado OpenGL
        glPushMatrix();
        glPushAttrib(GL_ALL_ATTRIB_BITS);
        
        // Desabilitar depth test para ESP
        glDisable(GL_DEPTH_TEST);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        
        // Obter lista de jogadores
        std::vector<PlayerInfo> players = GetPlayerList();
        
        for (const PlayerInfo& player : players) {
            if (!player.isEnemy || !player.isAlive) continue;
            
            // Converter posição 3D para tela 2D
            POINT screenPos = WorldToScreen(player.position);
            
            // Desenhar ESP box
            DrawESPBox(screenPos.x, screenPos.y, player.width, player.height, player.health);
            
            // Desenhar nome
            DrawESPText(screenPos.x, screenPos.y - 20, player.name.c_str());
        }
        
        // Restaurar estado
        glPopAttrib();
        glPopMatrix();
    }
    
    static void DrawESPBox(int x, int y, int width, int height, float health) {
        // Calcular cor baseada na vida
        float r = (health < 50) ? 1.0f : 0.0f;
        float g = (health > 50) ? 1.0f : 0.0f;
        float b = 0.0f;
        float a = 1.0f;
        
        glColor4f(r, g, b, a);
        glLineWidth(2.0f);
        
        // Desenhar retângulo
        glBegin(GL_LINE_LOOP);
        glVertex2i(x - width/2, y);
        glVertex2i(x + width/2, y);
        glVertex2i(x + width/2, y + height);
        glVertex2i(x - width/2, y + height);
        glEnd();
        
        // Desenhar barra de vida
        glColor4f(1.0f, 0.0f, 0.0f, 1.0f);
        glBegin(GL_QUADS);
        glVertex2i(x - width/2 - 5, y);
        glVertex2i(x - width/2 - 2, y);
        glVertex2i(x - width/2 - 2, y + height);
        glVertex2i(x - width/2 - 5, y + height);
        glEnd();
        
        glColor4f(0.0f, 1.0f, 0.0f, 1.0f);
        int healthHeight = (int)(height * (health / 100.0f));
        glBegin(GL_QUADS);
        glVertex2i(x - width/2 - 5, y + height - healthHeight);
        glVertex2i(x - width/2 - 2, y + height - healthHeight);
        glVertex2i(x - width/2 - 2, y + height);
        glVertex2i(x - width/2 - 5, y + height);
        glEnd();
    }
    
    static void DrawESPText(int x, int y, const char* text) {
        // Usar glBitmap ou similar para texto
        // Ou integrar com biblioteca de fonte
        
        glColor4f(1.0f, 1.0f, 1.0f, 1.0f);
        glRasterPos2i(x, y);
        
        // Renderizar texto (simplificado)
        for (const char* c = text; *c; c++) {
            // glutBitmapCharacter(GLUT_BITMAP_HELVETICA_12, *c);
            // Ou usar implementação customizada
        }
    }
};
```

### OpenGL Function Hooking

```cpp
// Hooking de funções OpenGL
class OpenGLFunctionHooker {
private:
    std::map<std::string, uintptr_t> originalFunctions;
    std::map<std::string, uintptr_t> hookFunctions;
    
public:
    void Initialize() {
        // Registrar funções OpenGL importantes
        RegisterOpenGLFunctions();
        
        // Aplicar hooks
        ApplyHooks();
    }
    
    void Cleanup() {
        // Remover hooks
        RemoveHooks();
    }
    
    void RegisterOpenGLFunctions() {
        // Funções de renderização
        RegisterFunction("glDrawElements", &hkglDrawElements);
        RegisterFunction("glDrawArrays", &hkglDrawArrays);
        RegisterFunction("glDrawRangeElements", &hkglDrawRangeElements);
        
        // Funções de estado
        RegisterFunction("glEnable", &hkglEnable);
        RegisterFunction("glDisable", &hkglDisable);
        RegisterFunction("glClear", &hkglClear);
        
        // Funções de shader (OpenGL 3.0+)
        RegisterFunction("glUseProgram", &hkglUseProgram);
        RegisterFunction("glUniform1f", &hkglUniform1f);
        RegisterFunction("glUniformMatrix4fv", &hkglUniformMatrix4fv);
    }
    
    void RegisterFunction(const std::string& funcName, uintptr_t hkFunc) {
        HMODULE hOpenGL = GetModuleHandleA("opengl32.dll");
        if (!hOpenGL) return;
        
        uintptr_t originalFunc = (uintptr_t)GetProcAddress(hOpenGL, funcName.c_str());
        if (originalFunc) {
            originalFunctions[funcName] = originalFunc;
            hookFunctions[funcName] = hkFunc;
        }
    }
    
    void ApplyHooks() {
        for (auto& pair : originalFunctions) {
            const std::string& funcName = pair.first;
            uintptr_t originalFunc = pair.second;
            uintptr_t hkFunc = hookFunctions[funcName];
            
            // Usar MinHook para hooking
            MH_STATUS status = MH_CreateHook((LPVOID)originalFunc, (LPVOID)hkFunc, nullptr);
            if (status == MH_OK) {
                MH_EnableHook((LPVOID)originalFunc);
            }
        }
    }
    
    void RemoveHooks() {
        for (auto& pair : originalFunctions) {
            uintptr_t originalFunc = pair.second;
            MH_RemoveHook((LPVOID)originalFunc);
        }
    }
    
    // Hook implementations
    static void __stdcall hkglUseProgram(GLuint program) {
        // Monitorar uso de shaders
        if (IsCheatShader(program)) {
            // Reportar ou bloquear
            program = 0; // Desabilitar shader suspeito
        }
        
        // Chamar função original através de MinHook
        return; // MinHook cuida da chamada original
    }
    
    static void __stdcall hkglUniform1f(GLint location, GLfloat v0) {
        // Monitorar uniforms suspeitos
        if (IsSuspiciousUniform(location, v0)) {
            // Modificar valor
            v0 = 0.0f; // Desabilitar efeito
        }
        
        return;
    }
    
    static void __stdcall hkglUniformMatrix4fv(GLint location, GLsizei count, GLboolean transpose, const GLfloat* value) {
        // Monitorar matrizes de transformação
        if (IsSuspiciousMatrix(location, value)) {
            // Modificar matriz
            // ... código para modificar matriz ...
        }
        
        return;
    }
    
    static bool IsCheatShader(GLuint program) {
        // Verificar se shader tem características de cheat
        // Análise de bytecode do shader
        
        return false; // Placeholder
    }
    
    static bool IsSuspiciousUniform(GLint location, GLfloat value) {
        // Verificar uniforms suspeitos
        // Exemplo: valores que desabilitam depth test
        
        return false; // Placeholder
    }
    
    static bool IsSuspiciousMatrix(GLint location, const GLfloat* value) {
        // Verificar matrizes suspeitas
        // Exemplo: projeção modificada para wallhack
        
        return false; // Placeholder
    }
};
```

### Por que é Detectado

> [!WARNING]
> **OpenGL hooking deixa rastros através de modificações de estado e shaders suspeitos**

#### 1. OpenGL State Monitoring
```cpp
// Monitoramento de estado OpenGL
class OpenGLStateMonitor {
private:
    std::map<GLenum, GLboolean> glStates;
    std::map<GLenum, GLint> glStateValues;
    
public:
    void Initialize() {
        // Registrar estados OpenGL padrão
        RegisterDefaultStates();
        
        // Hook funções de estado
        HookStateFunctions();
    }
    
    void CheckStateIntegrity() {
        // Verificar se estados foram modificados
        for (auto& pair : glStates) {
            GLenum cap = pair.first;
            GLboolean expected = pair.second;
            
            GLboolean current;
            glGetBooleanv(cap, &current);
            
            if (current != expected) {
                ReportStateModification(cap, expected, current);
            }
        }
    }
    
    void RegisterDefaultStates() {
        // Estados padrão do jogo
        glStates[GL_DEPTH_TEST] = GL_TRUE;
        glStates[GL_BLEND] = GL_FALSE;
        glStates[GL_CULL_FACE] = GL_TRUE;
        glStates[GL_TEXTURE_2D] = GL_TRUE;
        
        // Valores padrão
        glStateValues[GL_BLEND_SRC] = GL_ONE;
        glStateValues[GL_BLEND_DST] = GL_ZERO;
    }
    
    void HookStateFunctions() {
        // Hook glEnable/glDisable
        HookFunction("glEnable", &hkglEnable);
        HookFunction("glDisable", &hkglDisable);
        
        // Hook glBlendFunc
        HookFunction("glBlendFunc", &hkglBlendFunc);
    }
    
    void HookFunction(const std::string& funcName, uintptr_t hkFunc) {
        HMODULE hOpenGL = GetModuleHandleA("opengl32.dll");
        uintptr_t originalFunc = (uintptr_t)GetProcAddress(hOpenGL, funcName.c_str());
        
        MH_CreateHook((LPVOID)originalFunc, (LPVOID)hkFunc, nullptr);
        MH_EnableHook((LPVOID)originalFunc);
    }
    
    static void __stdcall hkglEnable(GLenum cap) {
        // Verificar se habilitação é suspeita
        if (IsSuspiciousEnable(cap)) {
            ReportSuspiciousEnable(cap);
        }
        
        return; // MinHook chama original
    }
    
    static void __stdcall hkglDisable(GLenum cap) {
        // Verificar se desabilitação é suspeita
        if (IsSuspiciousDisable(cap)) {
            ReportSuspiciousDisable(cap);
        }
        
        return;
    }
    
    static void __stdcall hkglBlendFunc(GLenum sfactor, GLenum dfactor) {
        // Verificar função de blend suspeita
        if (IsSuspiciousBlendFunc(sfactor, dfactor)) {
            ReportSuspiciousBlendFunc(sfactor, dfactor);
        }
        
        return;
    }
    
    static bool IsSuspiciousEnable(GLenum cap) {
        // GL_DEPTH_TEST desabilitado
        if (cap == GL_DEPTH_TEST) {
            return true;
        }
        
        // GL_BLEND habilitado inesperadamente
        if (cap == GL_BLEND) {
            return true;
        }
        
        return false;
    }
    
    static bool IsSuspiciousDisable(GLenum cap) {
        // GL_CULL_FACE desabilitado
        if (cap == GL_CULL_FACE) {
            return true;
        }
        
        return false;
    }
    
    static bool IsSuspiciousBlendFunc(GLenum sfactor, GLenum dfactor) {
        // Blend function típica de chams
        if (sfactor == GL_SRC_ALPHA && dfactor == GL_ONE_MINUS_SRC_ALPHA) {
            return true;
        }
        
        return false;
    }
};
```

#### 2. Shader Program Analysis
```cpp
// Análise de programas shader
class ShaderProgramAnalyzer {
private:
    std::set<GLuint> knownPrograms;
    std::map<GLuint, ShaderInfo> shaderInfo;
    
public:
    void Initialize() {
        // Registrar programas shader legítimos
        EnumerateLegitimateShaders();
        
        // Hook funções de shader
        HookShaderFunctions();
    }
    
    void OnShaderCreation(GLuint program) {
        // Verificar se shader é suspeito
        if (IsSuspiciousShader(program)) {
            ReportSuspiciousShader(program);
        }
        
        // Adicionar aos shaders conhecidos
        knownPrograms.insert(program);
        
        // Extrair informações do shader
        ExtractShaderInfo(program);
    }
    
    void OnShaderUsage(GLuint program) {
        // Verificar uso suspeito
        if (IsSuspiciousShaderUsage(program)) {
            ReportSuspiciousShaderUsage(program);
        }
    }
    
    bool IsSuspiciousShader(GLuint program) {
        // Analisar código fonte do shader
        const char* source = GetShaderSource(program);
        if (source) {
            return AnalyzeShaderSource(source);
        }
        
        // Analisar bytecode
        return AnalyzeShaderBytecode(program);
    }
    
    bool AnalyzeShaderSource(const char* source) {
        std::string src(source);
        
        // Procurar por padrões suspeitos
        if (src.find("discard") != std::string::npos) {
            // Pixel shader que descarta pixels (wallhack)
            return true;
        }
        
        if (src.find("gl_FragColor.a = 0.5") != std::string::npos) {
            // Semi-transparente (chams)
            return true;
        }
        
        return false;
    }
    
    bool AnalyzeShaderBytecode(GLuint program) {
        // Obter bytecode do shader
        GLint size;
        glGetProgramiv(program, GL_PROGRAM_BINARY_LENGTH, &size);
        
        if (size > 0) {
            std::vector<char> binary(size);
            GLenum format;
            glGetProgramBinary(program, size, nullptr, &format, binary.data());
            
            // Analisar bytecode
            return ContainsSuspiciousBytecode(binary);
        }
        
        return false;
    }
    
    bool ContainsSuspiciousBytecode(const std::vector<char>& binary) {
        // Procurar por instruções suspeitas no bytecode
        // Análise simplificada
        
        return false; // Placeholder
    }
    
    bool IsSuspiciousShaderUsage(GLuint program) {
        // Verificar frequência de uso
        // ou uso em contextos suspeitos
        
        return false; // Placeholder
    }
    
    const char* GetShaderSource(GLuint program) {
        // Obter código fonte dos shaders anexados
        GLint numShaders;
        glGetProgramiv(program, GL_ATTACHED_SHADERS, &numShaders);
        
        for (GLint i = 0; i < numShaders; i++) {
            GLuint shader = 0;
            glGetAttachedShaders(program, 1, nullptr, &shader);
            
            if (shader) {
                GLint length;
                glGetShaderiv(shader, GL_SHADER_SOURCE_LENGTH, &length);
                
                if (length > 0) {
                    char* source = new char[length];
                    glGetShaderSource(shader, length, nullptr, source);
                    
                    // Verificar se é suspeito
                    if (AnalyzeShaderSource(source)) {
                        delete[] source;
                        return source; // Retornar fonte suspeita
                    }
                    
                    delete[] source;
                }
            }
        }
        
        return nullptr;
    }
    
    void ExtractShaderInfo(GLuint program) {
        ShaderInfo info;
        
        // Extrair metadados do shader
        glGetProgramiv(program, GL_ACTIVE_UNIFORMS, &info.numUniforms);
        glGetProgramiv(program, GL_ACTIVE_ATTRIBUTES, &info.numAttributes);
        
        // ... mais extração ...
        
        shaderInfo[program] = info;
    }
    
    void HookShaderFunctions() {
        HookFunction("glCreateProgram", &hkglCreateProgram);
        HookFunction("glUseProgram", &hkglUseProgram);
        HookFunction("glLinkProgram", &hkglLinkProgram);
    }
    
    void HookFunction(const std::string& funcName, uintptr_t hkFunc) {
        HMODULE hOpenGL = GetModuleHandleA("opengl32.dll");
        uintptr_t originalFunc = (uintptr_t)GetProcAddress(hOpenGL, funcName.c_str());
        
        MH_CreateHook((LPVOID)originalFunc, (LPVOID)hkFunc, nullptr);
        MH_EnableHook((LPVOID)originalFunc);
    }
    
    static void __stdcall hkglCreateProgram() {
        GLuint program = glCreateProgram(); // Chamar original primeiro
        
        // Registrar programa criado
        OnShaderCreation(program);
        
        return program;
    }
    
    static void __stdcall hkglUseProgram(GLuint program) {
        // Verificar uso
        OnShaderUsage(program);
        
        return; // MinHook chama original
    }
    
    static void __stdcall hkglLinkProgram(GLuint program) {
        // Chamar original primeiro
        glLinkProgram(program);
        
        // Verificar linking
        GLint linkStatus;
        glGetProgramiv(program, GL_LINK_STATUS, &linkStatus);
        
        if (linkStatus == GL_TRUE) {
            OnShaderCreation(program);
        }
    }
};
```

#### 3. Draw Call Analysis
```cpp
// Análise de chamadas de desenho
class DrawCallAnalyzer {
private:
    std::vector<DrawCallInfo> drawCalls;
    
public:
    void Initialize() {
        // Hook funções de desenho
        HookDrawFunctions();
    }
    
    void AnalyzeDrawCalls() {
        // Analisar padrão de draw calls
        DetectSuspiciousPatterns();
    }
    
    void HookDrawFunctions() {
        HookFunction("glDrawElements", &hkglDrawElements);
        HookFunction("glDrawArrays", &hkglDrawArrays);
        HookFunction("glDrawRangeElements", &hkglDrawRangeElements);
    }
    
    void HookFunction(const std::string& funcName, uintptr_t hkFunc) {
        HMODULE hOpenGL = GetModuleHandleA("opengl32.dll");
        uintptr_t originalFunc = (uintptr_t)GetProcAddress(hOpenGL, funcName.c_str());
        
        MH_CreateHook((LPVOID)originalFunc, (LPVOID)hkFunc, nullptr);
        MH_EnableHook((LPVOID)originalFunc);
    }
    
    static void __stdcall hkglDrawElements(GLenum mode, GLsizei count, GLenum type, const GLvoid* indices) {
        // Registrar draw call
        DrawCallInfo info;
        info.mode = mode;
        info.count = count;
        info.type = type;
        info.timestamp = GetTickCount();
        
        drawCalls.push_back(info);
        
        // Limitar tamanho do buffer
        if (drawCalls.size() > 1000) {
            drawCalls.erase(drawCalls.begin());
        }
        
        return; // MinHook chama original
    }
    
    static void __stdcall hkglDrawArrays(GLenum mode, GLint first, GLsizei count) {
        // Similar ao DrawElements
        DrawCallInfo info;
        info.mode = mode;
        info.count = count;
        info.first = first;
        info.timestamp = GetTickCount();
        
        drawCalls.push_back(info);
        
        if (drawCalls.size() > 1000) {
            drawCalls.erase(drawCalls.begin());
        }
        
        return;
    }
    
    void DetectSuspiciousPatterns() {
        // Analisar padrões de draw calls
        if (drawCalls.size() < 10) return;
        
        // Procurar por draw calls duplicadas (wallhack)
        std::map<std::tuple<GLenum, GLsizei, GLenum>, int> callCounts;
        
        for (const DrawCallInfo& call : drawCalls) {
            auto key = std::make_tuple(call.mode, call.count, call.type);
            callCounts[key]++;
        }
        
        for (auto& pair : callCounts) {
            if (pair.second > 5) { // Mesmo draw call repetido muitas vezes
                ReportSuspiciousDrawCallPattern(pair.first, pair.second);
            }
        }
        
        // Procurar por mudanças repentinas no count
        for (size_t i = 1; i < drawCalls.size(); i++) {
            const DrawCallInfo& prev = drawCalls[i-1];
            const DrawCallInfo& curr = drawCalls[i];
            
            if (abs((int)curr.count - (int)prev.count) > 10000) {
                ReportSuddenDrawCallChange(prev, curr);
            }
        }
    }
    
    void ReportSuspiciousDrawCallPattern(std::tuple<GLenum, GLsizei, GLenum> pattern, int count) {
        // Reportar padrão suspeito
        GLenum mode; GLsizei count_val; GLenum type;
        std::tie(mode, count_val, type) = pattern;
        
        // Log ou report
    }
    
    void ReportSuddenDrawCallChange(const DrawCallInfo& prev, const DrawCallInfo& curr) {
        // Reportar mudança repentina
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | OpenGL state monitoring | < 30s | 75% |
| VAC Live | Shader analysis | Imediato | 70% |
| BattlEye | Draw call analysis | < 1 min | 80% |
| Faceit AC | Function hooking detection | < 30s | 65% |

---

## 🔄 Alternativas Seguras

### 1. OpenGL Overlay
```cpp
// ✅ Overlay OpenGL
class OpenGLOverlay {
private:
    HDC hDC;
    HGLRC hRC;
    HWND hOverlayWindow;
    
public:
    void Initialize() {
        // Criar janela overlay
        CreateOverlayWindow();
        
        // Inicializar OpenGL para overlay
        InitializeOverlayGL();
    }
    
    void RenderOverlay() {
        // Fazer overlay window topmost
        SetWindowPos(hOverlayWindow, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        
        // Renderizar ESP
        wglMakeCurrent(hDC, hRC);
        
        glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
        glLoadIdentity();
        
        DrawESP();
        
        SwapBuffers(hDC);
    }
    
    void Cleanup() {
        wglDeleteContext(hRC);
        DestroyWindow(hOverlayWindow);
    }
    
private:
    void CreateOverlayWindow() {
        hOverlayWindow = CreateWindowExA(
            WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED,
            "OverlayWindow", "Overlay",
            WS_POPUP,
            0, 0, 1920, 1080,
            NULL, NULL, GetModuleHandle(NULL), NULL
        );
        
        // Tornar transparente
        SetLayeredWindowAttributes(hOverlayWindow, RGB(0, 0, 0), 0, LWA_COLORKEY);
        ShowWindow(hOverlayWindow, SW_SHOW);
    }
    
    void InitializeOverlayGL() {
        hDC = GetDC(hOverlayWindow);
        
        PIXELFORMATDESCRIPTOR pfd = {0};
        pfd.nSize = sizeof(pfd);
        pfd.nVersion = 1;
        pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
        pfd.iPixelType = PFD_TYPE_RGBA;
        pfd.cColorBits = 32;
        pfd.cDepthBits = 24;
        
        int pixelFormat = ChoosePixelFormat(hDC, &pfd);
        SetPixelFormat(hDC, pixelFormat, &pfd);
        
        hRC = wglCreateContext(hDC);
    }
    
    void DrawESP() {
        // Desabilitar depth test
        glDisable(GL_DEPTH_TEST);
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
        
        // Obter lista de jogadores
        std::vector<PlayerInfo> players = GetPlayerList();
        
        for (const PlayerInfo& player : players) {
            if (!player.isEnemy || !player.isAlive) continue;
            
            POINT screenPos = WorldToScreen(player.position);
            
            // Desenhar ESP
            DrawESPBox(screenPos.x, screenPos.y, player.width, player.height);
        }
    }
    
    void DrawESPBox(int x, int y, int width, int height) {
        glColor4f(1.0f, 0.0f, 0.0f, 1.0f);
        glLineWidth(2.0f);
        
        glBegin(GL_LINE_LOOP);
        glVertex2i(x - width/2, y);
        glVertex2i(x + width/2, y);
        glVertex2i(x + width/2, y + height);
        glVertex2i(x - width/2, y + height);
        glEnd();
    }
};
```

### 2. Framebuffer Copy
```cpp
// ✅ Cópia de framebuffer
class FramebufferCopier {
private:
    GLuint fbo;
    GLuint texture;
    GLsizei width, height;
    
public:
    void Initialize() {
        // Criar FBO para captura
        glGenFramebuffers(1, &fbo);
        glGenTextures(1, &texture);
        
        // Obter dimensões da tela
        glGetRenderbufferParameteriv(GL_RENDERBUFFER, GL_RENDERBUFFER_WIDTH, &width);
        glGetRenderbufferParameteriv(GL_RENDERBUFFER, GL_RENDERBUFFER_HEIGHT, &height);
        
        // Configurar textura
        glBindTexture(GL_TEXTURE_2D, texture);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, nullptr);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        
        glBindFramebuffer(GL_FRAMEBUFFER, fbo);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, texture, 0);
    }
    
    void CaptureFrame() {
        // Copiar framebuffer
        glBindFramebuffer(GL_READ_FRAMEBUFFER, 0); // Default framebuffer
        glBindFramebuffer(GL_DRAW_FRAMEBUFFER, fbo);
        glBlitFramebuffer(0, 0, width, height, 0, 0, width, height, GL_COLOR_BUFFER_BIT, GL_NEAREST);
        
        // Processar imagem capturada
        ProcessCapturedFrame();
    }
    
    void ProcessCapturedFrame() {
        // Ler pixels da textura
        std::vector<unsigned char> pixels(width * height * 4);
        glBindTexture(GL_TEXTURE_2D, texture);
        glGetTexImage(GL_TEXTURE_2D, 0, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        
        // Analisar pixels para detectar jogadores
        DetectPlayersInFrame(pixels);
        
        // Aplicar modificações (ESP)
        ApplyESPToFrame(pixels);
        
        // Renderizar frame modificado
        RenderModifiedFrame(pixels);
    }
    
    void DetectPlayersInFrame(const std::vector<unsigned char>& pixels) {
        // Usar visão computacional para detectar jogadores
        // Análise de cor, forma, movimento
        
        // Placeholder: detectar pixels vermelhos (inimigos)
        for (size_t i = 0; i < pixels.size(); i += 4) {
            unsigned char r = pixels[i];
            unsigned char g = pixels[i+1];
            unsigned char b = pixels[i+2];
            
            if (r > 200 && g < 100 && b < 100) {
                // Pixel vermelho detectado - possível jogador
                int x = (i / 4) % width;
                int y = (i / 4) / width;
                
                // Adicionar à lista de detecções
                AddPlayerDetection(x, y);
            }
        }
    }
    
    void ApplyESPToFrame(std::vector<unsigned char>& pixels) {
        // Aplicar ESP modificando pixels
        for (auto& detection : playerDetections) {
            // Desenhar box ESP nos pixels
            DrawESPBoxOnPixels(pixels, detection.x, detection.y, detection.width, detection.height);
        }
    }
    
    void RenderModifiedFrame(const std::vector<unsigned char>& pixels) {
        // Renderizar frame modificado de volta
        glBindTexture(GL_TEXTURE_2D, texture);
        glTexSubImage2D(GL_TEXTURE_2D, 0, 0, 0, width, height, GL_RGBA, GL_UNSIGNED_BYTE, pixels.data());
        
        // Renderizar textura na tela
        glBindFramebuffer(GL_FRAMEBUFFER, 0); // Back to default
        glEnable(GL_TEXTURE_2D);
        glBindTexture(GL_TEXTURE_2D, texture);
        
        glBegin(GL_QUADS);
        glTexCoord2f(0.0f, 1.0f); glVertex2f(-1.0f, -1.0f);
        glTexCoord2f(1.0f, 0.0f); glVertex2f(1.0f, -1.0f);
        glTexCoord2f(1.0f, 1.0f); glVertex2f(1.0f, 1.0f);
        glTexCoord2f(0.0f, 0.0f); glVertex2f(-1.0f, 1.0f);
        glEnd();
        
        glDisable(GL_TEXTURE_2D);
    }
    
    void DrawESPBoxOnPixels(std::vector<unsigned char>& pixels, int x, int y, int w, int h) {
        // Desenhar retângulo vermelho nos pixels
        for (int dy = 0; dy < h; dy++) {
            for (int dx = 0; dx < w; dx++) {
                if (dx == 0 || dx == w-1 || dy == 0 || dy == h-1) { // Apenas bordas
                    int pixelIndex = ((y + dy) * width + (x + dx)) * 4;
                    if (pixelIndex < pixels.size()) {
                        pixels[pixelIndex] = 255;     // R
                        pixels[pixelIndex + 1] = 0;   // G
                        pixels[pixelIndex + 2] = 0;   // B
                        pixels[pixelIndex + 3] = 255; // A
                    }
                }
            }
        }
    }
};
```

### 3. Shader Uniform Modification
```cpp
// ✅ Modificação de uniforms de shader
class ShaderUniformModifier {
private:
    std::map<GLuint, ShaderUniforms> shaderUniforms;
    
public:
    void Initialize() {
        // Hook funções de uniform
        HookUniformFunctions();
    }
    
    void ModifyWallhackUniforms() {
        // Encontrar shader de wallhack
        GLuint wallhackShader = FindWallhackShader();
        
        if (wallhackShader) {
            // Modificar uniforms para desabilitar wallhack
            ModifyShaderUniforms(wallhackShader);
        }
    }
    
    void HookUniformFunctions() {
        HookFunction("glUniform1f", &hkglUniform1f);
        HookFunction("glUniform2f", &hkglUniform2f);
        HookFunction("glUniform3f", &hkglUniform3f);
        HookFunction("glUniform4f", &hkglUniform4f);
        HookFunction("glUniformMatrix4fv", &hkglUniformMatrix4fv);
    }
    
    void HookFunction(const std::string& funcName, uintptr_t hkFunc) {
        HMODULE hOpenGL = GetModuleHandleA("opengl32.dll");
        uintptr_t originalFunc = (uintptr_t)GetProcAddress(hOpenGL, funcName.c_str());
        
        MH_CreateHook((LPVOID)originalFunc, (LPVOID)hkFunc, nullptr);
        MH_EnableHook((LPVOID)originalFunc);
    }
    
    static void __stdcall hkglUniform1f(GLint location, GLfloat v0) {
        // Verificar se uniform é suspeito
        if (IsWallhackUniform(location)) {
            // Modificar valor para desabilitar wallhack
            v0 = 1.0f; // Reabilitar depth test
        }
        
        return; // MinHook chama original
    }
    
    static void __stdcall hkglUniformMatrix4fv(GLint location, GLsizei count, GLboolean transpose, const GLfloat* value) {
        // Verificar se é matriz de projeção modificada
        if (IsModifiedProjectionMatrix(location, value)) {
            // Restaurar matriz original
            // ... código para restaurar matriz ...
        }
        
        return;
    }
    
    static bool IsWallhackUniform(GLint location) {
        // Verificar se location corresponde a uniform de depth test
        // ou outro uniform suspeito
        
        return false; // Placeholder
    }
    
    static bool IsModifiedProjectionMatrix(GLint location, const GLfloat* value) {
        // Verificar se matriz de projeção foi modificada para wallhack
        // Comparar com matriz esperada
        
        return false; // Placeholder
    }
    
    GLuint FindWallhackShader() {
        // Procurar shader que está sendo usado para wallhack
        // Baseado em padrões de uso ou bytecode
        
        return 0; // Placeholder
    }
    
    void ModifyShaderUniforms(GLuint shader) {
        // Modificar uniforms do shader para desabilitar efeitos de cheat
        glUseProgram(shader);
        
        // Encontrar locations dos uniforms
        GLint depthTestLoc = glGetUniformLocation(shader, "depthTestEnabled");
        if (depthTestLoc != -1) {
            glUniform1f(depthTestLoc, 1.0f); // Reabilitar depth test
        }
        
        // ... mais modificações ...
        
        glUseProgram(0);
    }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | State monitoring |
| 2020-2024 | ⚠️ Médio risco | Shader analysis |
| 2025-2026 | ⚠️ Alto risco | Draw call analysis |

---

## 🎯 Lições Aprendidas

1. **Estado OpenGL é Monitorado**: Mudanças em GL_DEPTH_TEST, GL_BLEND são detectadas.

2. **Shaders São Analisados**: Bytecode e código fonte são verificados.

3. **Draw Calls São Rastreadas**: Padrões suspeitos são identificados.

4. **Overlay Externo é Melhor**: Renderização independente é menos detectável.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#35]]
- [[OpenGL_Overlay]]
- [[Framebuffer_Copying]]
- [[Shader_Uniform_Modification]]

---

*OpenGL hooking tem risco moderado. Considere overlay externo para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
