# 📖 Técnica 010: Direct3D Hooking

🔗 Link do vídeo: Não informado
📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 010: Direct3D Hooking]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Graphics & Rendering  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Direct3D Hooking** envolve interceptar chamadas da API Direct3D para modificar rendering. Embora ainda usado em alguns cheats modernos, é detectável pelos sistemas anti-cheat que monitoram hooks gráficos.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO COM RISCO MODERADO
class D3D9Hook {
private:
    IDirect3DDevice9* pDevice;
    uintptr_t* vtable;
    
public:
    void Initialize() {
        // Obter dispositivo D3D9
        pDevice = GetD3D9Device();
        vtable = *(uintptr_t**)pDevice;
        
        // Hook EndScene
        OriginalEndScene = (EndScene_t)vtable[42];
        vtable[42] = (uintptr_t)HookedEndScene;
        
        // Hook Present
        OriginalPresent = (Present_t)vtable[17];
        vtable[17] = (uintptr_t)HookedPresent;
    }
    
    HRESULT HookedEndScene() {
        // Renderizar overlays (ESP, etc)
        DrawESP();
        DrawAimbotFOV();
        
        return OriginalEndScene(pDevice);
    }
    
    HRESULT HookedPresent(const RECT* pSourceRect, const RECT* pDestRect,
                         HWND hDestWindowOverride, const RGNDATA* pDirtyRegion) {
        // Modificar apresentação final
        ApplyColorCorrections();
        
        return OriginalPresent(pDevice, pSourceRect, pDestRect, 
                             hDestWindowOverride, pDirtyRegion);
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Hooks gráficos são detectáveis através de vtable scanning e integrity checks**

#### 1. VTable Integrity Checks
```cpp
// Verificar integridade da vtable
void CheckD3DVTableIntegrity() {
    IDirect3DDevice9* device = GetD3D9Device();
    uintptr_t* vtable = *(uintptr_t**)device;
    
    // Comparar com vtable original
    for (int i = 0; i < D3D9_VTABLE_SIZE; i++) {
        if (vtable[i] != OriginalD3DVTable[i]) {
            LogVTableModification(i, vtable[i]);
        }
    }
}

// Hook detection via memory scanning
void ScanForD3DHooks() {
    // Enumerar todos os módulos
    EnumModules();
    
    for (auto& module : modules) {
        // Verificar se módulo contém hooks D3D
        if (ContainsD3DHook(module)) {
            ReportD3DHook(module);
        }
    }
}
```

#### 2. Graphics API Monitoring
```cpp
// Monitorar chamadas gráficas suspeitas
class GraphicsAPIMonitor {
private:
    std::vector<D3D_CALL> callLog;
    
public:
    void OnD3DCall(D3D_CALL_TYPE type, void* params) {
        D3D_CALL call = {type, params, GetTickCount()};
        callLog.push_back(call);
        
        AnalyzeCallPattern();
    }
    
    void AnalyzeCallPattern() {
        // Detectar padrões de wallhack
        if (HasWallhackPattern()) {
            ReportWallhack();
        }
        
        // Detectar aimbot via mouse manipulation
        if (HasAimbotPattern()) {
            ReportAimbot();
        }
        
        // Detectar ESP via text rendering
        if (HasESPPattern()) {
            ReportESP();
        }
    }
    
    bool HasWallhackPattern() {
        // Verificar chamadas de depth buffer manipulation
        int depthCalls = CountCallsInTimeframe(D3D_SETDEPTHSTENCIL, 1000);
        return depthCalls > NORMAL_DEPTH_CALLS;
    }
    
    bool HasESPPattern() {
        // Verificar text rendering excessivo
        int textCalls = CountCallsInTimeframe(D3D_DRAWTEXT, 1000);
        return textCalls > NORMAL_TEXT_CALLS;
    }
};
```

#### 3. Shader Analysis
```cpp
// Analisar shaders modificados
void AnalyzeShaders() {
    // Enumerar shaders ativos
    EnumActiveShaders();
    
    for (auto& shader : activeShaders) {
        // Verificar se shader foi modificado
        if (IsModifiedShader(shader)) {
            ReportShaderModification(shader);
        }
        
        // Verificar padrões de cheat
        if (HasCheatShaderPattern(shader)) {
            ReportCheatShader(shader);
        }
    }
}

bool HasCheatShaderPattern(const SHADER_INFO& shader) {
    // Wallhack: shaders que ignoram depth
    if (IgnoresDepthBuffer(shader)) return true;
    
    // Chams: shaders com glow effects
    if (HasGlowEffect(shader)) return true;
    
    // No recoil: shaders que modificam view matrix
    if (ModifiesViewMatrix(shader)) return true;
    
    return false;
}
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | VTable scanning | < 30s | 90% |
| VAC Live | API monitoring | Imediato | 95% |
| BattlEye | Shader analysis | < 1 min | 85% |
| Faceit AC | Call patterns | < 30s | 80% |

---

## 🔄 Alternativas Seguras

### 1. Vulkan Layer Injection
```cpp
// ✅ Vulkan layers para graphics hooking
class VulkanLayerHook {
private:
    VkInstance instance;
    VkDevice device;
    
public:
    void Initialize() {
        // Criar layer Vulkan
        const char* layers[] = {"VK_LAYER_CHEAT_LAYER"};
        
        VkInstanceCreateInfo createInfo = {};
        createInfo.enabledLayerCount = 1;
        createInfo.ppEnabledLayerNames = layers;
        
        vkCreateInstance(&createInfo, nullptr, &instance);
    }
    
    // Interceptar draw calls
    VkResult HookedQueueSubmit(VkQueue queue, uint32_t submitCount,
                              const VkSubmitInfo* pSubmits, VkFence fence) {
        // Modificar draw calls antes da submissão
        ModifyDrawCalls(pSubmits, submitCount);
        
        return OriginalQueueSubmit(queue, submitCount, pSubmits, fence);
    }
    
    void ModifyDrawCalls(const VkSubmitInfo* pSubmits, uint32_t count) {
        for (uint32_t i = 0; i < count; i++) {
            for (uint32_t j = 0; j < pSubmits[i].commandBufferCount; j++) {
                // Injetar comandos de cheat
                InjectCheatCommands(pSubmits[i].pCommandBuffers[j]);
            }
        }
    }
};
```

### 2. GPU Memory Manipulation
```cpp
// ✅ Manipulação direta de memória GPU
class GPUMemoryManipulator {
private:
    ID3D11Device* device;
    ID3D11DeviceContext* context;
    
public:
    void Initialize() {
        // Obter device D3D11
        D3D11CreateDevice(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0,
                         nullptr, 0, D3D11_SDK_VERSION, &device, nullptr, &context);
    }
    
    void ManipulateFrameBuffer() {
        // Mapear back buffer
        ID3D11Texture2D* backBuffer;
        ID3D11RenderTargetView* rtv;
        
        // Obter back buffer atual
        GetCurrentBackBuffer(&backBuffer, &rtv);
        
        // Mapear para CPU access
        D3D11_MAPPED_SUBRESOURCE mapped;
        context->Map(backBuffer, 0, D3D11_MAP_READ_WRITE, 0, &mapped);
        
        // Modificar pixels diretamente
        ModifyPixels((uint32_t*)mapped.pData, mapped.RowPitch / 4, GetBackBufferHeight());
        
        context->Unmap(backBuffer, 0);
    }
    
    void ModifyPixels(uint32_t* pixels, int width, int height) {
        // Aplicar wallhack: tornar paredes transparentes
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                uint32_t pixel = pixels[y * width + x];
                
                // Detectar pixels de parede
                if (IsWallPixel(pixel)) {
                    // Tornar transparente
                    pixels[y * width + x] = MakeTransparent(pixel);
                }
            }
        }
    }
};
```

### 3. Compute Shader Injection
```cpp
// ✅ Injeção de compute shaders
class ComputeShaderInjector {
private:
    ID3D11ComputeShader* cheatShader;
    
public:
    void Initialize() {
        // Criar compute shader para cheat
        const char* shaderCode = R"(
            RWTexture2D<float4> backBuffer : register(u0);
            
            [numthreads(8, 8, 1)]
            void CSMain(uint3 dispatchId : SV_DispatchThreadID) {
                // Aplicar efeitos de cheat
                float4 color = backBuffer[dispatchId.xy];
                
                // Wallhack: reduzir opacidade de paredes
                if (IsWallColor(color)) {
                    color.a *= 0.3;
                }
                
                backBuffer[dispatchId.xy] = color;
            }
        )";
        
        // Compilar e criar shader
        CompileAndCreateShader(shaderCode);
    }
    
    void ApplyCheat() {
        // Bind shader
        context->CSSetShader(cheatShader, nullptr, 0);
        
        // Bind back buffer como UAV
        ID3D11UnorderedAccessView* uav = GetBackBufferUAV();
        context->CSSetUnorderedAccessViews(0, 1, &uav, nullptr);
        
        // Dispatch
        context->Dispatch(backBufferWidth / 8, backBufferHeight / 8, 1);
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC Graphics Monitor
```cpp
// VAC graphics hooking detection
class VAC_GraphicsMonitor {
private:
    std::vector<uintptr_t> originalVTable;
    
public:
    void Initialize() {
        // Capturar vtable original
        CaptureOriginalVTable();
        
        // Iniciar monitoring
        StartGraphicsMonitoring();
    }
    
    void CheckIntegrity() {
        uintptr_t* currentVTable = GetCurrentVTable();
        
        for (size_t i = 0; i < originalVTable.size(); i++) {
            if (currentVTable[i] != originalVTable[i]) {
                ReportVTableHook(i, currentVTable[i]);
            }
        }
    }
    
    void AnalyzeAPICalls() {
        // Monitorar padrões de chamada
        if (HasSuspiciousCallPattern()) {
            ReportGraphicsCheat();
        }
    }
};
```

### BattlEye Shader Scanner
```cpp
// BE shader analysis system
void BE_AnalyzeShaders() {
    // Enumerate all active shaders
    EnumShaders();
    
    for (auto& shader : shaders) {
        // Check shader bytecode
        if (IsModifiedShader(shader)) {
            ReportModifiedShader(shader);
        }
        
        // Check for cheat patterns
        if (ContainsCheatCode(shader)) {
            ReportCheatShader(shader);
        }
    }
}

bool ContainsCheatCode(const SHADER_BYTECODE& shader) {
    // Look for wallhack patterns
    if (HasDepthIgnoreCode(shader)) return true;
    
    // Look for glow/chams patterns
    if (HasGlowCode(shader)) return true;
    
    // Look for color manipulation
    if (HasColorModCode(shader)) return true;
    
    return false;
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ✅ Funcional | Básica |
| 2015-2020 | ⚠️ Risco | VTable checks |
| 2020-2024 | ⚠️ Risco | API monitoring |
| 2025-2026 | ⚠️ Moderado | Shader analysis |

---

## 🎯 Lições Aprendidas

1. **VTable é Monitorada**: Modificações na tabela virtual são detectadas.

2. **Shaders São Analisados**: Bytecode de shaders é examinado.

3. **Padrões São Reconhecidos**: Sequências de chamadas revelam cheats.

4. **Vulkan é Mais Seguro**: Layers Vulkan são menos detectáveis.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#10]]
- [[Vulkan_Layer_Injection]]
- [[GPU_Memory_Manipulation]]
- [[Compute_Shader_Injection]]

---

*D3D hooking ainda funciona mas é arriscado. Considere Vulkan layers para graphics cheats em 2026.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
