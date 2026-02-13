# Técnica 021: Direct3D Hooking

> **Status:** ❌ Defasado / Ineficaz  
> **Risco de Detecção:** 🔴 Alto  
> **Domínio:** Graphics & Rendering  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Direct3D Hooking** intercepta chamadas da API Direct3D para modificar renderização, implementar ESP, wallhacks, ou outros overlays visuais. Era comum em cheats antigos, mas é facilmente detectado hoje.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ❌ CÓDIGO DEFASADO - NÃO USE
class D3D9Hook {
private:
    IDirect3DDevice9* pDevice;
    uintptr_t* vTable;
    
    // Funções originais
    typedef HRESULT(WINAPI* EndScene_t)(IDirect3DDevice9* pDevice);
    typedef HRESULT(WINAPI* DrawIndexedPrimitive_t)(IDirect3DDevice9* pDevice, 
                                                   D3DPRIMITIVETYPE Type, 
                                                   INT BaseVertexIndex, 
                                                   UINT MinVertexIndex, 
                                                   UINT NumVertices, 
                                                   UINT startIndex, 
                                                   UINT primCount);
    
    EndScene_t oEndScene;
    DrawIndexedPrimitive_t oDrawIndexedPrimitive;
    
public:
    void Initialize() {
        // Encontrar dispositivo D3D9
        pDevice = GetD3D9Device();
        if (!pDevice) return;
        
        // Pegar vtable
        vTable = *(uintptr_t**)pDevice;
        
        // Hook EndScene
        oEndScene = (EndScene_t)vTable[42]; // EndScene index
        vTable[42] = (uintptr_t)HookedEndScene;
        
        // Hook DrawIndexedPrimitive
        oDrawIndexedPrimitive = (DrawIndexedPrimitive_t)vTable[82];
        vTable[82] = (uintptr_t)HookedDrawIndexedPrimitive;
    }
    
    void Shutdown() {
        // Restaurar hooks
        if (vTable) {
            vTable[42] = (uintptr_t)oEndScene;
            vTable[82] = (uintptr_t)oDrawIndexedPrimitive;
        }
    }
    
private:
    static HRESULT WINAPI HookedEndScene(IDirect3DDevice9* pDevice) {
        // Renderizar overlays
        DrawESP();
        DrawMenu();
        
        // Chamar função original
        return oEndScene(pDevice);
    }
    
    static HRESULT WINAPI HookedDrawIndexedPrimitive(IDirect3DDevice9* pDevice,
                                                    D3DPRIMITIVETYPE Type,
                                                    INT BaseVertexIndex,
                                                    UINT MinVertexIndex,
                                                    UINT NumVertices,
                                                    UINT startIndex,
                                                    UINT primCount) {
        // Modificar geometria para wallhack
        if (IsWallGeometry(Type, NumVertices, primCount)) {
            // Aplicar wallhack
            ModifyWallTransparency(pDevice);
        }
        
        // Chamar função original
        return oDrawIndexedPrimitive(pDevice, Type, BaseVertexIndex, 
                                   MinVertexIndex, NumVertices, startIndex, primCount);
    }
    
    void DrawESP() {
        // Desenhar ESP boxes
        for (auto& entity : entities) {
            if (entity.isVisible) {
                DrawBox(entity.screenPos, entity.health);
            }
        }
    }
    
    void DrawMenu() {
        // Desenhar menu do cheat
        DrawMenuBackground();
        DrawMenuItems();
    }
    
    bool IsWallGeometry(D3DPRIMITIVETYPE Type, UINT NumVertices, UINT primCount) {
        // Detectar geometria de paredes
        return Type == D3DPT_TRIANGLELIST && 
               NumVertices > 100 && 
               primCount > 50;
    }
    
    void ModifyWallTransparency(IDirect3DDevice9* pDevice) {
        // Modificar render state para transparência
        pDevice->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
        pDevice->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
        pDevice->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
    }
    
    void DrawBox(D3DXVECTOR2 pos, int health) {
        // Desenhar box ESP
        D3DCOLOR color = GetHealthColor(health);
        
        // Top line
        DrawLine(pos.x - 20, pos.y - 30, pos.x + 20, pos.y - 30, color);
        // Bottom line
        DrawLine(pos.x - 20, pos.y + 30, pos.x + 20, pos.y + 30, color);
        // Left line
        DrawLine(pos.x - 20, pos.y - 30, pos.x - 20, pos.y + 30, color);
        // Right line
        DrawLine(pos.x + 20, pos.y - 30, pos.x + 20, pos.y + 30, color);
    }
    
    void DrawLine(float x1, float y1, float x2, float y2, D3DCOLOR color) {
        // Implementar drawing usando D3D
        // Criar vertex buffer, etc.
    }
};
```

### Por que é Detectado

> [!DANGER]
> **D3D hooking modifica vtables e deixa rastros óbvios na memória**

#### 1. VTable Integrity Checks
```cpp
// Verificar integridade da vtable
class VTableIntegrityChecker {
private:
    std::map<uintptr_t, VT_HOOK_INFO> originalVTables;
    
public:
    void Initialize() {
        // Salvar vtables originais
        EnumerateD3DDevices();
        SaveOriginalVTables();
    }
    
    void CheckIntegrity() {
        // Verificar se vtables foram modificadas
        for (auto& vtInfo : originalVTables) {
            if (IsVTableHooked(vtInfo.first)) {
                ReportD3DHook();
            }
        }
    }
    
    bool IsVTableHooked(uintptr_t vtableAddr) {
        uintptr_t* vtable = (uintptr_t*)vtableAddr;
        
        // Verificar se ponteiros apontam para módulos suspeitos
        for (int i = 0; i < VTABLE_SIZE; i++) {
            uintptr_t funcAddr = vtable[i];
            
            if (IsHookedFunction(funcAddr)) {
                return true;
            }
        }
        
        return false;
    }
    
    bool IsHookedFunction(uintptr_t funcAddr) {
        // Verificar se função está em módulo suspeito
        HMODULE hModule = GetModuleFromAddress(funcAddr);
        
        if (hModule != GetD3DModule()) {
            // Função hookada - não está no módulo D3D
            return true;
        }
        
        // Verificar se função foi modificada
        return IsFunctionModified(funcAddr);
    }
    
    bool IsFunctionModified(uintptr_t funcAddr) {
        // Comparar com função original
        auto it = originalFunctions.find(funcAddr);
        if (it != originalFunctions.end()) {
            return !CompareFunctionBytes(funcAddr, it->second);
        }
        
        return false;
    }
    
private:
    void EnumerateD3DDevices() {
        // Encontrar dispositivos D3D ativos
        // Salvar seus endereços
    }
    
    void SaveOriginalVTables() {
        // Salvar cópia das vtables originais
        // Para comparação posterior
    }
};
```

#### 2. Module Boundary Checks
```cpp
// Verificar se funções estão nos módulos corretos
class ModuleBoundaryChecker {
private:
    std::map<HMODULE, MODULE_INFO> moduleInfo;
    
public:
    void Initialize() {
        // Mapear módulos carregados
        EnumerateModules();
    }
    
    bool IsFunctionInCorrectModule(uintptr_t funcAddr) {
        HMODULE hModule = GetModuleFromAddress(funcAddr);
        
        if (!hModule) return false;
        
        // Verificar se endereço está dentro dos limites do módulo
        MODULE_INFO info = moduleInfo[hModule];
        
        return funcAddr >= (uintptr_t)info.baseAddr && 
               funcAddr < (uintptr_t)info.baseAddr + info.size;
    }
    
    bool IsCrossModuleCall(uintptr_t callerAddr, uintptr_t targetAddr) {
        HMODULE callerModule = GetModuleFromAddress(callerAddr);
        HMODULE targetModule = GetModuleFromAddress(targetAddr);
        
        // Chamadas cross-module são suspeitas
        return callerModule != targetModule;
    }
    
    void OnFunctionCall(uintptr_t caller, uintptr_t target) {
        if (IsCrossModuleCall(caller, target)) {
            // Verificar se é legítimo
            if (!IsLegitimateCrossCall(caller, target)) {
                ReportSuspiciousCall();
            }
        }
    }
    
private:
    bool IsLegitimateCrossCall(uintptr_t caller, uintptr_t target) {
        // Verificar se é chamada legítima (imports, etc.)
        // D3D hooks geralmente não são legítimos
        return false;
    }
};
```

#### 3. Memory Pattern Analysis
```cpp
// Análise de padrões na memória
class MemoryPatternAnalyzer {
private:
    std::vector<MEMORY_PATTERN> knownHookPatterns;
    
public:
    void Initialize() {
        // Padrões conhecidos de hooks D3D
        knownHookPatterns = {
            // VTable hook pattern
            {
                .signature = "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? FF E0",
                .description = "VTable hook trampoline"
            },
            
            // Detour pattern
            {
                .signature = "E9 ?? ?? ?? ??", // JMP rel32
                .description = "Function detour"
            },
            
            // Hook installation pattern
            {
                .signature = "48 89 05 ?? ?? ?? ?? C3",
                .description = "Hook installation"
            }
        };
    }
    
    void ScanMemory() {
        // Escanear memória do processo
        ScanProcessMemory();
        
        // Escanear módulos
        ScanModules();
    }
    
    void ScanProcessMemory() {
        // Escanear regiões de memória executáveis
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t address = 0;
        
        while (VirtualQuery((LPCVOID)address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_EXECUTE) != 0) {
                
                // Escanear região
                ScanMemoryRegion((uintptr_t)mbi.BaseAddress, mbi.RegionSize);
            }
            
            address += mbi.RegionSize;
        }
    }
    
    void ScanMemoryRegion(uintptr_t base, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)base, 
                            buffer.data(), size, &bytesRead)) {
            
            // Procurar padrões
            for (auto& pattern : knownHookPatterns) {
                if (FindPattern(buffer, pattern.signature)) {
                    ReportHookDetected(pattern.description);
                }
            }
        }
    }
    
    bool FindPattern(const std::vector<BYTE>& data, const std::string& signature) {
        // Implementar pattern matching
        return false; // Placeholder
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | VTable integrity | Imediato | 95% |
| VAC Live | Memory patterns | < 30s | 90% |
| BattlEye | Module boundaries | < 1 min | 85% |
| Faceit AC | Function hooks | Imediato | 80% |

---

## 🔄 Alternativas Seguras

### 1. External Overlay
```cpp
// ✅ Overlay externo
class ExternalOverlay {
private:
    HWND gameWindow;
    HDC overlayDC;
    
public:
    void Initialize(HWND hwnd) {
        gameWindow = hwnd;
        
        // Criar overlay window
        CreateOverlayWindow();
        
        // Configurar transparency
        SetWindowTransparent();
    }
    
    void Render() {
        // Obter posição da janela do jogo
        RECT gameRect;
        GetWindowRect(gameWindow, &gameRect);
        
        // Renderizar ESP
        DrawESP(gameRect);
        
        // Renderizar menu
        DrawMenu(gameRect);
    }
    
private:
    void CreateOverlayWindow() {
        // Criar janela overlay
        overlayDC = GetDC(NULL); // Desktop DC
    }
    
    void SetWindowTransparent() {
        // Configurar layered window
        SetWindowLong(overlayHWND, GWL_EXSTYLE, 
                     GetWindowLong(overlayHWND, GWL_EXSTYLE) | WS_EX_LAYERED);
        SetLayeredWindowAttributes(overlayHWND, 0, 255, LWA_ALPHA);
    }
    
    void DrawESP(const RECT& gameRect) {
        // Desenhar ESP usando GDI
        HDC hdc = GetDC(overlayHWND);
        
        for (auto& entity : entities) {
            DrawESPBox(hdc, entity, gameRect);
        }
        
        ReleaseDC(overlayHWND, hdc);
    }
    
    void DrawESPBox(HDC hdc, const Entity& entity, const RECT& gameRect) {
        // Converter world to screen
        POINT screenPos = WorldToScreen(entity.position, gameRect);
        
        // Desenhar box
        HPEN pen = CreatePen(PS_SOLID, 2, RGB(255, 0, 0));
        SelectObject(hdc, pen);
        
        Rectangle(hdc, screenPos.x - 20, screenPos.y - 30, 
                 screenPos.x + 20, screenPos.y + 30);
        
        DeleteObject(pen);
    }
};
```

### 2. ImGui-Based Overlay
```cpp
// ✅ Overlay usando ImGui
class ImGuiOverlay {
private:
    WNDCLASSEX wc;
    HWND hwnd;
    
public:
    void Initialize() {
        // Criar window class
        CreateWindowClass();
        
        // Criar window
        CreateOverlayWindow();
        
        // Inicializar ImGui
        ImGui::CreateContext();
        ImGuiIO& io = ImGui::GetIO();
        
        // Configurar backend
        ImGui_ImplWin32_Init(hwnd);
        ImGui_ImplDX11_Init(device, context);
    }
    
    void Render() {
        // Start frame
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        
        // Renderizar ESP
        RenderESP();
        
        // Renderizar menu
        RenderMenu();
        
        // Render
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }
    
private:
    void RenderESP() {
        ImGui::Begin("ESP", nullptr, ImGuiWindowFlags_NoTitleBar | 
                     ImGuiWindowFlags_NoBackground | ImGuiWindowFlags_NoInputs);
        
        ImDrawList* drawList = ImGui::GetWindowDrawList();
        
        for (auto& entity : entities) {
            // Desenhar ESP elements
            DrawESPBox(drawList, entity);
            DrawESPHealth(drawList, entity);
            DrawESPName(drawList, entity);
        }
        
        ImGui::End();
    }
    
    void RenderMenu() {
        ImGui::Begin("Cheat Menu");
        
        ImGui::Checkbox("ESP", &espEnabled);
        ImGui::Checkbox("Wallhack", &wallhackEnabled);
        ImGui::SliderFloat("ESP Distance", &espDistance, 0.0f, 1000.0f);
        
        ImGui::End();
    }
    
    void DrawESPBox(ImDrawList* drawList, const Entity& entity) {
        ImVec2 min = ImVec2(entity.screenPos.x - 20, entity.screenPos.y - 30);
        ImVec2 max = ImVec2(entity.screenPos.x + 20, entity.screenPos.y + 30);
        
        drawList->AddRect(min, max, IM_COL32(255, 0, 0, 255), 0.0f, 0, 2.0f);
    }
};
```

### 3. Vulkan/DX12 Interception
```cpp
// ✅ Intercepção de Vulkan/DX12
class VulkanInterceptor {
private:
    VkInstance instance;
    VkDevice device;
    std::vector<VkCommandBuffer> commandBuffers;
    
public:
    void Initialize() {
        // Hook Vulkan functions
        HookVulkanFunctions();
        
        // Intercept command buffers
        InterceptCommandBuffers();
    }
    
    void OnPresent(VkSwapchainKHR swapchain) {
        // Modificar apresentação
        ModifyPresentation(swapchain);
        
        // Injetar overlays
        InjectOverlays();
    }
    
    void ModifyPresentation(VkSwapchainKHR swapchain) {
        // Modificar imagens antes da apresentação
        // Aplicar efeitos visuais
    }
    
    void InjectOverlays() {
        // Injetar ESP, menu, etc.
        RenderESP();
        RenderMenu();
    }
    
private:
    void HookVulkanFunctions() {
        // Hook vkQueuePresentKHR
        // Hook vkAcquireNextImageKHR
        // Hook vkCreateSwapchainKHR
    }
    
    void InterceptCommandBuffers() {
        // Interceptar command buffers
        // Modificar para incluir overlays
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC D3D Protection
```cpp
// VAC D3D hook detection
class VAC_D3DProtector {
private:
    VTableIntegrityChecker vtChecker;
    MemoryPatternAnalyzer patternAnalyzer;
    ModuleBoundaryChecker boundaryChecker;
    
public:
    void Initialize() {
        vtChecker.Initialize();
        patternAnalyzer.Initialize();
        boundaryChecker.Initialize();
        
        // Instalar hooks de monitoramento
        InstallMonitoringHooks();
    }
    
    void CheckD3DIntegrity() {
        // Verificar vtables
        vtChecker.CheckIntegrity();
        
        // Escanear padrões
        patternAnalyzer.ScanMemory();
        
        // Verificar boundaries
        boundaryChecker.CheckBoundaries();
    }
    
    void OnD3DCall(uintptr_t caller, uintptr_t target) {
        // Monitorar chamadas D3D
        boundaryChecker.OnFunctionCall(caller, target);
    }
};
```

### BattlEye Graphics Protection
```cpp
// BE graphics hook detection
void BE_DetectGraphicsHooks() {
    // Monitor D3D/Vulkan calls
    MonitorGraphicsAPICalls();
    
    // Check for overlay windows
    CheckOverlayWindows();
    
    // Analyze graphics memory
    AnalyzeGraphicsMemory();
}

void MonitorGraphicsAPICalls() {
    // Hook graphics API functions
    // Detect modifications
}

void CheckOverlayWindows() {
    // Look for suspicious overlay windows
    // Check transparency settings
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2000s | ✅ Funcional | Nenhuma |
| 2010s | ⚠️ Risco | Básica |
| 2015-2020 | ❌ Detectado | VTable checks |
| 2020-2024 | ⛔ Alto risco | Memory analysis |
| 2025-2026 | ⛔ Crítico | AI detection |

---

## 🎯 Lições Aprendadas

1. **VTables São Monitoradas**: Modificações na vtable são imediatamente detectadas.

2. **Memória é Escaneada**: Padrões de hook são procurados na memória.

3. **Boundaries São Verificados**: Chamadas cross-module são suspeitas.

4. **Overlays Externos São Seguros**: Renderizar separadamente evita detecção.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#21]]
- [[External_Overlay]]
- [[ImGui_Based_Overlay]]
- [[Vulkan_Interception]]

---

*D3D hooking é completamente obsoleto. Use overlays externos ou ImGui.*