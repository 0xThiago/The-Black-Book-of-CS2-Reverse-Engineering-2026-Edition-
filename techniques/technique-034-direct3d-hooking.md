# 📖 Técnica 034: Direct3D Hooking

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 034: Direct3D Hooking]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Graphics & Rendering  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Direct3D Hooking** intercepta chamadas da API Direct3D para modificar renderização, criando wallhack, ESP ou chams. É detectado por verificações de integridade da VMT.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class D3D11Hooker {
private:
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    IDXGISwapChain* pSwapChain;
    
    // Ponteiros originais
    typedef HRESULT(__stdcall* Present_t)(IDXGISwapChain*, UINT, UINT);
    Present_t oPresent;
    
    typedef HRESULT(__stdcall* DrawIndexed_t)(ID3D11DeviceContext*, UINT, UINT, INT);
    DrawIndexed_t oDrawIndexed;
    
public:
    void Initialize() {
        // Encontrar ponteiros D3D11
        if (!FindD3D11Pointers()) return;
        
        // Hook Present
        oPresent = (Present_t)HookVMTFunction((uintptr_t*)pSwapChain, 8, &hkPresent);
        
        // Hook DrawIndexed
        oDrawIndexed = (DrawIndexed_t)HookVMTFunction((uintptr_t*)pContext, 12, &hkDrawIndexed);
    }
    
    void Cleanup() {
        // Remover hooks
        if (oPresent) UnhookVMTFunction((uintptr_t*)pSwapChain, 8, oPresent);
        if (oDrawIndexed) UnhookVMTFunction((uintptr_t*)pContext, 12, oDrawIndexed);
    }
    
private:
    bool FindD3D11Pointers() {
        // Criar dispositivo dummy para obter ponteiros
        D3D_FEATURE_LEVEL featureLevel;
        DXGI_SWAP_CHAIN_DESC swapChainDesc = {0};
        swapChainDesc.BufferCount = 1;
        swapChainDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        swapChainDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        swapChainDesc.OutputWindow = GetForegroundWindow();
        swapChainDesc.SampleDesc.Count = 1;
        swapChainDesc.Windowed = TRUE;
        
        HRESULT hr = D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
                                                  NULL, 0, D3D11_SDK_VERSION, &swapChainDesc,
                                                  &pSwapChain, &pDevice, &featureLevel, &pContext);
        
        return SUCCEEDED(hr);
    }
    
    uintptr_t HookVMTFunction(uintptr_t* vmt, int index, void* hkFunc) {
        // Salvar ponteiro original
        uintptr_t originalFunc = vmt[index];
        
        // Alterar proteção da VMT
        DWORD oldProtect;
        VirtualProtect(&vmt[index], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
        
        // Instalar hook
        vmt[index] = (uintptr_t)hkFunc;
        
        // Restaurar proteção
        VirtualProtect(&vmt[index], sizeof(uintptr_t), oldProtect, &oldProtect);
        
        return originalFunc;
    }
    
    void UnhookVMTFunction(uintptr_t* vmt, int index, uintptr_t originalFunc) {
        DWORD oldProtect;
        VirtualProtect(&vmt[index], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
        vmt[index] = originalFunc;
        VirtualProtect(&vmt[index], sizeof(uintptr_t), oldProtect, &oldProtect);
    }
    
    // Hook functions
    static HRESULT __stdcall hkPresent(IDXGISwapChain* pSwapChain, UINT SyncInterval, UINT Flags) {
        // Renderizar overlays (ESP, etc.)
        DrawESP();
        
        // Chamar função original
        return oPresent(pSwapChain, SyncInterval, Flags);
    }
    
    static HRESULT __stdcall hkDrawIndexed(ID3D11DeviceContext* pContext, UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation) {
        // Modificar renderização para wallhack/chams
        if (ShouldApplyWallhack(IndexCount, StartIndexLocation, BaseVertexLocation)) {
            ApplyWallhackShader();
        }
        
        // Chamar função original
        return oDrawIndexed(pContext, IndexCount, StartIndexLocation, BaseVertexLocation);
    }
    
    static void DrawESP() {
        // Desenhar ESP através do ImGui ou D3D primitives
        // Obter lista de jogadores
        std::vector<PlayerInfo> players = GetPlayerList();
        
        for (const PlayerInfo& player : players) {
            if (!player.isEnemy || !player.isAlive) continue;
            
            // Converter posição 3D para tela 2D
            POINT screenPos = WorldToScreen(player.position);
            
            // Desenhar box ESP
            DrawESPBox(screenPos.x, screenPos.y, player.height, player.width, player.health);
            
            // Desenhar nome
            DrawText(screenPos.x, screenPos.y - 20, player.name.c_str());
        }
    }
    
    static bool ShouldApplyWallhack(UINT IndexCount, UINT StartIndexLocation, INT BaseVertexLocation) {
        // Verificar se é um modelo de jogador
        // Análise de padrões de IndexCount/StartIndex para identificar jogadores
        
        // Exemplo: jogadores têm ~5000-15000 índices
        return IndexCount > 5000 && IndexCount < 15000;
    }
    
    static void ApplyWallhackShader() {
        // Aplicar shader que ignora depth/stencil
        // ou modifica blend state para chams
        
        // Exemplo: desabilitar depth test
        D3D11_DEPTH_STENCIL_DESC depthDesc;
        ZeroMemory(&depthDesc, sizeof(depthDesc));
        depthDesc.DepthEnable = FALSE;
        depthDesc.DepthWriteMask = D3D11_DEPTH_WRITE_MASK_ZERO;
        
        ID3D11DepthStencilState* pDepthState;
        pDevice->CreateDepthStencilState(&depthDesc, &pDepthState);
        pContext->OMSetDepthStencilState(pDepthState, 0);
        
        // Renderizar com shader customizado
        // ... código para aplicar shader de wallhack ...
        
        // Restaurar estado original
        // ... restaurar depth stencil state original ...
    }
    
    static void DrawESPBox(int x, int y, int height, int width, float health) {
        // Desenhar retângulo usando D3D primitives
        // Calcular cor baseada na vida
        D3DCOLOR color = (health > 50) ? D3DCOLOR_ARGB(255, 0, 255, 0) : D3DCOLOR_ARGB(255, 255, 0, 0);
        
        // Usar DrawPrimitive ou similar
        // ... código para desenhar linhas ...
    }
    
    static void DrawText(int x, int y, const char* text) {
        // Desenhar texto usando D3D font
        // ... código para renderizar texto ...
    }
};
```

### VMT Hooking Mechanism

```cpp
// Mecanismo de VMT hooking
class VMTHook {
private:
    uintptr_t* vmt;
    uintptr_t* originalVMT;
    std::vector<uintptr_t> hookedFunctions;
    
public:
    VMTHook(uintptr_t* vmtPtr) : vmt(vmtPtr) {
        // Salvar VMT original
        SIZE_T vmtSize = GetVMTSize();
        originalVMT = new uintptr_t[vmtSize];
        memcpy(originalVMT, vmt, vmtSize * sizeof(uintptr_t));
    }
    
    ~VMTHook() {
        // Restaurar VMT original
        RestoreVMT();
        delete[] originalVMT;
    }
    
    void HookFunction(int index, void* hkFunc) {
        // Verificar se já está hookado
        if (index >= hookedFunctions.size()) {
            hookedFunctions.resize(index + 1, 0);
        }
        
        // Salvar função original
        hookedFunctions[index] = vmt[index];
        
        // Instalar hook
        DWORD oldProtect;
        VirtualProtect(&vmt[index], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
        vmt[index] = (uintptr_t)hkFunc;
        VirtualProtect(&vmt[index], sizeof(uintptr_t), oldProtect, &oldProtect);
    }
    
    void UnhookFunction(int index) {
        if (index < hookedFunctions.size() && hookedFunctions[index] != 0) {
            DWORD oldProtect;
            VirtualProtect(&vmt[index], sizeof(uintptr_t), PAGE_EXECUTE_READWRITE, &oldProtect);
            vmt[index] = hookedFunctions[index];
            VirtualProtect(&vmt[index], sizeof(uintptr_t), oldProtect, &oldProtect);
            
            hookedFunctions[index] = 0;
        }
    }
    
    uintptr_t GetOriginalFunction(int index) {
        if (index < hookedFunctions.size()) {
            return hookedFunctions[index];
        }
        return 0;
    }
    
private:
    SIZE_T GetVMTSize() {
        SIZE_T size = 0;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQuery((LPCVOID)(vmt + size), &mbi, sizeof(mbi))) {
            if (mbi.Protect & PAGE_EXECUTE_READ) {
                // Verificar se é um ponteiro válido para função
                if (IsValidFunctionPointer(vmt[size])) {
                    size++;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        
        return size;
    }
    
    bool IsValidFunctionPointer(uintptr_t ptr) {
        // Verificar se ponteiro aponta para código executável
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi))) {
            return (mbi.Protect & PAGE_EXECUTE_READ) != 0;
        }
        return false;
    }
    
    void RestoreVMT() {
        // Restaurar todas as funções
        for (size_t i = 0; i < hookedFunctions.size(); i++) {
            if (hookedFunctions[i] != 0) {
                UnhookFunction(i);
            }
        }
    }
};
```

### Por que é Detectado

> [!WARNING]
> **D3D hooking deixa rastros de modificações na VMT e shaders suspeitos**

#### 1. VMT Integrity Checking
```cpp
// Verificação de integridade da VMT
class VMTIntegrityChecker {
private:
    std::map<uintptr_t, VMT_CHECKSUM> vmtChecksums;
    
public:
    void Initialize() {
        // Registrar VMTs importantes
        RegisterD3D11VMTs();
    }
    
    void CheckVMTIntegrity() {
        for (auto& pair : vmtChecksums) {
            uintptr_t vmtAddr = pair.first;
            VMT_CHECKSUM& checksum = pair.second;
            
            uint32_t currentChecksum = CalculateVMTChecksum(vmtAddr, checksum.size);
            if (currentChecksum != checksum.originalChecksum) {
                ReportVMTModification(vmtAddr);
            }
        }
    }
    
    void RegisterD3D11VMTs() {
        // Encontrar e registrar VMTs D3D11
        ID3D11Device* pDevice = nullptr;
        ID3D11DeviceContext* pContext = nullptr;
        IDXGISwapChain* pSwapChain = nullptr;
        
        if (FindD3D11Pointers(pDevice, pContext, pSwapChain)) {
            RegisterVMT((uintptr_t*)pDevice, "ID3D11Device");
            RegisterVMT((uintptr_t*)pContext, "ID3D11DeviceContext");
            RegisterVMT((uintptr_t*)pSwapChain, "IDXGISwapChain");
        }
    }
    
    void RegisterVMT(uintptr_t* vmt, const char* name) {
        SIZE_T vmtSize = GetVMTSize(vmt);
        uint32_t checksum = CalculateVMTChecksum((uintptr_t)vmt, vmtSize);
        
        VMT_CHECKSUM vmtChecksum;
        vmtChecksum.originalChecksum = checksum;
        vmtChecksum.size = vmtSize;
        strcpy_s(vmtChecksum.name, name);
        
        vmtChecksums[(uintptr_t)vmt] = vmtChecksum;
    }
    
    uint32_t CalculateVMTChecksum(uintptr_t vmtAddr, SIZE_T size) {
        uintptr_t* vmt = (uintptr_t*)vmtAddr;
        uint32_t checksum = 0;
        
        for (SIZE_T i = 0; i < size; i++) {
            checksum = ((checksum << 5) + checksum) + (uint32_t)vmt[i];
        }
        
        return checksum;
    }
    
    SIZE_T GetVMTSize(uintptr_t* vmt) {
        SIZE_T size = 0;
        while (vmt[size] != 0 && IsValidFunctionPointer(vmt[size])) {
            size++;
            if (size > 100) break; // Limite de segurança
        }
        return size;
    }
    
    bool IsValidFunctionPointer(uintptr_t ptr) {
        MEMORY_BASIC_INFORMATION mbi;
        return VirtualQuery((LPCVOID)ptr, &mbi, sizeof(mbi)) &&
               (mbi.Protect & PAGE_EXECUTE_READ);
    }
};
```

#### 2. Shader Analysis
```cpp
// Análise de shaders
class ShaderAnalyzer {
private:
    std::set<uintptr_t> knownShaders;
    
public:
    void Initialize() {
        // Registrar shaders legítimos
        EnumerateLegitimateShaders();
    }
    
    void OnShaderCreation(ID3D11DeviceChild* pShader) {
        // Verificar se shader é suspeito
        if (IsSuspiciousShader(pShader)) {
            ReportSuspiciousShader(pShader);
        }
        
        // Adicionar aos shaders conhecidos
        knownShaders.insert((uintptr_t)pShader);
    }
    
    void OnShaderUsage(ID3D11DeviceChild* pShader) {
        // Verificar uso suspeito
        if (IsSuspiciousShaderUsage(pShader)) {
            ReportSuspiciousShaderUsage(pShader);
        }
    }
    
    bool IsSuspiciousShader(ID3D11DeviceChild* pShader) {
        // Analisar bytecode do shader
        ID3D10Blob* pBlob = nullptr;
        
        // Obter bytecode (método depende do tipo de shader)
        if (SUCCEEDED(GetShaderBytecode(pShader, &pBlob))) {
            bool suspicious = AnalyzeShaderBytecode(pBlob);
            if (pBlob) pBlob->Release();
            return suspicious;
        }
        
        return false;
    }
    
    bool AnalyzeShaderBytecode(ID3D10Blob* pBlob) {
        const BYTE* bytecode = (const BYTE*)pBlob->GetBufferPointer();
        SIZE_T size = pBlob->GetBufferSize();
        
        // Procurar por padrões suspeitos
        // Exemplo: shaders que desabilitam depth test
        return ContainsSuspiciousPatterns(bytecode, size);
    }
    
    bool ContainsSuspiciousPatterns(const BYTE* bytecode, SIZE_T size) {
        // Procurar por instruções suspeitas
        // dcl_depthstencil (declaração de depth stencil)
        // ou modificações de blend state
        
        // Análise simplificada
        for (SIZE_T i = 0; i < size - 4; i++) {
            if (memcmp(&bytecode[i], "dcl_", 4) == 0) {
                // Verificar se é depth stencil related
                if (strstr((const char*)&bytecode[i], "depth") != nullptr) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool IsSuspiciousShaderUsage(ID3D11DeviceChild* pShader) {
        // Verificar frequência de uso
        // ou uso em contextos suspeitos
        
        return false; // Placeholder
    }
    
    HRESULT GetShaderBytecode(ID3D11DeviceChild* pShader, ID3D10Blob** ppBlob) {
        // Método para extrair bytecode depende do tipo de shader
        // Exemplo para vertex shader:
        if (pShader->GetType() == D3D11_SHADER_TYPE_VERTEX) {
            ID3D11VertexShader* pVS = (ID3D11VertexShader*)pShader;
            // Não há API direta para obter bytecode após criação
            // Pode requerer hooking da criação
        }
        
        return E_FAIL;
    }
};
```

#### 3. Render State Monitoring
```cpp
// Monitoramento de estado de renderização
class RenderStateMonitor {
private:
    std::map<D3D11_RENDER_STATE_TYPE, D3D11_RENDER_STATE> renderStates;
    
public:
    void Initialize() {
        // Registrar estados de renderização padrão
        RegisterDefaultRenderStates();
    }
    
    void OnRenderStateChange(D3D11_RENDER_STATE_TYPE type, const void* pState) {
        // Verificar mudança suspeita
        if (IsSuspiciousRenderStateChange(type, pState)) {
            ReportSuspiciousRenderState(type);
        }
        
        // Atualizar estado registrado
        UpdateRenderState(type, pState);
    }
    
    bool IsSuspiciousRenderStateChange(D3D11_RENDER_STATE_TYPE type, const void* pState) {
        switch (type) {
            case DEPTH_STENCIL_STATE:
                return IsSuspiciousDepthStencilState((const D3D11_DEPTH_STENCIL_DESC*)pState);
                
            case BLEND_STATE:
                return IsSuspiciousBlendState((const D3D11_BLEND_DESC*)pState);
                
            case RASTERIZER_STATE:
                return IsSuspiciousRasterizerState((const D3D11_RASTERIZER_DESC*)pState);
                
            default:
                return false;
        }
    }
    
    bool IsSuspiciousDepthStencilState(const D3D11_DEPTH_STENCIL_DESC* pDesc) {
        // Depth test desabilitado
        if (!pDesc->DepthEnable) {
            return true;
        }
        
        // Depth write desabilitado
        if (pDesc->DepthWriteMask == D3D11_DEPTH_WRITE_MASK_ZERO) {
            return true;
        }
        
        return false;
    }
    
    bool IsSuspiciousBlendState(const D3D11_BLEND_DESC* pDesc) {
        // Blend habilitado para wallhack/chams
        for (int i = 0; i < 8; i++) {
            if (pDesc->RenderTarget[i].BlendEnable) {
                // Verificar se é configuração suspeita
                if (pDesc->RenderTarget[i].SrcBlend == D3D11_BLEND_SRC_ALPHA &&
                    pDesc->RenderTarget[i].DestBlend == D3D11_BLEND_INV_SRC_ALPHA) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    bool IsSuspiciousRasterizerState(const D3D11_RASTERIZER_DESC* pDesc) {
        // Fill mode wireframe (usado para debugging/cheats)
        if (pDesc->FillMode == D3D11_FILL_WIREFRAME) {
            return true;
        }
        
        // Cull mode none (renderizar tudo)
        if (pDesc->CullMode == D3D11_CULL_NONE) {
            return true;
        }
        
        return false;
    }
    
    void RegisterDefaultRenderStates() {
        // Registrar estados padrão do jogo
        // ... código para capturar estados iniciais ...
    }
    
    void UpdateRenderState(D3D11_RENDER_STATE_TYPE type, const void* pState) {
        // Atualizar registro de estado
        renderStates[type].data = pState;
        renderStates[type].timestamp = GetTickCount();
    }
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | VMT integrity | < 30s | 80% |
| VAC Live | Shader analysis | Imediato | 75% |
| BattlEye | Render state monitoring | < 1 min | 85% |
| Faceit AC | Draw call analysis | < 30s | 70% |

---

## 🔄 Alternativas Seguras

### 1. ImGui-Based Overlay
```cpp
// ✅ Overlay baseado em ImGui
class ImGuiOverlay {
private:
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    IDXGISwapChain* pSwapChain;
    
    // ImGui state
    ImGuiContext* imGuiContext;
    
public:
    void Initialize() {
        // Inicializar ImGui
        IMGUI_CHECKVERSION();
        imGuiContext = ImGui::CreateContext();
        ImGui::StyleColorsDark();
        
        // Inicializar ImGui para D3D11
        ImGui_ImplWin32_Init(GetForegroundWindow());
        ImGui_ImplDX11_Init(pDevice, pContext);
    }
    
    void RenderOverlay() {
        // Começar frame ImGui
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        
        // Renderizar ESP
        DrawESPOverlay();
        
        // Renderizar menu
        DrawMenuOverlay();
        
        // Finalizar frame
        ImGui::Render();
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
    }
    
    void Cleanup() {
        ImGui_ImplDX11_Shutdown();
        ImGui_ImplWin32_Shutdown();
        ImGui::DestroyContext(imGuiContext);
    }
    
private:
    void DrawESPOverlay() {
        // Obter lista de jogadores
        std::vector<PlayerInfo> players = GetPlayerList();
        
        for (const PlayerInfo& player : players) {
            if (!player.isEnemy || !player.isAlive) continue;
            
            POINT screenPos = WorldToScreen(player.position);
            
            // Desenhar box usando ImGui
            ImVec2 boxMin(screenPos.x - player.width/2, screenPos.y);
            ImVec2 boxMax(screenPos.x + player.width/2, screenPos.y + player.height);
            
            ImGui::GetBackgroundDrawList()->AddRect(boxMin, boxMax, 
                                                   IM_COL32(255, 0, 0, 255), 0.0f, 0, 2.0f);
            
            // Desenhar barra de vida
            float healthRatio = player.health / 100.0f;
            ImVec2 healthMin = boxMin - ImVec2(5, 0);
            ImVec2 healthMax = ImVec2(boxMin.x - 2, boxMax.y);
            ImVec2 healthFill = ImVec2(healthMin.x + 3, healthMin.y + (healthMax.y - healthMin.y) * (1.0f - healthRatio));
            
            ImGui::GetBackgroundDrawList()->AddRectFilled(healthMin, healthMax, IM_COL32(255, 0, 0, 255));
            ImGui::GetBackgroundDrawList()->AddRectFilled(healthFill, healthMax, IM_COL32(0, 255, 0, 255));
            
            // Desenhar nome
            ImVec2 textPos(screenPos.x, screenPos.y - 20);
            ImGui::GetBackgroundDrawList()->AddText(textPos, IM_COL32(255, 255, 255, 255), player.name.c_str());
        }
    }
    
    void DrawMenuOverlay() {
        // Menu de configurações
        ImGui::Begin("CS2 Cheat Menu", nullptr, ImGuiWindowFlags_AlwaysAutoResize);
        
        ImGui::Checkbox("ESP", &espEnabled);
        ImGui::Checkbox("Wallhack", &wallhackEnabled);
        ImGui::Checkbox("Aimbot", &aimbotEnabled);
        
        if (ImGui::CollapsingHeader("ESP Settings")) {
            ImGui::ColorEdit3("Box Color", (float*)&espBoxColor);
            ImGui::SliderFloat("Box Thickness", &espBoxThickness, 1.0f, 5.0f);
        }
        
        ImGui::End();
    }
};
```

### 2. External Rendering
```cpp
// ✅ Renderização externa
class ExternalRenderer {
private:
    // Janela externa
    HWND hExternalWindow;
    ID3D11Device* pExternalDevice;
    ID3D11DeviceContext* pExternalContext;
    IDXGISwapChain* pExternalSwapChain;
    
public:
    void Initialize() {
        // Criar janela externa
        hExternalWindow = CreateWindowExA(0, "ExternalOverlay", "Overlay", 
                                        WS_POPUP | WS_VISIBLE, 0, 0, 1920, 1080,
                                        NULL, NULL, GetModuleHandle(NULL), NULL);
        
        // Inicializar D3D11 para janela externa
        InitializeExternalD3D11();
        
        // Tornar janela transparente e topmost
        SetWindowLong(hExternalWindow, GWL_EXSTYLE, 
                     GetWindowLong(hExternalWindow, GWL_EXSTYLE) | WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_TOPMOST);
        SetLayeredWindowAttributes(hExternalWindow, RGB(0, 0, 0), 0, LWA_COLORKEY);
    }
    
    void RenderFrame() {
        // Limpar backbuffer
        float clearColor[4] = {0.0f, 0.0f, 0.0f, 0.0f};
        pExternalContext->ClearRenderTargetView(pExternalRTV, clearColor);
        
        // Renderizar ESP
        DrawExternalESP();
        
        // Present
        pExternalSwapChain->Present(0, 0);
    }
    
private:
    void InitializeExternalD3D11() {
        // Criar dispositivo D3D11 para overlay externo
        D3D_FEATURE_LEVEL featureLevel;
        DXGI_SWAP_CHAIN_DESC swapDesc = {0};
        swapDesc.BufferCount = 1;
        swapDesc.BufferDesc.Width = 1920;
        swapDesc.BufferDesc.Height = 1080;
        swapDesc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
        swapDesc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
        swapDesc.OutputWindow = hExternalWindow;
        swapDesc.SampleDesc.Count = 1;
        swapDesc.Windowed = TRUE;
        
        D3D11CreateDeviceAndSwapChain(NULL, D3D_DRIVER_TYPE_HARDWARE, NULL, 0,
                                    NULL, 0, D3D11_SDK_VERSION, &swapDesc,
                                    &pExternalSwapChain, &pExternalDevice, 
                                    &featureLevel, &pExternalContext);
        
        // Criar render target view
        ID3D11Texture2D* pBackBuffer;
        pExternalSwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), (void**)&pBackBuffer);
        pExternalDevice->CreateRenderTargetView(pBackBuffer, NULL, &pExternalRTV);
        pBackBuffer->Release();
        
        pExternalContext->OMSetRenderTargets(1, &pExternalRTV, NULL);
    }
    
    void DrawExternalESP() {
        // Renderizar ESP na janela externa
        // Posicionar sobre a janela do jogo
        
        std::vector<PlayerInfo> players = GetPlayerList();
        
        for (const PlayerInfo& player : players) {
            if (!player.isEnemy || !player.isAlive) continue;
            
            POINT screenPos = WorldToScreen(player.position);
            
            // Desenhar primitivas D3D11
            DrawESPBoxExternal(screenPos.x, screenPos.y, player.width, player.height);
        }
    }
    
    void DrawESPBoxExternal(int x, int y, int width, int height) {
        // Criar vértices para retângulo
        struct Vertex {
            float x, y, z;
            float r, g, b, a;
        };
        
        Vertex vertices[] = {
            {x - width/2, y, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f},
            {x + width/2, y, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f},
            {x + width/2, y + height, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f},
            {x - width/2, y + height, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f}
        };
        
        // Criar vertex buffer
        D3D11_BUFFER_DESC bufferDesc = {0};
        bufferDesc.Usage = D3D11_USAGE_DEFAULT;
        bufferDesc.ByteWidth = sizeof(vertices);
        bufferDesc.BindFlags = D3D11_BIND_VERTEX_BUFFER;
        
        D3D11_SUBRESOURCE_DATA initData = {0};
        initData.pSysMem = vertices;
        
        ID3D11Buffer* pVertexBuffer;
        pExternalDevice->CreateBuffer(&bufferDesc, &initData, &pVertexBuffer);
        
        // Renderizar
        UINT stride = sizeof(Vertex);
        UINT offset = 0;
        pExternalContext->IASetVertexBuffers(0, 1, &pVertexBuffer, &stride, &offset);
        pExternalContext->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_LINESTRIP);
        
        // Shader simples para linhas
        // ... código para shader ...
        
        pExternalContext->Draw(4, 0);
        pVertexBuffer->Release();
    }
};
```

### 3. Pixel Shader Injection
```cpp
// ✅ Injeção de pixel shader
class PixelShaderInjector {
private:
    ID3D11Device* pDevice;
    ID3D11DeviceContext* pContext;
    
public:
    void Initialize() {
        // Obter ponteiros D3D11
        FindD3D11Pointers();
    }
    
    void InjectWallhackShader() {
        // Criar pixel shader customizado
        ID3D11PixelShader* pWallhackShader = CreateWallhackPixelShader();
        
        // Hook PSSetShader para injetar shader
        HookPSSetShader();
    }
    
private:
    ID3D11PixelShader* CreateWallhackPixelShader() {
        // HLSL shader que ignora depth
        const char* shaderCode = 
            "Texture2D tex : register(t0);"
            "SamplerState sam : register(s0);"
            ""
            "struct PS_INPUT {"
            "    float4 pos : SV_POSITION;"
            "    float2 tex : TEXCOORD0;"
            "};"
            ""
            "float4 main(PS_INPUT input) : SV_TARGET {"
            "    float4 color = tex.Sample(sam, input.tex);"
            "    // Wallhack: tornar semi-transparente"
            "    color.a = 0.5f;"
            "    return color;"
            "}";
        
        // Compilar shader
        ID3D10Blob* pBlob;
        D3DCompile(shaderCode, strlen(shaderCode), NULL, NULL, NULL, "main", "ps_5_0", 0, 0, &pBlob, NULL);
        
        ID3D11PixelShader* pShader;
        pDevice->CreatePixelShader(pBlob->GetBufferPointer(), pBlob->GetBufferSize(), NULL, &pShader);
        
        pBlob->Release();
        return pShader;
    }
    
    void HookPSSetShader() {
        // Hook da função PSSetShader
        uintptr_t* vmt = *(uintptr_t**)pContext;
        int psSetShaderIndex = 9; // Índice da função PSSetShader na VMT
        
        oPSSetShader = (PSSetShader_t)HookVMTFunction(vmt, psSetShaderIndex, &hkPSSetShader);
    }
    
    typedef void(__stdcall* PSSetShader_t)(ID3D11DeviceContext*, ID3D11PixelShader*, ID3D11ClassInstance* const*, UINT);
    PSSetShader_t oPSSetShader;
    
    static void __stdcall hkPSSetShader(ID3D11DeviceContext* pContext, ID3D11PixelShader* pPixelShader, 
                                       ID3D11ClassInstance* const* ppClassInstances, UINT NumClassInstances) {
        // Verificar se é shader de modelo de jogador
        if (IsPlayerModelShader(pPixelShader)) {
            // Substituir por shader de wallhack
            pPixelShader = pWallhackShader;
        }
        
        // Chamar função original
        oPSSetShader(pContext, pPixelShader, ppClassInstances, NumClassInstances);
    }
    
    static bool IsPlayerModelShader(ID3D11PixelShader* pShader) {
        // Identificar shaders de modelos de jogador
        // por análise de bytecode ou por contexto de chamada
        
        return false; // Placeholder
    }
};
```

---

## 🛡️ Contramedidas Anti-Cheat

### VAC D3D Hooking Detection
```cpp
// VAC D3D hooking detection
class VAC_D3DDetector {
private:
    VMTIntegrityChecker vmtChecker;
    ShaderAnalyzer shaderAnalyzer;
    RenderStateMonitor renderMonitor;
    
public:
    void Initialize() {
        vmtChecker.Initialize();
        shaderAnalyzer.Initialize();
        renderMonitor.Initialize();
    }
    
    void OnProcessAttach(HANDLE hProcess) {
        // Começar monitoramento
        StartD3DMonitoring();
    }
    
    void PeriodicIntegrityCheck() {
        vmtChecker.CheckVMTIntegrity();
    }
    
    void OnShaderCreation(ID3D11DeviceChild* pShader) {
        shaderAnalyzer.OnShaderCreation(pShader);
    }
    
    void OnRenderStateChange(D3D11_RENDER_STATE_TYPE type, const void* pState) {
        renderMonitor.OnRenderStateChange(type, pState);
    }
};
```

### BattlEye D3D Analysis
```cpp
// BE D3D hooking analysis
void BE_DetectD3DHooking() {
    // Monitor VMT modifications
    MonitorVMTModifications();
    
    // Analyze shader usage
    AnalyzeShaderUsage();
    
    // Check render states
    CheckRenderStates();
}

void MonitorVMTModifications() {
    // Hook VirtualProtect to detect VMT changes
    // Validate D3D VMT integrity
}

void AnalyzeShaderUsage() {
    // Monitor CreatePixelShader calls
    // Detect suspicious shader patterns
}
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | VMT checks |
| 2020-2024 | ⚠️ Médio risco | Shader analysis |
| 2025-2026 | ⚠️ Alto risco | State monitoring |

---

## 🎯 Lições Aprendidas

1. **VMT é Verificada**: Integridade da tabela virtual é checada.

2. **Shaders São Analisados**: Bytecode suspeito é detectado.

3. **Estados São Monitorados**: Mudanças em render state são rastreadas.

4. **ImGui é Mais Stealth**: Overlays externos são menos detectáveis.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#34]]
- [[ImGui_Based_Overlay]]
- [[External_Rendering]]
- [[Pixel_Shader_Injection]]

---

*Direct3D hooking tem risco moderado. Considere ImGui overlay para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
