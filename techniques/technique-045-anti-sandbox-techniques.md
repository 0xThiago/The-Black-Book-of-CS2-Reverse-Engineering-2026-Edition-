# 📖 Técnica 045: Anti-Sandbox Techniques

📅 Criado em: 2026-02-14
🔗 Tags: #conhecimento #referência #cs2

## 📌 Resumo
> > **Status:** ⚠️ Risco Moderado

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[Técnica 045: Anti-Sandbox Techniques]]

## 🔍 Desenvolvimento
> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**Anti-Sandbox Techniques** detectam ambientes de sandbox automatizados, forçando analistas a usar sistemas reais ou mais sofisticados para análise.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class AntiSandboxDetector {
private:
    std::vector<SANDBOX_CHECK> sandboxChecks;
    DETECTION_REPORT report;
    
public:
    AntiSandboxDetector() {
        InitializeSandboxChecks();
    }
    
    void InitializeSandboxChecks() {
        // Verificações de timing
        sandboxChecks.push_back({CHECK_UPTIME, "System uptime", []() { return CheckSystemUptime(); }});
        sandboxChecks.push_back({CHECK_SLEEP, "Sleep timing", []() { return CheckSleepTiming(); }});
        sandboxChecks.push_back({CHECK_CPU_USAGE, "CPU usage", []() { return CheckCPUUsage(); }});
        
        // Verificações de interação do usuário
        sandboxChecks.push_back({CHECK_MOUSE, "Mouse activity", []() { return CheckMouseActivity(); }});
        sandboxChecks.push_back({CHECK_KEYBOARD, "Keyboard activity", []() { return CheckKeyboardActivity(); }});
        sandboxChecks.push_back({CHECK_CLIPBOARD, "Clipboard content", []() { return CheckClipboardContent(); }});
        
        // Verificações de arquivos e diretórios
        sandboxChecks.push_back({CHECK_SANDBOX_FILES, "Sandbox files", []() { return CheckSandboxFiles(); }});
        sandboxChecks.push_back({CHECK_SANDBOX_DIRS, "Sandbox directories", []() { return CheckSandboxDirectories(); }});
        sandboxChecks.push_back({CHECK_RECENT_FILES, "Recent files", []() { return CheckRecentFiles(); }});
        
        // Verificações de rede
        sandboxChecks.push_back({CHECK_NETWORK, "Network activity", []() { return CheckNetworkActivity(); }});
        sandboxChecks.push_back({CHECK_DNS, "DNS queries", []() { return CheckDNSQueries(); }});
        sandboxChecks.push_back({CHECK_PROXY, "Proxy detection", []() { return CheckProxyDetection(); }});
        
        // Verificações de hardware
        sandboxChecks.push_back({CHECK_HARDWARE, "Hardware config", []() { return CheckHardwareConfiguration(); }});
        sandboxChecks.push_back({CHECK_MEMORY, "Memory patterns", []() { return CheckMemoryPatterns(); }});
        sandboxChecks.push_back({CHECK_DISK, "Disk patterns", []() { return CheckDiskPatterns(); }});
        
        // Verificações de processos
        sandboxChecks.push_back({CHECK_SANDBOX_PROCESSES, "Sandbox processes", []() { return CheckSandboxProcesses(); }});
        sandboxChecks.push_back({CHECK_PARENT_PROCESS, "Parent process", []() { return CheckParentProcess(); }});
        
        // Verificações avançadas
        sandboxChecks.push_back({CHECK_HOOKS, "API hooks", []() { return CheckAPIHooks(); }});
        sandboxChecks.push_back({CHECK_DEBUGGER, "Debugger presence", []() { return CheckDebuggerPresence(); }});
        sandboxChecks.push_back({CHECK_FORENSICS, "Forensic tools", []() { return CheckForensicTools(); }});
    }
    
    bool PerformSandboxChecks() {
        report.detectedSandbox = false;
        report.checkResults.clear();
        
        for (const SANDBOX_CHECK& check : sandboxChecks) {
            bool result = check.function();
            report.checkResults.push_back({check.name, result});
            
            if (result) {
                IdentifySandboxType(check);
                report.detectedSandbox = true;
            }
        }
        
        return report.detectedSandbox;
    }
    
    void IdentifySandboxType(const SANDBOX_CHECK& check) {
        // Identificar tipo de sandbox baseado na verificação
        if (check.type == CHECK_SANDBOX_FILES || check.type == CHECK_SANDBOX_DIRS) {
            report.detectedSandboxes.push_back("Generic Sandbox");
        } else if (check.type == CHECK_SANDBOX_PROCESSES) {
            if (CheckCuckooProcesses()) {
                report.detectedSandboxes.push_back("Cuckoo Sandbox");
            } else if (CheckJoeSandboxProcesses()) {
                report.detectedSandboxes.push_back("Joe Sandbox");
            }
        } else if (check.type == CHECK_NETWORK) {
            report.detectedSandboxes.push_back("Network Sandbox");
        }
    }
    
    void OnSandboxDetected() {
        // Ações quando sandbox é detectado
        LogSandboxDetected();
        
        // Comportamento diferente em sandbox
        ModifyBehaviorForSandbox();
        
        // Possivelmente exit ou comportamento limitado
        if (ShouldExitOnSandbox()) {
            ExitProcess(0);
        }
    }
    
    void LogSandboxDetected() {
        std::ofstream log("sandbox_detection.log", std::ios::app);
        log << "Sandbox detected at " << std::time(nullptr) << std::endl;
        for (const std::string& sandbox : report.detectedSandboxes) {
            log << "  - " << sandbox << std::endl;
        }
        log.close();
    }
    
    void ModifyBehaviorForSandbox() {
        // Modificar comportamento quando em sandbox
        // Delay execution, show fake behavior, etc.
        Sleep(15000); // 15 second delay
        
        // Mostrar atividade falsa
        for (int i = 0; i < 10; i++) {
            MessageBoxA(NULL, "Loading...", "Please wait", MB_OK);
            Sleep(1000);
        }
    }
    
    bool ShouldExitOnSandbox() {
        // Decidir se deve sair baseado na configuração
        return true; // Sempre sair por segurança
    }
    
    // Implementações das verificações
    static bool CheckSystemUptime() {
        DWORD uptime = GetTickCount() / 1000; // segundos
        
        // Sandbox normalmente tem uptime curto
        return uptime < 300; // Menos de 5 minutos
    }
    
    static bool CheckSleepTiming() {
        DWORD start = GetTickCount();
        Sleep(5000); // 5 segundos
        DWORD end = GetTickCount();
        
        DWORD actualSleep = end - start;
        
        // Em sandbox, sleep pode ser acelerado
        return actualSleep < 4000; // Menos de 4 segundos
    }
    
    static bool CheckCPUUsage() {
        // Verificar se CPU está ociosa (sandbox pode não simular carga)
        // Implementar verificação de uso de CPU
        
        return false; // Placeholder
    }
    
    static bool CheckMouseActivity() {
        POINT currentPos;
        GetCursorPos(&currentPos);
        
        // Verificar se mouse se moveu recentemente
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD timeSinceLastInput = GetTickCount() - lii.dwTime;
        
        // Sem atividade do mouse por muito tempo = possível sandbox
        return timeSinceLastInput > 300000; // 5 minutos
    }
    
    static bool CheckKeyboardActivity() {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD timeSinceLastInput = GetTickCount() - lii.dwTime;
        
        // Sem atividade do teclado por muito tempo = possível sandbox
        return timeSinceLastInput > 300000; // 5 minutos
    }
    
    static bool CheckClipboardContent() {
        if (!OpenClipboard(NULL)) return false;
        
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (!hData) {
            CloseClipboard();
            return false;
        }
        
        char* pszText = static_cast<char*>(GlobalLock(hData));
        if (!pszText) {
            CloseClipboard();
            return false;
        }
        
        std::string clipboardContent(pszText);
        GlobalUnlock(hData);
        CloseClipboard();
        
        // Clipboard vazia ou conteúdo padrão pode indicar sandbox
        return clipboardContent.empty() || clipboardContent == "CLIPBOARD_DATA";
    }
    
    static bool CheckSandboxFiles() {
        const char* sandboxFiles[] = {
            "C:\\sandbox\\",
            "C:\\analysis\\",
            "C:\\cuckoo\\",
            "C:\\joeboxserver\\",
            "C:\\sandboxstarter.exe",
            "C:\\Program Files\\Sandboxie\\"
        };
        
        for (const char* file : sandboxFiles) {
            if (PathFileExistsA(file)) {
                return true;
            }
        }
        
        return false;
    }
    
    static bool CheckSandboxDirectories() {
        const char* sandboxDirs[] = {
            "C:\\sandbox",
            "C:\\analysis",
            "C:\\cuckoo",
            "C:\\joeboxserver",
            "C:\\Program Files\\Sandboxie"
        };
        
        for (const char* dir : sandboxDirs) {
            if (PathIsDirectoryA(dir)) {
                return true;
            }
        }
        
        return false;
    }
    
    static bool CheckRecentFiles() {
        // Verificar se há arquivos recentes (sandbox normalmente limpo)
        WIN32_FIND_DATAA findData;
        HANDLE hFind = FindFirstFileA("C:\\Users\\*\\Recent\\*", &findData);
        
        if (hFind == INVALID_HANDLE_VALUE) return true; // Nenhum arquivo recente
        
        FindClose(hFind);
        return false;
    }
    
    static bool CheckNetworkActivity() {
        // Verificar conectividade de rede limitada
        return !InternetCheckConnectionA("http://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0);
    }
    
    static bool CheckDNSQueries() {
        // Verificar DNS queries suspeitas
        // Implementar verificação de DNS
        
        return false; // Placeholder
    }
    
    static bool CheckProxyDetection() {
        // Verificar se está atrás de proxy
        WINHTTP_CURRENT_USER_IE_PROXY_CONFIG proxyConfig;
        WinHttpGetIEProxyConfigForCurrentUser(&proxyConfig);
        
        return proxyConfig.lpszProxy != NULL;
    }
    
    static bool CheckHardwareConfiguration() {
        // Verificar configuração de hardware suspeita
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        // Memória muito pequena ou muito grande pode indicar sandbox
        const uint64_t GB = 1024 * 1024 * 1024;
        return memStatus.ullTotalPhys < 1 * GB || memStatus.ullTotalPhys > 32 * GB;
    }
    
    static bool CheckMemoryPatterns() {
        // Verificar padrões de memória suspeitos
        // Implementar verificação de padrões de memória
        
        return false; // Placeholder
    }
    
    static bool CheckDiskPatterns() {
        // Verificar padrões de disco suspeitos
        ULARGE_INTEGER freeBytes, totalBytes, freeBytesAvailable;
        GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &freeBytes);
        
        // Disco muito pequeno pode indicar sandbox
        const uint64_t GB = 1024 * 1024 * 1024;
        return totalBytes.QuadPart < 10 * GB;
    }
    
    static bool CheckSandboxProcesses() {
        return CheckCuckooProcesses() || CheckJoeSandboxProcesses() || CheckSandboxieProcesses();
    }
    
    static bool CheckCuckooProcesses() {
        const char* cuckooProcs[] = {
            "cuckoo.exe",
            "cuckoomon.exe",
            "analyzer.exe"
        };
        
        return CheckProcessList(cuckooProcs, sizeof(cuckooProcs) / sizeof(cuckooProcs[0]));
    }
    
    static bool CheckJoeSandboxProcesses() {
        const char* joeProcs[] = {
            "joeboxserver.exe",
            "joeboxcontrol.exe",
            "joesandbox.exe"
        };
        
        return CheckProcessList(joeProcs, sizeof(joeProcs) / sizeof(joeProcs[0]));
    }
    
    static bool CheckSandboxieProcesses() {
        const char* sandboxieProcs[] = {
            "SandboxieRpcSs.exe",
            "SandboxieDcomLaunch.exe",
            "SandboxieBITS.exe"
        };
        
        return CheckProcessList(sandboxieProcs, sizeof(sandboxieProcs) / sizeof(sandboxieProcs[0]));
    }
    
    static bool CheckParentProcess() {
        // Verificar processo pai suspeito
        DWORD parentPid = GetParentProcessId();
        
        // Obter nome do processo pai
        char parentName[MAX_PATH];
        if (GetProcessNameById(parentPid, parentName, MAX_PATH)) {
            const char* suspiciousParents[] = {
                "cuckoo.exe",
                "analyzer.exe",
                "sandbox.exe"
            };
            
            for (const char* parent : suspiciousParents) {
                if (_stricmp(parentName, parent) == 0) {
                    return true;
                }
            }
        }
        
        return false;
    }
    
    static bool CheckAPIHooks() {
        // Verificar hooks em APIs críticas
        return IsAPIHooked("kernel32.dll", "CreateFileA") ||
               IsAPIHooked("kernel32.dll", "ReadProcessMemory");
    }
    
    static bool CheckDebuggerPresence() {
        return IsDebuggerPresent() || CheckRemoteDebuggerPresent();
    }
    
    static bool CheckRemoteDebuggerPresent() {
        BOOL isDebugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebugged);
        return isDebugged;
    }
    
    static bool CheckForensicTools() {
        // Verificar ferramentas forenses instaladas
        const char* forensicTools[] = {
            "C:\\Program Files\\Wireshark\\",
            "C:\\Program Files\\IDA Pro\\",
            "C:\\Program Files\\OllyDbg\\",
            "C:\\Program Files\\Process Hacker\\"
        };
        
        for (const char* tool : forensicTools) {
            if (PathFileExistsA(tool)) {
                return true;
            }
        }
        
        return false;
    }
    
    // Utility functions
    static bool CheckProcessList(const char* processes[], size_t count) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                for (size_t i = 0; i < count; i++) {
                    if (_stricmp(pe.szExeFile, processes[i]) == 0) {
                        CloseHandle(hSnapshot);
                        return true;
                    }
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    static DWORD GetParentProcessId() {
        // Implementar obtenção do PID do processo pai
        return 0; // Placeholder
    }
    
    static bool GetProcessNameById(DWORD processId, char* processName, size_t bufferSize) {
        // Implementar obtenção do nome do processo por ID
        return false; // Placeholder
    }
    
    static bool IsAPIHooked(const char* module, const char* function) {
        HMODULE hModule = GetModuleHandleA(module);
        if (!hModule) return false;
        
        PVOID pFunction = GetProcAddress(hModule, function);
        if (!pFunction) return false;
        
        // Verificar prólogo da função
        __try {
            BYTE* bytes = (BYTE*)pFunction;
            return bytes[0] == 0xE9 || bytes[0] == 0xFF; // JMP ou CALL
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return true; // Não conseguiu ler - possível hook
        }
    }
};
```

### Advanced Anti-Sandbox Techniques

```cpp
// Técnicas avançadas anti-sandbox
class AdvancedAntiSandboxDetector : public AntiSandboxDetector {
private:
    std::vector<ADVANCED_SANDBOX_CHECK> advancedChecks;
    ANTI_EVASION_TECHNIQUES evasionTech;
    
public:
    AdvancedAntiSandboxDetector() {
        InitializeAdvancedChecks();
        InitializeAntiEvasion();
    }
    
    void InitializeAdvancedChecks() {
        // Verificações avançadas
        advancedChecks.push_back({CHECK_BEHAVIORAL, "Behavioral analysis", []() { return CheckBehavioralAnalysis(); }});
        advancedChecks.push_back({CHECK_ENTROPY, "Entropy analysis", []() { return CheckEntropyAnalysis(); }});
        advancedChecks.push_back({CHECK_SIGNATURE, "Signature scanning", []() { return CheckSignatureScanning(); }});
        advancedChecks.push_back({CHECK_DYNAMIC, "Dynamic analysis", []() { return CheckDynamicAnalysis(); }});
        advancedChecks.push_back({CHECK_AUTOMATION, "Automation detection", []() { return CheckAutomationDetection(); }});
        advancedChecks.push_back({CHECK_RESOURCE, "Resource monitoring", []() { return CheckResourceMonitoring(); }});
        advancedChecks.push_back({CHECK_TIME, "Time-based detection", []() { return CheckTimeBasedDetection(); }});
        advancedChecks.push_back({CHECK_INTERACTION, "Interaction simulation", []() { return CheckInteractionSimulation(); }});
    }
    
    void InitializeAntiEvasion() {
        evasionTech.useDelayedExecution = true;
        evasionTech.useConditionalBehavior = true;
        evasionTech.useAntiAnalysisTechniques = true;
        evasionTech.useContextAwareness = true;
    }
    
    bool PerformAdvancedSandboxChecks() {
        // Executar verificações básicas primeiro
        if (AntiSandboxDetector::PerformSandboxChecks()) {
            return true;
        }
        
        // Executar verificações avançadas
        for (const ADVANCED_SANDBOX_CHECK& check : advancedChecks) {
            if (evasionTech.useDelayedExecution) {
                Sleep(1000 + rand() % 2000); // Delay aleatório
            }
            
            if (check.function()) {
                report.detectedSandbox = true;
                report.advancedDetection = true;
                return true;
            }
        }
        
        return false;
    }
    
    // Implementações avançadas
    static bool CheckBehavioralAnalysis() {
        // Verificar se comportamento está sendo analisado
        // Monitorar chamadas de API suspeitas
        
        return false; // Placeholder
    }
    
    static bool CheckEntropyAnalysis() {
        // Verificar se código está sendo analisado por entropia
        // Código com alta entropia pode ser detectado
        
        return false; // Placeholder
    }
    
    static bool CheckSignatureScanning() {
        // Verificar se assinaturas estão sendo escaneadas
        // Código pode ser modificado para evitar assinaturas
        
        return false; // Placeholder
    }
    
    static bool CheckDynamicAnalysis() {
        // Verificar análise dinâmica
        // Comportamento pode ser modificado durante análise
        
        return false; // Placeholder
    }
    
    static bool CheckAutomationDetection() {
        // Detectar automação
        // Verificar se execução é automatizada
        
        return CheckNoUserInteraction() || CheckAutomatedExecution();
    }
    
    static bool CheckResourceMonitoring() {
        // Verificar monitoramento de recursos
        // CPU, memória, I/O sendo monitorados
        
        return false; // Placeholder
    }
    
    static bool CheckTimeBasedDetection() {
        // Detecção baseada em tempo
        // Verificar se execução leva tempo suficiente
        
        DWORD startTime = GetTickCount();
        // Simular atividade normal
        for (int i = 0; i < 100; i++) {
            Sleep(100);
            // Fazer algo
        }
        DWORD endTime = GetTickCount();
        
        // Se execução foi muito rápida, pode ser sandbox
        return (endTime - startTime) < 5000; // Menos de 5 segundos
    }
    
    static bool CheckInteractionSimulation() {
        // Verificar se interações estão sendo simuladas
        // Mouse, teclado simulados podem ser detectados
        
        return CheckSimulatedMouse() || CheckSimulatedKeyboard();
    }
    
    static bool CheckNoUserInteraction() {
        // Verificar ausência de interação do usuário
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD idleTime = GetTickCount() - lii.dwTime;
        return idleTime > 600000; // 10 minutos sem interação
    }
    
    static bool CheckAutomatedExecution() {
        // Verificar execução automatizada
        // Verificar variáveis de ambiente, argumentos de linha de comando
        
        return CheckCommandLineArgs() || CheckEnvironmentVariables();
    }
    
    static bool CheckSimulatedMouse() {
        // Verificar se mouse está sendo simulado
        POINT pos1, pos2;
        GetCursorPos(&pos1);
        Sleep(100);
        GetCursorPos(&pos2);
        
        // Movimento muito preciso pode indicar simulação
        return abs(pos1.x - pos2.x) == 0 && abs(pos1.y - pos2.y) == 0;
    }
    
    static bool CheckSimulatedKeyboard() {
        // Verificar se teclado está sendo simulado
        // Implementar verificação de entrada de teclado simulada
        
        return false; // Placeholder
    }
    
    static bool CheckCommandLineArgs() {
        // Verificar argumentos de linha de comando suspeitos
        LPSTR cmdLine = GetCommandLineA();
        
        return strstr(cmdLine, "sandbox") != NULL ||
               strstr(cmdLine, "analysis") != NULL ||
               strstr(cmdLine, "cuckoo") != NULL;
    }
    
    static bool CheckEnvironmentVariables() {
        // Verificar variáveis de ambiente suspeitas
        const char* suspiciousVars[] = {
            "SANDBOX",
            "ANALYSIS",
            "CUCKOO",
            "JOEBOX"
        };
        
        for (const char* var : suspiciousVars) {
            if (GetEnvironmentVariableA(var, NULL, 0) > 0) {
                return true;
            }
        }
        
        return false;
    }
    
    // Anti-evasion techniques
    void ApplyAntiEvasion() {
        if (evasionTech.useDelayedExecution) {
            ApplyDelayedExecution();
        }
        
        if (evasionTech.useConditionalBehavior) {
            ApplyConditionalBehavior();
        }
        
        if (evasionTech.useAntiAnalysisTechniques) {
            ApplyAntiAnalysisTechniques();
        }
        
        if (evasionTech.useContextAwareness) {
            ApplyContextAwareness();
        }
    }
    
    void ApplyDelayedExecution() {
        // Executar verificações com delays
        for (SANDBOX_CHECK& check : sandboxChecks) {
            check.delay = 2000 + rand() % 3000; // 2-5 segundos
        }
    }
    
    void ApplyConditionalBehavior() {
        // Modificar comportamento baseado em condições
        if (IsLikelySandbox()) {
            SetSandboxBehavior();
        } else {
            SetNormalBehavior();
        }
    }
    
    void ApplyAntiAnalysisTechniques() {
        // Aplicar técnicas anti-análise
        ObfuscateCode();
        UseAntiDebugging();
        ImplementAntiHooking();
    }
    
    void ApplyContextAwareness() {
        // Adaptar baseado no contexto
        if (IsHighPerformanceSystem()) {
            // Sistema potente - verificações mais rigorosas
            IncreaseSensitivity();
        } else {
            // Sistema normal - verificações padrão
            UseStandardSensitivity();
        }
    }
    
    bool IsLikelySandbox() {
        // Avaliar se é provável sandbox
        return CheckSystemUptime() || CheckNoUserInteraction();
    }
    
    void SetSandboxBehavior() {
        // Comportamento para sandbox - limitado, falso
        report.sandboxMode = true;
    }
    
    void SetNormalBehavior() {
        // Comportamento normal
        report.normalMode = true;
    }
    
    void ObfuscateCode() {
        // Ofuscar código para evitar análise
        // Implementar ofuscação
    }
    
    void UseAntiDebugging() {
        // Usar técnicas anti-debugging
        // Implementar anti-debugging
    }
    
    void ImplementAntiHooking() {
        // Implementar anti-hooking
        // Implementar anti-hooking
    }
    
    bool IsHighPerformanceSystem() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        return memStatus.ullTotalPhys > 8LL * 1024 * 1024 * 1024; // > 8GB RAM
    }
    
    void IncreaseSensitivity() {
        // Aumentar sensibilidade das verificações
        // ...
    }
    
    void UseStandardSensitivity() {
        // Usar sensibilidade padrão
        // ...
    }
};
```

### Por que é Detectado

> [!WARNING]
> **Anti-sandbox deixa rastros através de verificações óbvias e comportamento suspeito**

#### 1. Signature-Based Detection
```cpp
// Detecção baseada em assinaturas
class AntiSandboxSignatureDetector {
private:
    std::vector<SANDBOX_SIGNATURE> knownSignatures;
    
public:
    void InitializeSignatures() {
        // Assinaturas de verificações anti-sandbox conhecidas
        knownSignatures.push_back({
            "Uptime_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x20, 0x4E, 0x00, 0x00}, // CALL GetTickCount; CMP EAX, 20000
            "System uptime check"
        });
        
        knownSignatures.push_back({
            "Sleep_Check",
            {0x6A, 0x05, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x3D, 0x00, 0x0F, 0x00, 0x00}, // PUSH 5; CALL Sleep; CMP
            "Sleep timing check"
        });
        
        knownSignatures.push_back({
            "Mouse_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x81, 0x38, 0x80, 0x3E, 0x00, 0x00}, // CALL GetLastInputInfo; CMP DWORD PTR
            "Mouse activity check"
        });
        
        knownSignatures.push_back({
            "Sandbox_Files_Check",
            {0x68, 0x00, 0x00, 0x00, 0x00, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // PUSH "C:\sandbox"; CALL PathFileExists; TEST EAX,EAX
            "Sandbox files check"
        });
        
        knownSignatures.push_back({
            "Process_Check",
            {0x8D, 0x45, 0xFC, 0x50, 0x68, 0x00, 0x00, 0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // LEA; PUSH; PUSH; CALL; TEST
            "Sandbox process check"
        });
        
        knownSignatures.push_back({
            "Clipboard_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x6A, 0x01, 0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x85, 0xC0}, // CALL OpenClipboard; PUSH 1; CALL GetClipboardData; TEST
            "Clipboard content check"
        });
        
        knownSignatures.push_back({
            "Hardware_Check",
            {0xFF, 0x15, 0x00, 0x00, 0x00, 0x00, 0x81, 0x78, 0x10, 0x00, 0x00, 0x00, 0x01}, // CALL GlobalMemoryStatusEx; CMP DWORD PTR [EAX+10], 100000000
            "Hardware configuration check"
        });
    }
    
    void ScanForAntiSandboxSignatures(PVOID baseAddress, SIZE_T size) {
        BYTE* code = (BYTE*)baseAddress;
        
        for (const SANDBOX_SIGNATURE& sig : knownSignatures) {
            if (FindSignature(code, size, sig)) {
                ReportAntiSandboxSignature(sig.description);
            }
        }
    }
    
    bool FindSignature(BYTE* code, SIZE_T size, const SANDBOX_SIGNATURE& sig) {
        for (SIZE_T i = 0; i < size - sig.pattern.size(); i++) {
            if (memcmp(&code[i], sig.pattern.data(), sig.pattern.size()) == 0) {
                return true;
            }
        }
        return false;
    }
    
    void ReportAntiSandboxSignature(const std::string& description) {
        std::cout << "Anti-sandbox signature detected: " << description << std::endl;
    }
};
```

#### 2. Behavioral Analysis
```cpp
// Análise comportamental
class AntiSandboxBehavioralAnalyzer {
private:
    std::map<DWORD, PROCESS_SANDBOX_BEHAVIOR> processBehaviors;
    
public:
    void MonitorProcessSandboxBehavior(DWORD processId) {
        // Registrar comportamento normal
        RegisterNormalSandboxBehavior(processId);
        
        // Monitorar desvios
        StartSandboxBehaviorMonitoring(processId);
    }
    
    void RegisterNormalSandboxBehavior(DWORD processId) {
        PROCESS_SANDBOX_BEHAVIOR behavior;
        
        // APIs que um processo normal chama
        behavior.expectedAPIs = {
            "kernel32.dll!GetTickCount",
            "user32.dll!GetCursorPos",
            "kernel32.dll!Sleep"
        };
        
        // Comportamento de timing normal
        behavior.expectedTiming.maxAPICallTime = 100; // ms
        behavior.expectedTiming.minExecutionTime = 10000; // 10 segundos
        
        processBehaviors[processId] = behavior;
    }
    
    void StartSandboxBehaviorMonitoring(DWORD processId) {
        std::thread([this, processId]() {
            while (true) {
                CheckSandboxBehavioralAnomalies(processId);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        }).detach();
    }
    
    void CheckSandboxBehavioralAnomalies(DWORD processId) {
        if (processBehaviors.find(processId) == processBehaviors.end()) return;
        
        PROCESS_SANDBOX_BEHAVIOR& behavior = processBehaviors[processId];
        
        // Verificar APIs suspeitas de detecção de sandbox
        if (HasSuspiciousSandboxAPICalls(processId)) {
            ReportSuspiciousSandboxAPIs(processId);
        }
        
        // Verificar timing anormal
        if (HasAbnormalSandboxTiming(processId, behavior.expectedTiming)) {
            ReportAbnormalSandboxTiming(processId);
        }
        
        // Verificar acesso a recursos suspeitos
        if (HasSuspiciousResourceAccess(processId)) {
            ReportSuspiciousResourceAccess(processId);
        }
        
        // Verificar comportamento evasivo
        if (HasEvasiveBehavior(processId)) {
            ReportEvasiveBehavior(processId);
        }
    }
    
    bool HasSuspiciousSandboxAPICalls(DWORD processId) {
        // Verificar se processo está chamando muitas APIs de detecção de sandbox
        // GetTickCount, GetLastInputInfo, PathFileExists, etc.
        
        return false; // Placeholder
    }
    
    bool HasAbnormalSandboxTiming(DWORD processId, const SANDBOX_TIMING_PROFILE& expected) {
        // Verificar se processo tem delays suspeitos ou execução muito rápida
        
        return false; // Placeholder
    }
    
    bool HasSuspiciousResourceAccess(DWORD processId) {
        // Verificar acesso a arquivos/diretórios suspeitos
        
        return false; // Placeholder
    }
    
    bool HasEvasiveBehavior(DWORD processId) {
        // Verificar comportamento evasivo (delays, fake activity)
        
        return false; // Placeholder
    }
    
    void ReportSuspiciousSandboxAPIs(DWORD processId) {
        std::cout << "Suspicious sandbox detection APIs detected in process " << processId << std::endl;
    }
    
    void ReportAbnormalSandboxTiming(DWORD processId) {
        std::cout << "Abnormal sandbox timing detected in process " << processId << std::endl;
    }
    
    void ReportSuspiciousResourceAccess(DWORD processId) {
        std::cout << "Suspicious resource access in process " << processId << std::endl;
    }
    
    void ReportEvasiveBehavior(DWORD processId) {
        std::cout << "Evasive behavior detected in process " << processId << std::endl;
    }
};
```

#### 3. Anti-Anti-Sandbox Techniques
```cpp
// Técnicas anti-anti-sandbox
class AntiAntiSandbox {
public:
    void BypassAntiSandboxChecks() {
        // Bypass verificações comuns
        BypassUptimeChecks();
        BypassSleepChecks();
        BypassUserInteractionChecks();
        BypassFileChecks();
        BypassProcessChecks();
        BypassHardwareChecks();
    }
    
    void BypassUptimeChecks() {
        // Hook GetTickCount para retornar uptime falso
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pGetTickCount = GetProcAddress(hKernel32, "GetTickCount");
        
        MH_CreateHook(pGetTickCount, &HkGetTickCount, &oGetTickCount);
        MH_EnableHook(pGetTickCount);
    }
    
    static DWORD WINAPI HkGetTickCount() {
        // Retornar uptime falso (30 minutos)
        return 30 * 60 * 1000 + rand() % 60000;
    }
    
    void BypassSleepChecks() {
        // Hook Sleep para timing normal
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pSleep = GetProcAddress(hKernel32, "Sleep");
        
        MH_CreateHook(pSleep, &HkSleep, &oSleep);
        MH_EnableHook(pSleep);
    }
    
    static void WINAPI HkSleep(DWORD dwMilliseconds) {
        // Simular sleep normal
        LARGE_INTEGER start, end, freq;
        QueryPerformanceFrequency(&freq);
        QueryPerformanceCounter(&start);
        
        do {
            QueryPerformanceCounter(&end);
        } while ((end.QuadPart - start.QuadPart) * 1000 / freq.QuadPart < dwMilliseconds);
    }
    
    void BypassUserInteractionChecks() {
        // Hook GetLastInputInfo para simular atividade
        HMODULE hUser32 = GetModuleHandleA("user32.dll");
        PVOID pGetLastInputInfo = GetProcAddress(hUser32, "GetLastInputInfo");
        
        MH_CreateHook(pGetLastInputInfo, &HkGetLastInputInfo, &oGetLastInputInfo);
        MH_EnableHook(pGetLastInputInfo);
    }
    
    static BOOL WINAPI HkGetLastInputInfo(PLASTINPUTINFO plii) {
        BOOL result = oGetLastInputInfo(plii);
        
        // Simular atividade recente
        plii->dwTime = GetTickCount() - 5000; // 5 segundos atrás
        
        return result;
    }
    
    void BypassFileChecks() {
        // Hook PathFileExists para esconder arquivos de sandbox
        HMODULE hShlwapi = GetModuleHandleA("shlwapi.dll");
        PVOID pPathFileExists = GetProcAddress(hShlwapi, "PathFileExistsA");
        
        MH_CreateHook(pPathFileExists, &HkPathFileExists, &oPathFileExists);
        MH_EnableHook(pPathFileExists);
    }
    
    static BOOL WINAPI HkPathFileExists(LPCSTR pszPath) {
        // Esconder arquivos de sandbox
        if (strstr(pszPath, "sandbox") || strstr(pszPath, "cuckoo") || strstr(pszPath, "analysis")) {
            return FALSE;
        }
        
        return oPathFileExists(pszPath);
    }
    
    void BypassProcessChecks() {
        // Hook CreateToolhelp32Snapshot e Process32* para esconder processos
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        
        PVOID pCreateToolhelp32Snapshot = GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
        MH_CreateHook(pCreateToolhelp32Snapshot, &HkCreateToolhelp32Snapshot, &oCreateToolhelp32Snapshot);
        MH_EnableHook(pCreateToolhelp32Snapshot);
        
        PVOID pProcess32First = GetProcAddress(hKernel32, "Process32First");
        MH_CreateHook(pProcess32First, &HkProcess32First, &oProcess32First);
        MH_EnableHook(pProcess32First);
        
        PVOID pProcess32Next = GetProcAddress(hKernel32, "Process32Next");
        MH_CreateHook(pProcess32Next, &HkProcess32Next, &oProcess32Next);
        MH_EnableHook(pProcess32Next);
    }
    
    static HANDLE WINAPI HkCreateToolhelp32Snapshot(DWORD dwFlags, DWORD th32ProcessID) {
        HANDLE hSnapshot = oCreateToolhelp32Snapshot(dwFlags, th32ProcessID);
        
        if (hSnapshot != INVALID_HANDLE_VALUE && (dwFlags & TH32CS_SNAPPROCESS)) {
            // Marcar snapshot como modificado
            // ...
        }
        
        return hSnapshot;
    }
    
    static BOOL WINAPI HkProcess32First(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
        BOOL result = oProcess32First(hSnapshot, lppe);
        
        if (result) {
            // Filtrar processos de sandbox
            if (IsSandboxProcess(lppe->szExeFile)) {
                // Pular este processo
                return HkProcess32Next(hSnapshot, lppe);
            }
        }
        
        return result;
    }
    
    static BOOL WINAPI HkProcess32Next(HANDLE hSnapshot, LPPROCESSENTRY32 lppe) {
        BOOL result;
        
        do {
            result = oProcess32Next(hSnapshot, lppe);
            if (!result) break;
        } while (IsSandboxProcess(lppe->szExeFile));
        
        return result;
    }
    
    static bool IsSandboxProcess(const char* processName) {
        const char* sandboxProcesses[] = {
            "cuckoo.exe", "analyzer.exe", "joeboxserver.exe", "SandboxieRpcSs.exe"
        };
        
        for (const char* proc : sandboxProcesses) {
            if (_stricmp(processName, proc) == 0) {
                return true;
            }
        }
        
        return false;
    }
    
    void BypassHardwareChecks() {
        // Hook GlobalMemoryStatusEx para retornar valores normais
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        PVOID pGlobalMemoryStatusEx = GetProcAddress(hKernel32, "GlobalMemoryStatusEx");
        
        MH_CreateHook(pGlobalMemoryStatusEx, &HkGlobalMemoryStatusEx, &oGlobalMemoryStatusEx);
        MH_EnableHook(pGlobalMemoryStatusEx);
    }
    
    static BOOL WINAPI HkGlobalMemoryStatusEx(LPMEMORYSTATUSEX lpBuffer) {
        BOOL result = oGlobalMemoryStatusEx(lpBuffer);
        
        // Ajustar valores para parecer sistema normal
        if (lpBuffer->ullTotalPhys < 2LL * 1024 * 1024 * 1024) { // < 2GB
            lpBuffer->ullTotalPhys = 8LL * 1024 * 1024 * 1024; // 8GB
        }
        
        return result;
    }
    
    // Original function pointers
    static decltype(&GetTickCount) oGetTickCount;
    static decltype(&Sleep) oSleep;
    static decltype(&GetLastInputInfo) oGetLastInputInfo;
    static decltype(&PathFileExistsA) oPathFileExists;
    static decltype(&CreateToolhelp32Snapshot) oCreateToolhelp32Snapshot;
    static decltype(&Process32First) oProcess32First;
    static decltype(&Process32Next) oProcess32Next;
    static decltype(&GlobalMemoryStatusEx) oGlobalMemoryStatusEx;
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Signature scanning | < 30s | 85% |
| VAC Live | Behavioral analysis | Imediato | 80% |
| BattlEye | Anti-bypass hooks | < 1 min | 90% |
| Faceit AC | Timing analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Delayed Execution
```cpp
// ✅ Execução atrasada
class DelayedExecutionSandboxBypass {
private:
    std::chrono::steady_clock::time_point startTime;
    std::vector<DELAYED_CHECK> delayedChecks;
    
public:
    DelayedExecutionSandboxBypass() {
        startTime = std::chrono::steady_clock::now();
        InitializeDelayedChecks();
    }
    
    void InitializeDelayedChecks() {
        // Verificações que só executam após delay
        delayedChecks.push_back({300, []() { return CheckSystemUptime(); }}); // 5 minutos
        delayedChecks.push_back({600, []() { return CheckUserInteraction(); }}); // 10 minutos
        delayedChecks.push_back({900, []() { return CheckNetworkActivity(); }}); // 15 minutos
    }
    
    bool ShouldExecute() {
        auto currentTime = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
        
        // Só executar se passou tempo suficiente
        return elapsed.count() > 300; // 5 minutos
    }
    
    void PerformDelayedChecks() {
        if (!ShouldExecute()) {
            return; // Ainda não é hora
        }
        
        for (const DELAYED_CHECK& check : delayedChecks) {
            auto currentTime = std::chrono::steady_clock::now();
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
            
            if (elapsed.count() >= check.delaySeconds) {
                if (check.function()) {
                    OnSandboxDetected();
                    break;
                }
            }
        }
    }
    
    void OnSandboxDetected() {
        // Sandbox detectado após delay
        // Comportamento apropriado
        ExitProcess(0);
    }
    
    // Utility functions
    static bool CheckSystemUptime() {
        DWORD uptime = GetTickCount() / 1000;
        return uptime < 600; // 10 minutos
    }
    
    static bool CheckUserInteraction() {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD idleTime = GetTickCount() - lii.dwTime;
        return idleTime > 1800000; // 30 minutos
    }
    
    static bool CheckNetworkActivity() {
        // Verificar atividade de rede significativa
        return false; // Placeholder
    }
};
```

### 2. Conditional Behavior
```cpp
// ✅ Comportamento condicional
class ConditionalBehaviorSandboxBypass {
private:
    ENVIRONMENT_STATE environment;
    
public:
    void AnalyzeEnvironment() {
        // Analisar ambiente continuamente
        DetectEnvironmentType();
        
        // Adaptar comportamento
        AdaptBehavior();
    }
    
    void DetectEnvironmentType() {
        // Detectar tipo de ambiente baseado em múltiplos fatores
        environment.isSandbox = EvaluateSandboxLikelihood();
        environment.isDebugger = IsDebuggerPresent();
        environment.isAutomated = CheckAutomation();
        environment.confidence = CalculateConfidence();
    }
    
    void AdaptBehavior() {
        if (environment.isSandbox && environment.confidence > 0.8) {
            // Ambiente hostil - comportamento limitado
            RunLimitedBehavior();
        } else if (environment.confidence < 0.3) {
            // Ambiente normal - comportamento completo
            RunFullBehavior();
        } else {
            // Ambiente incerto - comportamento gradual
            RunGradualBehavior();
        }
    }
    
    bool EvaluateSandboxLikelihood() {
        int score = 0;
        
        // Fatores que indicam sandbox
        if (GetTickCount() / 1000 < 300) score += 2; // Uptime < 5min
        if (CheckNoUserActivity()) score += 2; // Sem atividade do usuário
        if (CheckLimitedHardware()) score += 1; // Hardware limitado
        if (CheckSandboxFiles()) score += 3; // Arquivos de sandbox
        
        return score > 4; // Threshold
    }
    
    double CalculateConfidence() {
        double confidence = 0.0;
        
        if (environment.isSandbox) confidence += 0.7;
        if (environment.isDebugger) confidence += 0.2;
        if (environment.isAutomated) confidence += 0.1;
        
        return min(confidence, 1.0);
    }
    
    void RunLimitedBehavior() {
        // Comportamento limitado para sandbox
        // Não executar funcionalidades principais
        ShowFakeLoading();
        Sleep(30000); // 30 segundos
        ExitProcess(0);
    }
    
    void RunFullBehavior() {
        // Comportamento completo
        ExecuteCheatFunctionality();
    }
    
    void RunGradualBehavior() {
        // Comportamento gradual
        // Começar com verificações, depois funcionalidades
        if (PassedInitialChecks()) {
            ExecuteCheatFunctionality();
        } else {
            RunLimitedBehavior();
        }
    }
    
    void ShowFakeLoading() {
        // Mostrar loading falso
        for (int i = 0; i < 10; i++) {
            std::cout << "Loading... " << (i + 1) * 10 << "%" << std::endl;
            Sleep(1000);
        }
    }
    
    bool PassedInitialChecks() {
        // Verificações iniciais
        return !CheckNoUserActivity() && !CheckLimitedHardware();
    }
    
    // Utility functions
    static bool CheckNoUserActivity() {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        
        DWORD idleTime = GetTickCount() - lii.dwTime;
        return idleTime > 600000; // 10 minutos
    }
    
    static bool CheckLimitedHardware() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        
        return memStatus.ullTotalPhys < 4LL * 1024 * 1024 * 1024; // < 4GB
    }
    
    static bool CheckSandboxFiles() {
        return PathFileExistsA("C:\\sandbox\\") ||
               PathFileExistsA("C:\\cuckoo\\");
    }
    
    static bool CheckAutomation() {
        // Verificar se execução é automatizada
        return CheckCommandLineAutomation() || CheckEnvironmentAutomation();
    }
    
    static bool CheckCommandLineAutomation() {
        LPSTR cmdLine = GetCommandLineA();
        return strstr(cmdLine, "auto") != NULL ||
               strstr(cmdLine, "test") != NULL;
    }
    
    static bool CheckEnvironmentAutomation() {
        return GetEnvironmentVariableA("CI", NULL, 0) > 0 ||
               GetEnvironmentVariableA("AUTOMATION", NULL, 0) > 0;
    }
    
    void ExecuteCheatFunctionality() {
        // Implementar funcionalidade do cheat
    }
};
```

### 3. Context-Aware Detection
```cpp
// ✅ Detecção consciente do contexto
class ContextAwareSandboxDetector {
private:
    SYSTEM_CONTEXT context;
    DETECTION_STRATEGY strategy;
    
public:
    void PerformContextAwareDetection() {
        // Coletar contexto do sistema
        GatherSystemContext();
        
        // Avaliar contexto
        EvaluateContext();
        
        // Escolher estratégia de detecção
        ChooseDetectionStrategy();
        
        // Executar detecção
        ExecuteDetection();
    }
    
    void GatherSystemContext() {
        context.uptime = GetTickCount() / 1000;
        context.userIdleTime = GetUserIdleTime();
        context.memorySize = GetMemorySize();
        context.diskSize = GetDiskSize();
        context.hasNetwork = CheckNetworkConnectivity();
        context.installedPrograms = GetInstalledProgramsCount();
        context.runningProcesses = GetRunningProcessesCount();
    }
    
    void EvaluateContext() {
        // Avaliar se contexto parece normal ou de análise
        context.likelihoodScore = CalculateLikelihoodScore();
        context.isLikelyRealSystem = context.likelihoodScore < 0.3;
        context.isLikelySandbox = context.likelihoodScore > 0.7;
        context.isUncertain = context.likelihoodScore >= 0.3 && context.likelihoodScore <= 0.7;
    }
    
    void ChooseDetectionStrategy() {
        if (context.isLikelyRealSystem) {
            // Sistema real - detecção leve
            strategy.useAggressiveChecks = false;
            strategy.useDelayedChecks = true;
            strategy.checkFrequency = LOW;
        } else if (context.isLikelySandbox) {
            // Sandbox - detecção stealth ou exit
            strategy.useStealthMode = true;
            strategy.exitOnDetection = true;
            strategy.checkFrequency = HIGH;
        } else {
            // Incerto - detecção gradual
            strategy.useGradualChecks = true;
            strategy.adaptToFeedback = true;
            strategy.checkFrequency = MEDIUM;
        }
    }
    
    void ExecuteDetection() {
        if (strategy.useStealthMode) {
            ExecuteStealthDetection();
        } else if (strategy.useGradualChecks) {
            ExecuteGradualDetection();
        } else {
            ExecuteStandardDetection();
        }
    }
    
    void ExecuteStealthDetection() {
        // Detecção stealth - verificações espaçadas, sutis
        std::thread([this]() {
            while (true) {
                PerformStealthCheck();
                Sleep(CalculateStealthDelay());
            }
        }).detach();
    }
    
    void ExecuteGradualDetection() {
        // Detecção gradual - começar simples, aumentar complexidade
        if (PerformBasicChecks()) {
            if (PerformIntermediateChecks()) {
                PerformAdvancedChecks();
            }
        }
    }
    
    void ExecuteStandardDetection() {
        // Detecção padrão
        AntiSandboxDetector detector;
        if (detector.PerformSandboxChecks()) {
            HandleDetection();
        }
    }
    
    void PerformStealthCheck() {
        // Verificação stealth
        if (CheckSubtleIndicator()) {
            HandleStealthDetection();
        }
    }
    
    void HandleDetection() {
        if (strategy.exitOnDetection) {
            ExitProcess(0);
        } else {
            ModifyBehavior();
        }
    }
    
    void HandleStealthDetection() {
        // Detecção stealth - log discreto, comportamento sutil
        LogStealthDetection();
        AdjustBehaviorSlightly();
    }
    
    double CalculateLikelihoodScore() {
        double score = 0.0;
        
        // Fatores que aumentam score de sandbox
        if (context.uptime < 600) score += 0.3; // < 10 minutos
        if (context.userIdleTime > 1800) score += 0.3; // > 30 minutos idle
        if (context.memorySize < 4LL * 1024 * 1024 * 1024) score += 0.2; // < 4GB
        if (context.diskSize < 50LL * 1024 * 1024 * 1024) score += 0.2; // < 50GB
        if (!context.hasNetwork) score += 0.1; // Sem rede
        if (context.installedPrograms < 10) score += 0.1; // Poucos programas
        if (context.runningProcesses < 20) score += 0.1; // Poucos processos
        
        return min(score, 1.0);
    }
    
    bool PerformBasicChecks() {
        return !CheckLowUptime() && !CheckNoUserActivity();
    }
    
    bool PerformIntermediateChecks() {
        return !CheckLimitedResources() && !CheckSandboxFiles();
    }
    
    bool PerformAdvancedChecks() {
        return !CheckSandboxProcesses() && !CheckAutomation();
    }
    
    bool CheckSubtleIndicator() {
        // Verificação sutil
        return CheckUnusualTiming() || CheckUnusualPatterns();
    }
    
    DWORD CalculateStealthDelay() {
        // Delay baseado na estratégia
        switch (strategy.checkFrequency) {
            case LOW: return 300000; // 5 minutos
            case MEDIUM: return 60000; // 1 minuto
            case HIGH: return 10000; // 10 segundos
            default: return 60000;
        }
    }
    
    // Utility functions
    static DWORD GetUserIdleTime() {
        LASTINPUTINFO lii;
        lii.cbSize = sizeof(lii);
        GetLastInputInfo(&lii);
        return (GetTickCount() - lii.dwTime) / 1000;
    }
    
    static uint64_t GetMemorySize() {
        MEMORYSTATUSEX memStatus;
        memStatus.dwLength = sizeof(memStatus);
        GlobalMemoryStatusEx(&memStatus);
        return memStatus.ullTotalPhys;
    }
    
    static uint64_t GetDiskSize() {
        ULARGE_INTEGER freeBytes, totalBytes, freeBytesAvailable;
        GetDiskFreeSpaceExA("C:\\", &freeBytesAvailable, &totalBytes, &freeBytes);
        return totalBytes.QuadPart;
    }
    
    static bool CheckNetworkConnectivity() {
        return InternetCheckConnectionA("http://www.google.com", FLAG_ICC_FORCE_CONNECTION, 0);
    }
    
    static int GetInstalledProgramsCount() {
        // Contar programas instalados
        return 50; // Placeholder
    }
    
    static int GetRunningProcessesCount() {
        DWORD processes[1024], cbNeeded;
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            return cbNeeded / sizeof(DWORD);
        }
        return 0;
    }
    
    static bool CheckLowUptime() {
        return context.uptime < 600;
    }
    
    static bool CheckNoUserActivity() {
        return context.userIdleTime > 1800;
    }
    
    static bool CheckLimitedResources() {
        return context.memorySize < 4LL * 1024 * 1024 * 1024 ||
               context.diskSize < 50LL * 1024 * 1024 * 1024;
    }
    
    static bool CheckSandboxFiles() {
        return PathFileExistsA("C:\\sandbox\\");
    }
    
    static bool CheckSandboxProcesses() {
        return IsProcessRunning("cuckoo.exe");
    }
    
    static bool CheckAutomation() {
        return GetEnvironmentVariableA("CI", NULL, 0) > 0;
    }
    
    static bool CheckUnusualTiming() {
        // Verificar timing incomum
        return false; // Placeholder
    }
    
    static bool CheckUnusualPatterns() {
        // Verificar padrões incomuns
        return false; // Placeholder
    }
    
    static bool IsProcessRunning(const char* processName) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        
        if (Process32First(hSnapshot, &pe)) {
            do {
                if (_stricmp(pe.szExeFile, processName) == 0) {
                    CloseHandle(hSnapshot);
                    return true;
                }
            } while (Process32Next(hSnapshot, &pe));
        }
        
        CloseHandle(hSnapshot);
        return false;
    }
    
    void LogStealthDetection() { /* Log discreto */ }
    void AdjustBehaviorSlightly() { /* Ajuste sutil */ }
    void ModifyBehavior() { /* Modificação */ }
};
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Signature detection |
| 2020-2024 | ⚠️ Médio risco | Behavioral analysis |
| 2025-2026 | ⚠️ Alto risco | Advanced evasion |

---

## 🎯 Lições Aprendidas

1. **Sandboxes São Determináveis**: Ambiente de análise deixa rastros detectáveis.

2. **Comportamento é Rastreado**: Ações evasivas são monitoradas.

3. **Timing é Analisado**: Anomalias de tempo são detectadas.

4. **Adaptação é Melhor**: Detecção contextual é mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#45]]
- [[Delayed_Execution]]
- [[Conditional_Behavior]]
- [[Context_Aware_Detection]]

---

*Anti-sandbox techniques tem risco moderado. Considere delayed execution para mais stealth.*

---
📌 **Quando usar esta nota?** Sempre que precisar revisar rapidamente este conceito e conectá-lo com outras notas do seu vault.
