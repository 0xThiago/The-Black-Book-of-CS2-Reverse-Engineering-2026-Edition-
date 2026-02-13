# Técnica 042: String Encryption and Obfuscation

> **Status:** ⚠️ Risco Moderado  
> **Risco de Detecção:** 🟡 Médio  
> **Domínio:** Anti-Analysis  
> **Data da Análise:** 12/02/2026

---

## 📋 Visão Geral

**String Encryption and Obfuscation** encripta e ofusca strings no código executável, dificultando análise estática e debugging ao esconder dados sensíveis como nomes de APIs, mensagens de erro e configurações.

---

## 🔍 Análise Técnica Detalhada

### Como Funciona

```cpp
// ⚠️ CÓDIGO DE RISCO MODERADO - USE COM CAUTELA
class StringEncryptor {
private:
    std::vector<ENCRYPTED_STRING> encryptedStrings;
    ENCRYPTION_ALGORITHM algorithm;
    std::string masterKey;
    
public:
    StringEncryptor() {
        algorithm = ALGORITHM_AES256;
        masterKey = GenerateMasterKey();
    }
    
    void EncryptAllStrings() {
        // Encontrar todas as strings no executável
        FindAllStrings();
        
        // Encriptar strings encontradas
        for (ENCRYPTED_STRING& str : encryptedStrings) {
            EncryptString(str);
        }
        
        // Substituir strings no código
        ReplaceStringsInCode();
        
        // Adicionar código de decriptação
        AddDecryptionStub();
    }
    
    void FindAllStrings() {
        PVOID imageBase = GetModuleHandle(NULL);
        
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)imageBase;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)imageBase + pDosHeader->e_lfanew);
        
        // Percorrer seções procurando strings
        PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
        for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)pSection[i].Name, ".rdata") == 0 || 
                strcmp((char*)pSection[i].Name, ".data") == 0) {
                
                ScanSectionForStrings((PBYTE)imageBase + pSection[i].VirtualAddress, 
                                    pSection[i].SizeOfRawData);
            }
        }
    }
    
    void ScanSectionForStrings(PBYTE sectionData, DWORD sectionSize) {
        for (DWORD i = 0; i < sectionSize - 4; i++) {
            if (IsValidString(&sectionData[i])) {
                ENCRYPTED_STRING str;
                str.offset = i;
                str.originalString = (char*)&sectionData[i];
                str.length = strlen(str.originalString);
                
                encryptedStrings.push_back(str);
            }
        }
    }
    
    bool IsValidString(PBYTE data) {
        // Verificar se é uma string ASCII válida
        if (!isprint(*data) || *data == 0) return false;
        
        int len = 0;
        while (len < 256 && data[len] != 0) {
            if (!isprint(data[len])) return false;
            len++;
        }
        
        // Strings muito curtas ou muito longas são ignoradas
        return len >= 4 && len <= 100;
    }
    
    void EncryptString(ENCRYPTED_STRING& str) {
        // Gerar chave única para esta string
        str.key = GenerateStringKey(str.originalString);
        
        // Encriptar string
        std::vector<BYTE> data(str.originalString.begin(), str.originalString.end());
        EncryptData(data, str.key);
        
        str.encryptedData = data;
    }
    
    void ReplaceStringsInCode() {
        PVOID imageBase = GetModuleHandle(NULL);
        
        for (const ENCRYPTED_STRING& str : encryptedStrings) {
            PBYTE targetAddress = (PBYTE)imageBase + str.offset;
            
            // Substituir string original pelos dados encriptados
            memcpy(targetAddress, str.encryptedData.data(), str.encryptedData.size());
            
            // Adicionar null terminator se necessário
            targetAddress[str.encryptedData.size()] = 0;
        }
    }
    
    void AddDecryptionStub() {
        // Adicionar função de decriptação
        // Esta função será chamada quando a string for necessária
    }
    
    std::string GenerateMasterKey() {
        // Gerar chave mestra de 32 bytes
        std::string key;
        for (int i = 0; i < 32; i++) {
            key += (char)(rand() % 256);
        }
        return key;
    }
    
    std::string GenerateStringKey(const std::string& str) {
        // Gerar chave baseada no hash da string
        std::string key = masterKey;
        
        // XOR com hash da string
        uint32_t hash = CalculateStringHash(str);
        for (size_t i = 0; i < key.size(); i++) {
            key[i] ^= ((hash >> (i % 4) * 8) & 0xFF);
        }
        
        return key;
    }
    
    uint32_t CalculateStringHash(const std::string& str) {
        // FNV-1a hash
        uint32_t hash = 2166136261u;
        for (char c : str) {
            hash ^= (uint8_t)c;
            hash *= 16777619u;
        }
        return hash;
    }
    
    void EncryptData(std::vector<BYTE>& data, const std::string& key) {
        // Encriptação simples XOR para exemplo
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= key[i % key.size()];
        }
    }
    
    // Função de decriptação em runtime
    static std::string DecryptString(const BYTE* encryptedData, size_t length, const std::string& key) {
        std::vector<BYTE> data(encryptedData, encryptedData + length);
        
        // Decriptar
        for (size_t i = 0; i < data.size(); i++) {
            data[i] ^= key[i % key.size()];
        }
        
        return std::string(data.begin(), data.end());
    }
};
```

### Advanced String Obfuscation

```cpp
// Técnicas avançadas de ofuscação de strings
class AdvancedStringObfuscator : public StringEncryptor {
private:
    std::vector<OBFUSCATION_TECHNIQUE> techniques;
    POLYMORPHIC_ENGINE polyEngine;
    
public:
    AdvancedStringObfuscator() {
        InitializeTechniques();
        InitializePolymorphicEngine();
    }
    
    void InitializeTechniques() {
        techniques.push_back({TECHNIQUE_STACK_STRINGS, "Stack-based string construction"});
        techniques.push_back({TECHNIQUE_STRING_SPLITTING, "Split strings across multiple locations"});
        techniques.push_back({TECHNIQUE_API_HASHING, "API name hashing"});
        techniques.push_back({TECHNIQUE_DYNAMIC_DECRYPTION, "Runtime decryption with polymorphism"});
    }
    
    void InitializePolymorphicEngine() {
        // Inicializar engine polimórfico para geração de código de decriptação
    }
    
    void ApplyAdvancedObfuscation() {
        // Aplicar técnicas avançadas
        for (const OBFUSCATION_TECHNIQUE& tech : techniques) {
            ApplyTechnique(tech);
        }
        
        // Gerar código polimórfico de decriptação
        GeneratePolymorphicDecryption();
    }
    
    void ApplyTechnique(const OBFUSCATION_TECHNIQUE& tech) {
        switch (tech.type) {
            case TECHNIQUE_STACK_STRINGS:
                ApplyStackStrings();
                break;
            case TECHNIQUE_STRING_SPLITTING:
                ApplyStringSplitting();
                break;
            case TECHNIQUE_API_HASHING:
                ApplyAPIHashing();
                break;
            case TECHNIQUE_DYNAMIC_DECRYPTION:
                ApplyDynamicDecryption();
                break;
        }
    }
    
    void ApplyStackStrings() {
        // Converter strings para construção em stack
        for (ENCRYPTED_STRING& str : encryptedStrings) {
            ConvertToStackString(str);
        }
    }
    
    void ConvertToStackString(ENCRYPTED_STRING& str) {
        // Transformar string em código que a constrói na stack
        // Ex: "Hello" -> push 'o', push 'l', push 'l', push 'e', push 'H'
        
        str.stackConstruction = true;
        str.stackCode = GenerateStackConstructionCode(str.originalString);
    }
    
    std::vector<BYTE> GenerateStackConstructionCode(const std::string& str) {
        std::vector<BYTE> code;
        
        // Código assembly para construir string na stack
        for (int i = str.length() - 1; i >= 0; i--) {
            // PUSH imm8/imm32
            code.push_back(0x6A); // PUSH imm8
            code.push_back((BYTE)str[i]);
        }
        
        return code;
    }
    
    void ApplyStringSplitting() {
        // Dividir strings em múltiplas partes
        for (ENCRYPTED_STRING& str : encryptedStrings) {
            if (str.originalString.length() > 10) {
                SplitString(str);
            }
        }
    }
    
    void SplitString(ENCRYPTED_STRING& str) {
        // Dividir string em 2-3 partes
        size_t len = str.originalString.length();
        size_t part1Len = len / 3;
        size_t part2Len = len / 3;
        size_t part3Len = len - part1Len - part2Len;
        
        str.splitParts.push_back(str.originalString.substr(0, part1Len));
        str.splitParts.push_back(str.originalString.substr(part1Len, part2Len));
        str.splitParts.push_back(str.originalString.substr(part1Len + part2Len, part3Len));
        
        str.isSplit = true;
    }
    
    void ApplyAPIHashing() {
        // Converter nomes de APIs para hashes
        FindAPIReferences();
        
        for (API_REFERENCE& api : apiReferences) {
            ConvertAPIToHash(api);
        }
    }
    
    void FindAPIReferences() {
        // Encontrar referências a APIs no código
        // Usar análise estática ou dinâmica
    }
    
    void ConvertAPIToHash(API_REFERENCE& api) {
        // Calcular hash do nome da API
        api.hash = CalculateAPIHash(api.name);
        api.useHash = true;
    }
    
    uint32_t CalculateAPIHash(const std::string& apiName) {
        // Hash personalizado para APIs
        uint32_t hash = 0;
        for (char c : apiName) {
            hash = ((hash << 5) + hash) + tolower(c); // DJB2-like
        }
        return hash;
    }
    
    void ApplyDynamicDecryption() {
        // Implementar decriptação dinâmica com polimorfismo
        for (ENCRYPTED_STRING& str : encryptedStrings) {
            str.dynamicDecryption = true;
            str.decryptionRoutine = GeneratePolymorphicDecryptionRoutine();
        }
    }
    
    std::vector<BYTE> GeneratePolymorphicDecryptionRoutine() {
        // Gerar rotina de decriptação polimórfica
        std::vector<BYTE> routine;
        
        // Adicionar junk code
        AddJunkInstructions(routine);
        
        // Adicionar lógica de decriptação
        AddDecryptionLogic(routine);
        
        // Adicionar mais junk code
        AddJunkInstructions(routine);
        
        return routine;
    }
    
    void AddJunkInstructions(std::vector<BYTE>& code) {
        // Adicionar instruções junk
        const BYTE junkInstructions[][2] = {
            {0x90, 0x90}, // NOP NOP
            {0x87, 0xC0}, // XCHG EAX, EAX
            {0x8B, 0xC0}, // MOV EAX, EAX
        };
        
        int junkCount = rand() % 5 + 1;
        for (int i = 0; i < junkCount; i++) {
            int idx = rand() % (sizeof(junkInstructions) / sizeof(junkInstructions[0]));
            code.push_back(junkInstructions[idx][0]);
            if (junkInstructions[idx][1] != 0) {
                code.push_back(junkInstructions[idx][1]);
            }
        }
    }
    
    void AddDecryptionLogic(std::vector<BYTE>& code) {
        // Adicionar lógica XOR de decriptação
        // MOV ECX, length
        code.push_back(0xB9); // MOV ECX, imm32
        // ... adicionar tamanho ...
        
        // Loop de decriptação
        // XOR [EDI + ECX], AL
        code.push_back(0x30);
        code.push_back(0x04);
        code.push_back(0x0F);
        
        // LOOP
        code.push_back(0xE2);
        code.push_back(0xFC);
    }
    
    void GeneratePolymorphicDecryption() {
        // Gerar código de decriptação polimórfico
        polyEngine.GenerateDecryptionCode();
    }
    
    // Runtime string access
    static std::string GetDecryptedString(const ENCRYPTED_STRING& str) {
        if (str.stackConstruction) {
            return ConstructStringFromStack(str.stackCode);
        }
        
        if (str.isSplit) {
            return ReconstructSplitString(str.splitParts);
        }
        
        if (str.dynamicDecryption) {
            return DecryptWithPolymorphicRoutine(str);
        }
        
        // Decriptação padrão
        return DecryptString(str.encryptedData.data(), str.encryptedData.size(), str.key);
    }
    
    static std::string ConstructStringFromStack(const std::vector<BYTE>& stackCode) {
        // Executar código para construir string na stack
        // Usar abordagem mais segura: simular execução
        
        std::string result;
        for (size_t i = 0; i < stackCode.size(); i += 2) {
            if (stackCode[i] == 0x6A) { // PUSH imm8
                result = (char)stackCode[i + 1] + result;
            }
        }
        
        return result;
    }
    
    static std::string ReconstructSplitString(const std::vector<std::string>& parts) {
        std::string result;
        for (const std::string& part : parts) {
            result += part;
        }
        return result;
    }
    
    static std::string DecryptWithPolymorphicRoutine(const ENCRYPTED_STRING& str) {
        // Executar rotina polimórfica
        return polyEngine.ExecuteDecryption(str.encryptedData, str.key);
    }
    
    // API resolution by hash
    static PVOID ResolveAPIByHash(uint32_t hash) {
        // Resolver API por hash
        HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
        HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
        
        // Lista de APIs comuns
        const std::vector<std::pair<std::string, FARPROC>> apis = {
            {"LoadLibraryA", GetProcAddress(hKernel32, "LoadLibraryA")},
            {"GetProcAddress", GetProcAddress(hKernel32, "GetProcAddress")},
            {"VirtualAlloc", GetProcAddress(hKernel32, "VirtualAlloc")},
            {"VirtualFree", GetProcAddress(hKernel32, "VirtualFree")},
            // ... mais APIs ...
        };
        
        for (const auto& api : apis) {
            if (CalculateAPIHash(api.first) == hash) {
                return api.second;
            }
        }
        
        return nullptr;
    }
};
```

### Por que é Detectado

> [!WARNING]
> **String encryption deixa rastros através de padrões de acesso e anomalias na memória**

#### 1. String Access Pattern Analysis
```cpp
// Análise de padrões de acesso a strings
class StringAccessAnalyzer {
private:
    std::map<PVOID, STRING_ACCESS_INFO> stringAccesses;
    
public:
    void MonitorStringAccess() {
        // Hook funções de acesso a strings
        HookStringFunctions();
        
        // Monitorar padrões de acesso
        StartAccessMonitoring();
    }
    
    void HookStringFunctions() {
        // Hook strlen, strcpy, strcmp, etc.
        HMODULE hMsvcrt = GetModuleHandleA("msvcrt.dll");
        if (hMsvcrt) {
            PVOID pStrlen = GetProcAddress(hMsvcrt, "strlen");
            if (pStrlen) {
                MH_CreateHook(pStrlen, &HkStrlen, &oStrlen);
                MH_EnableHook(pStrlen);
            }
        }
    }
    
    void StartAccessMonitoring() {
        std::thread([this]() {
            while (true) {
                AnalyzeAccessPatterns();
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        }).detach();
    }
    
    void AnalyzeAccessPatterns() {
        for (const auto& pair : stringAccesses) {
            const STRING_ACCESS_INFO& info = pair.second;
            
            // Verificar padrões suspeitos
            if (HasSuspiciousAccessPattern(info)) {
                ReportSuspiciousStringAccess(info);
            }
        }
    }
    
    bool HasSuspiciousAccessPattern(const STRING_ACCESS_INFO& info) {
        // Acesso frequente a strings encriptadas
        if (info.accessCount > 100) {
            return true;
        }
        
        // Acesso a strings de alta entropia
        if (info.entropy > 7.0) {
            return true;
        }
        
        // Acesso sequencial a múltiplas strings
        if (info.sequentialAccesses > 10) {
            return true;
        }
        
        return false;
    }
    
    void ReportSuspiciousStringAccess(const STRING_ACCESS_INFO& info) {
        std::cout << "Suspicious string access pattern detected" << std::endl;
    }
    
    // Hook implementations
    static size_t WINAPI HkStrlen(const char* str) {
        // Monitorar acesso a string
        RecordStringAccess((PVOID)str);
        
        return oStrlen(str);
    }
    
    static void RecordStringAccess(PVOID address) {
        if (stringAccesses.find(address) == stringAccesses.end()) {
            STRING_ACCESS_INFO info;
            info.address = address;
            info.firstAccess = GetTickCount();
            info.entropy = CalculateStringEntropy(address);
            stringAccesses[address] = info;
        }
        
        stringAccesses[address].accessCount++;
        stringAccesses[address].lastAccess = GetTickCount();
        
        // Verificar acesso sequencial
        static PVOID lastAccessed = nullptr;
        if (lastAccessed && (uintptr_t)address - (uintptr_t)lastAccessed < 0x100) {
            stringAccesses[address].sequentialAccesses++;
        }
        lastAccessed = address;
    }
    
    static double CalculateStringEntropy(PVOID address) {
        const char* str = (const char*)address;
        size_t len = strlen(str);
        
        if (len == 0) return 0.0;
        
        std::map<char, int> frequency;
        for (size_t i = 0; i < len; i++) {
            frequency[str[i]]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / len;
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    static decltype(&strlen) oStrlen;
};
```

#### 2. Memory Entropy Analysis
```cpp
// Análise de entropia de memória
class MemoryEntropyAnalyzer {
private:
    std::vector<MEMORY_REGION> analyzedRegions;
    
public:
    void AnalyzeMemoryEntropy(DWORD processId) {
        // Enumerar regiões de memória
        EnumerateMemoryRegions(processId);
        
        // Calcular entropia de cada região
        CalculateRegionsEntropy(processId);
        
        // Identificar regiões suspeitas
        IdentifySuspiciousRegions();
    }
    
    void EnumerateMemoryRegions(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return;
        
        PVOID address = NULL;
        MEMORY_BASIC_INFORMATION mbi;
        
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && 
                (mbi.Protect & PAGE_READWRITE) && 
                mbi.Type == MEM_PRIVATE) {
                
                MEMORY_REGION region;
                region.address = address;
                region.size = mbi.RegionSize;
                analyzedRegions.push_back(region);
            }
            
            address = (PVOID)((uintptr_t)address + mbi.RegionSize);
        }
        
        CloseHandle(hProcess);
    }
    
    void CalculateRegionsEntropy(DWORD processId) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
        if (!hProcess) return;
        
        for (MEMORY_REGION& region : analyzedRegions) {
            region.entropy = CalculateRegionEntropy(hProcess, region.address, region.size);
        }
        
        CloseHandle(hProcess);
    }
    
    double CalculateRegionEntropy(HANDLE hProcess, PVOID address, SIZE_T size) {
        std::vector<BYTE> buffer(size);
        SIZE_T bytesRead;
        
        if (ReadProcessMemory(hProcess, address, buffer.data(), size, &bytesRead)) {
            return CalculateEntropy(buffer);
        }
        
        return 0.0;
    }
    
    double CalculateEntropy(const std::vector<BYTE>& data) {
        std::map<BYTE, int> frequency;
        for (BYTE b : data) {
            frequency[b]++;
        }
        
        double entropy = 0.0;
        for (const auto& pair : frequency) {
            double p = (double)pair.second / data.size();
            entropy -= p * log2(p);
        }
        
        return entropy;
    }
    
    void IdentifySuspiciousRegions() {
        for (const MEMORY_REGION& region : analyzedRegions) {
            if (region.entropy > 7.5) {
                ReportHighEntropyRegion(region);
            }
            
            // Verificar se contém strings encriptadas
            if (MayContainEncryptedStrings(region)) {
                ReportPotentialEncryptedStrings(region);
            }
        }
    }
    
    bool MayContainEncryptedStrings(const MEMORY_REGION& region) {
        // Verificar se região pode conter strings encriptadas
        // Procurar por padrões de acesso ou características
        
        return region.entropy > 6.0 && region.size > 1024;
    }
    
    void ReportHighEntropyRegion(const MEMORY_REGION& region) {
        std::cout << "High entropy memory region: " << region.address 
                  << " (entropy: " << region.entropy << ")" << std::endl;
    }
    
    void ReportPotentialEncryptedStrings(const MEMORY_REGION& region) {
        std::cout << "Potential encrypted strings in region: " << region.address << std::endl;
    }
};
```

#### 3. Dynamic Analysis Detection
```cpp
// Detecção por análise dinâmica
class DynamicAnalysisDetector {
private:
    std::vector<DECRYPTION_PATTERN> decryptionPatterns;
    
public:
    void MonitorDynamicDecryption() {
        // Monitorar decriptação de strings em runtime
        InstallDecryptionHooks();
        
        // Registrar padrões de decriptação
        RegisterDecryptionPatterns();
        
        // Detectar decriptação suspeita
        StartDecryptionMonitoring();
    }
    
    void InstallDecryptionHooks() {
        // Hook funções criptográficas
        HookCryptographicAPIs();
    }
    
    void HookCryptographicAPIs() {
        // Hook CryptDecrypt, etc.
        HMODULE hAdvapi32 = LoadLibraryA("advapi32.dll");
        if (hAdvapi32) {
            PVOID pCryptDecrypt = GetProcAddress(hAdvapi32, "CryptDecrypt");
            if (pCryptDecrypt) {
                MH_CreateHook(pCryptDecrypt, &HkCryptDecrypt, &oCryptDecrypt);
                MH_EnableHook(pCryptDecrypt);
            }
        }
    }
    
    void RegisterDecryptionPatterns() {
        // Padrões comuns de decriptação
        decryptionPatterns.push_back({PATTERN_XOR_LOOP, "XOR decryption loop"});
        decryptionPatterns.push_back({PATTERN_AES_DECRYPT, "AES decryption"});
        decryptionPatterns.push_back({PATTERN_STACK_CONSTRUCTION, "Stack string construction"});
    }
    
    void StartDecryptionMonitoring() {
        std::thread([this]() {
            while (true) {
                DetectDecryptionActivity();
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }).detach();
    }
    
    void DetectDecryptionActivity() {
        // Detectar atividade de decriptação
        if (HasRecentDecryption()) {
            AnalyzeDecryptionPattern();
        }
    }
    
    bool HasRecentDecryption() {
        // Verificar se houve decriptação recente
        return false; // Placeholder
    }
    
    void AnalyzeDecryptionPattern() {
        // Analisar padrão de decriptação
        for (const DECRYPTION_PATTERN& pattern : decryptionPatterns) {
            if (MatchesPattern(pattern)) {
                ReportDecryptionPattern(pattern);
            }
        }
    }
    
    bool MatchesPattern(const DECRYPTION_PATTERN& pattern) {
        // Verificar se atividade atual combina com padrão
        return false; // Placeholder
    }
    
    void ReportDecryptionPattern(const DECRYPTION_PATTERN& pattern) {
        std::cout << "Decryption pattern detected: " << pattern.description << std::endl;
    }
    
    // Hook implementations
    static BOOL WINAPI HkCryptDecrypt(HCRYPTKEY hKey, HCRYPTHASH hHash, BOOL Final, 
                                    DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen) {
        // Monitorar decriptação
        RecordDecryptionActivity(pbData, *pdwDataLen);
        
        return oCryptDecrypt(hKey, hHash, Final, dwFlags, pbData, pdwDataLen);
    }
    
    static void RecordDecryptionActivity(BYTE* data, DWORD length) {
        // Registrar atividade de decriptação
        // Verificar se parece com string
        if (IsLikelyString(data, length)) {
            ReportStringDecryption(data, length);
        }
    }
    
    static bool IsLikelyString(BYTE* data, DWORD length) {
        if (length < 4 || length > 256) return false;
        
        int printable = 0;
        for (DWORD i = 0; i < length && data[i] != 0; i++) {
            if (isprint(data[i])) printable++;
        }
        
        return (double)printable / length > 0.8; // 80% printable
    }
    
    static void ReportStringDecryption(BYTE* data, DWORD length) {
        std::string decryptedString((char*)data, length);
        std::cout << "String decryption detected: " << decryptedString << std::endl;
    }
    
    static decltype(&CryptDecrypt) oCryptDecrypt;
};
```

---

## 📊 Detecção por Anti-Cheat

| Sistema | Método de Detecção | Tempo | Precisão |
|---------|-------------------|-------|----------|
| VAC | Memory entropy analysis | < 30s | 85% |
| VAC Live | Dynamic decryption monitoring | Imediato | 80% |
| BattlEye | String access pattern analysis | < 1 min | 90% |
| Faceit AC | Behavioral analysis | < 30s | 75% |

---

## 🔄 Alternativas Seguras

### 1. Compile-Time String Obfuscation
```cpp
// ✅ Ofuscação em tempo de compilação
class CompileTimeObfuscator {
public:
    // Usar templates para ofuscar strings em compile-time
    template <char... Chars>
    struct ObfuscatedString {
        static constexpr char value[sizeof...(Chars) + 1] = {Chars..., '\0'};
        
        static const char* Get() {
            return value;
        }
    };
    
    // Macro para criar strings ofuscadas
    #define OBFUSCATED_STRING(str) \
        []() -> const char* { \
            constexpr auto obfuscated = ObfuscateString<str>(); \
            return obfuscated.Get(); \
        }()
    
    template <size_t N>
    constexpr auto ObfuscateString(const char (&str)[N]) {
        // Ofuscar string em compile-time
        return CreateObfuscatedString<N>(str, std::make_index_sequence<N - 1>{});
    }
    
    template <size_t N, size_t... Indices>
    constexpr auto CreateObfuscatedString(const char (&str)[N], std::index_sequence<Indices...>) {
        // Criar string ofuscada com XOR em compile-time
        constexpr char key = 0x42;
        return ObfuscatedString<(str[Indices] ^ key)...>{};
    }
};

// Uso:
// const char* apiName = OBFUSCATED_STRING("MessageBoxA");
```

### 2. Runtime Polymorphic Decryption
```cpp
// ✅ Decriptação polimórfica em runtime
class PolymorphicDecryptor {
private:
    std::vector<DECRYPTION_ROUTINE> routines;
    
public:
    PolymorphicDecryptor() {
        GenerateDecryptionRoutines();
    }
    
    void GenerateDecryptionRoutines() {
        // Gerar múltiplas rotinas de decriptação
        for (int i = 0; i < 10; i++) {
            routines.push_back(GenerateRoutine());
        }
    }
    
    DECRYPTION_ROUTINE GenerateRoutine() {
        DECRYPTION_ROUTINE routine;
        
        // Gerar código assembly polimórfico
        routine.code = GeneratePolymorphicCode();
        routine.key = GenerateRandomKey();
        
        return routine;
    }
    
    std::vector<BYTE> GeneratePolymorphicCode() {
        std::vector<BYTE> code;
        
        // Adicionar prólogo variável
        AddRandomPrologue(code);
        
        // Adicionar lógica de decriptação
        AddDecryptionLogic(code);
        
        // Adicionar epílogo variável
        AddRandomEpilogue(code);
        
        return code;
    }
    
    void AddRandomPrologue(std::vector<BYTE>& code) {
        // PUSH EBP; MOV EBP, ESP ou variações
        const BYTE prologues[][4] = {
            {0x55, 0x8B, 0xEC, 0x00}, // PUSH EBP; MOV EBP, ESP
            {0x53, 0x55, 0x8B, 0xEC}, // PUSH EBX; PUSH EBP; MOV EBP, ESP
            {0x57, 0x56, 0x55, 0x8B}  // PUSH EDI; PUSH ESI; PUSH EBP; MOV...
        };
        
        int idx = rand() % (sizeof(prologues) / sizeof(prologues[0]));
        for (int i = 0; prologues[idx][i] != 0; i++) {
            code.push_back(prologues[idx][i]);
        }
    }
    
    void AddDecryptionLogic(std::vector<BYTE>& code) {
        // Lógica XOR com variações
        // MOV ECX, length; MOV AL, key; XOR [EDI + ECX], AL; LOOP
        code.push_back(0xB9); // MOV ECX, ...
        // ... adicionar tamanho dinamicamente ...
        
        code.push_back(0xB0); // MOV AL, ...
        // ... adicionar chave dinamicamente ...
        
        code.push_back(0x30); // XOR [EDI + ECX], AL
        code.push_back(0x04);
        code.push_back(0x0F);
        
        code.push_back(0xE2); // LOOP
        code.push_back(0xFC);
    }
    
    void AddRandomEpilogue(std::vector<BYTE>& code) {
        // MOV ESP, EBP; POP EBP; RET ou variações
        const BYTE epilogues[][4] = {
            {0x8B, 0xE5, 0x5D, 0xC3}, // MOV ESP, EBP; POP EBP; RET
            {0x5D, 0xC2, 0x00, 0x00}, // POP EBP; RET 0
            {0x8B, 0xE5, 0x5F, 0x5E}  // MOV ESP, EBP; POP EDI; POP ESI
        };
        
        int idx = rand() % (sizeof(epilogues) / sizeof(epilogues[0]));
        for (int i = 0; epilogues[idx][i] != 0; i++) {
            code.push_back(epilogues[idx][i]);
        }
    }
    
    std::string GenerateRandomKey() {
        std::string key;
        for (int i = 0; i < 32; i++) {
            key += (char)(rand() % 256);
        }
        return key;
    }
    
    std::string DecryptString(const std::string& encrypted, int routineIndex) {
        if (routineIndex >= routines.size()) return "";
        
        const DECRYPTION_ROUTINE& routine = routines[routineIndex];
        
        // Executar rotina polimórfica
        return ExecutePolymorphicDecryption(encrypted, routine);
    }
    
    std::string ExecutePolymorphicDecryption(const std::string& encrypted, const DECRYPTION_ROUTINE& routine) {
        // Alocar memória executável
        PVOID pCode = VirtualAlloc(NULL, routine.code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        memcpy(pCode, routine.code.data(), routine.code.size());
        
        // Executar decriptação
        typedef void (*DecryptFunc)(char*, size_t, char);
        DecryptFunc decrypt = (DecryptFunc)pCode;
        
        std::string result = encrypted;
        decrypt(&result[0], result.size(), routine.key[0]);
        
        VirtualFree(pCode, 0, MEM_RELEASE);
        
        return result;
    }
};
```

### 3. API Hashing with Runtime Resolution
```cpp
// ✅ Hashing de APIs com resolução em runtime
class APIResolver {
private:
    std::map<uint32_t, PVOID> resolvedAPIs;
    
public:
    PVOID ResolveAPI(uint32_t hash) {
        // Verificar cache
        if (resolvedAPIs.find(hash) != resolvedAPIs.end()) {
            return resolvedAPIs[hash];
        }
        
        // Resolver API
        PVOID pAPI = FindAPIByHash(hash);
        if (pAPI) {
            resolvedAPIs[hash] = pAPI;
        }
        
        return pAPI;
    }
    
    PVOID FindAPIByHash(uint32_t hash) {
        // Módulos comuns
        const char* modules[] = {
            "kernel32.dll", "user32.dll", "ntdll.dll", 
            "advapi32.dll", "ws2_32.dll", "ole32.dll"
        };
        
        for (const char* moduleName : modules) {
            HMODULE hModule = GetModuleHandleA(moduleName);
            if (!hModule) continue;
            
            PVOID pAPI = FindAPIInModule(hModule, hash);
            if (pAPI) return pAPI;
        }
        
        return nullptr;
    }
    
    PVOID FindAPIInModule(HMODULE hModule, uint32_t hash) {
        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hModule + pDosHeader->e_lfanew);
        PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)
            ((PBYTE)hModule + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
        
        DWORD* pNames = (DWORD*)((PBYTE)hModule + pExportDir->AddressOfNames);
        WORD* pOrdinals = (WORD*)((PBYTE)hModule + pExportDir->AddressOfNameOrdinals);
        DWORD* pFunctions = (DWORD*)((PBYTE)hModule + pExportDir->AddressOfFunctions);
        
        for (DWORD i = 0; i < pExportDir->NumberOfNames; i++) {
            const char* apiName = (const char*)((PBYTE)hModule + pNames[i]);
            uint32_t apiHash = CalculateAPIHash(apiName);
            
            if (apiHash == hash) {
                return (PVOID)((PBYTE)hModule + pFunctions[pOrdinals[i]]);
            }
        }
        
        return nullptr;
    }
    
    uint32_t CalculateAPIHash(const char* apiName) {
        // Algoritmo de hash personalizado
        uint32_t hash = 0;
        while (*apiName) {
            hash = ((hash << 5) + hash) + tolower(*apiName);
            apiName++;
        }
        return hash;
    }
};

// Uso:
// APIResolver resolver;
// typedef decltype(&MessageBoxA) MessageBoxFunc;
// MessageBoxFunc pMessageBox = (MessageBoxFunc)resolver.ResolveAPI(0x12345678); // Hash de "MessageBoxA"
```

---

## 📈 Evolução Histórica

| Era | Status | Detecção |
|-----|--------|----------|
| 2010s | ✅ Funcional | Nenhuma |
| 2015-2020 | ⚠️ Risco | Static analysis |
| 2020-2024 | ⚠️ Médio risco | Dynamic analysis |
| 2025-2026 | ⚠️ Alto risco | Pattern recognition |

---

## 🎯 Lições Aprendidas

1. **Strings São Assinaturas**: Strings revelam funcionalidade do código.

2. **Acesso é Rastreado**: Padrões de acesso a strings são monitorados.

3. **Entropia é Analisada**: Memória encriptada tem entropia alta.

4. **Compile-Time é Melhor**: Ofuscação em tempo de compilação é mais stealth.

---

## 🔗 Referências

- [[FULL_DATABASE_v2#42]]
- [[Compile_Time_Obfuscation]]
- [[API_Hashing]]
- [[Polymorphic_Code]]

---

*String encryption tem risco moderado. Considere compile-time obfuscation para mais stealth.*