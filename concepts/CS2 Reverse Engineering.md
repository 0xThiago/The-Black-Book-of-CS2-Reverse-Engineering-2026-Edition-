# 🎮 CS2 Reverse Engineering (Map of Content)

> ### *"O guia definitivo para o hacking de Counter-Strike 2 no Ring 0"*
> **Status:** 🟢 Ativo | **Última Atualização:** Fevereiro 2026

---

## 🏗️ Pilares da Arquitetura (2026)

Este vault contém o conhecimento técnico necessário para desenvolver sistemas ofensivos contra o **Source 2 Engine** e o **VAC Live**. O foco é a evasão absoluta e alta performance em Rust.

### 1. Memória & Evasão
Exploração do espaço de endereçamento do jogo sem gatilhar callbacks do kernel ou detecções de User-mode.
- [[Técnica 004 - Kernel Page Table Manipulation (CR3 Swap)]]
- [[Técnica 011 - Direct3D Hooking]]
- [[Técnica 054 - Rust Kernel Memory RW (2026 Edition)]]

### 2. Entrada (Input) & Hardware
Simulação de movimento físico indetectável utilizando microcontroladores e dispositivos USB dedicados.
- [[Técnica 002 - Hardware HID (Sayo Device)]]
- [[Técnica 013 - Sub-pixel Precise RCS]]

### 3. AI & Machine Learning
Uso de redes neurais para detecção visual (Aimbot Externo) e mimetismo comportamental para enganar o VACnet.
- [[Técnica 055 - High-Performance Rust ONNX Inference (ort)]]
- [[Técnica 008 - Curvas de Bézier + Jitter de Tremor]]

### 4. Networking & Sub-tick
Sincronização milimétrica com o novo sistema de sub-tick do CS2.
- [[Técnica 006 - Sub-tick Sample Alignment]]

---

## 🛡️ Sistemas Anti-Cheat
Notas de estudo sobre as defesas que estamos enfrentando:
- [[VAC Live Analysis]]
- [[VACnet 2026 Overview]]
- [[Driver Filter Verification]]
- [[ML_Based_Detection]]
- [[Context_Aware_Detection]]
- [[Dynamic_Behavior_Analysis]]

---

## 📚 Conceitos Avançados
Documentação técnica de conceitos referenciados:
- [[Code_Virtualization]]
- [[Metamorphic_Code_Generation]]
- [[Polymorphic_Code]]
- [[Encrypted_Memory_Management]]
- [[Memory_Obfuscation_Engine]]
- [[Secure_Memory_Allocator]]
- [[Hardware_Input_Methods]]

---

## 📖 Índice Completo de Técnicas

### Input & Simulação
- [[Técnica 001 - Windows SendInput]]
- [[Técnica 002 - Hardware HID (Sayo Device)]]

### Memória & Leitura
- [[Técnica 003 - ReadProcessMemory (RPM)]]
- [[Técnica 004 - Kernel Page Table Manipulation (CR3 Swap)]]
- [[Técnica 005 - WriteProcessMemory (WPM)]]
- [[Técnica 006 - Sub-tick Sample Alignment]]

### Injeção de Código
- [[Técnica 007 - CreateRemoteThread]]
- [[Técnica 008 - Curvas de Bézier + Jitter de Tremor]]
- [[Técnica 009 - SetWindowsHookEx]]

### Renderização & Overlay
- [[Técnica 010 - Asynchronous ESP Rendering (Vulkan)]]
- [[Técnica 011 - Direct3D Hooking]]

### Kernel & Drivers
- [[Técnica 012 - Kernel Driver]]
- [[Técnica 013 - Sub-pixel Precise RCS]]

### DLL Injection
- [[Técnica 014 - DLL Injection via APC]]
- [[Técnica 015 - Manual DLL Mapping]]
- [[Técnica 016 - Reflective DLL Injection]]

### Hooking Avançado
- [[Técnica 017 - VMT Hooking]]
- [[Técnica 018 - Input Spoofing]]
- [[Técnica 019 - Memory Scanning]]
- [[Técnica 020 - Pattern Scanning]]

### Técnicas de Suporte (Legacy & Refactored)
- [[Técnica 021 - Direct3D Hooking]]
- [[Técnica 022 - Input Spoofing]]
- [[Técnica 023 - Kernel Driver]]
- [[Técnica 024 - Memory Patching]]
- [[Técnica 025 - Reflective DLL Injection]]
- [[Técnica 026 - VMT Hooking]]
- [[Técnica 027 - Manual DLL Mapping]]
- [[Técnica 028 - Reflective DLL Injection]]
- [[Técnica 029 - APC Injection]]
- [[Técnica 030 - Early Bird APC Injection]]
- [[Técnica 031 - Thread Hijacking]]

### Evasão & Stealth
- [[Técnica 032 - Input Manipulation]]
- [[Técnica 033 - Memory Patching]]
- [[Técnica 034 - Direct3D Hooking]]
- [[Técnica 035 - OpenGL Hooking]]
- [[Técnica 036 - Vulkan Hooking]]
- [[Técnica 037 - Kernel Mode Hooking]]
- [[Técnica 038 - Process Hollowing]]
- [[Técnica 039 - Anti-Debugging Techniques]]
- [[Técnica 040 - Code Packing and Compression]]
- [[Técnica 041 - Memory Dumping Prevention]]
- [[Técnica 042 - String Encryption and Obfuscation]]
- [[Técnica 043 - Control Flow Obfuscation]]

### Análise de Ambiente
- [[Técnica 044 - Anti-VM Techniques]]
- [[Técnica 045 - Anti-Sandbox Techniques]]
- [[Técnica 046 - Anti-Emulator Techniques]]
- [[Técnica 047 - Anti-Debugging Techniques]]
- [[Técnica 048 - Anti-Memory Dumping Techniques]]
- [[Técnica 049 - Anti-Reverse Engineering Techniques]]

### Rust & 2026 🟢
- [[Técnica 054 - Rust Kernel Memory RW (2026 Edition)]]
- [[Técnica 055 - High-Performance Rust ONNX Inference (ort)]]

---

## 🗃️ Navegação Rápida
- [[DATABASE]]: Lista completa de técnicas curadas.
- [[README]]: Visão geral do projeto e estatísticas.
- [[PROMPT_TEMPLATE_OBSIDIAN_2026]]: Template oficial para criação de novas notas.

---
<p align="center">REDFLAG © 2026 - Hack the Game, Hack the Learning</p>
