# 🚩 REDFLAG: The Black Book of CS2 Reverse Engineering (2026 Edition)

**English Version** | [**Versão em Português**](./README_PT.md)

[![Security Research](https://img.shields.io/badge/Domain-Security_Research-red?style=for-the-badge)]()
[![Target](https://img.shields.io/badge/Target-Counter_Strike_2-white?style=for-the-badge&logo=counter-strike)]()

### *"The most extensive technical database for CS2 Offensive Security. 500+ documented tactics covering Kernel-level evasion, hardware-backed injection (Sayo Device), and biologically-accurate movement modeling."*

---

## 📖 Overview
This repository contains the **[Documentacao_Ultimate_Cheat_2026.xlsx](./Documentacao_Ultimate_Cheat_2026.xlsx)**, a master database with 500 exploration and evasion techniques for Counter-Strike 2, focused on Windows 11 architecture and **Sayo Device** integration.

---

## 🚀 Technical Highlights

| Technique | Domain | 2026 Status | Description |
| :--- | :--- | :--- | :--- |
| **Sayo HID Injection** | Hardware | ✅ Operational | Total bypass of injection flags via physical USB bus. |
| **EPT Hooking / VTEE** | Kernel | ✅ Undetectable | Memory protection via Virtualization (Extended Page Tables). |
| **Sub-tick Alignment** | Networking | ✅ High Precision | Command synchronization with exact Engine2 timestamp. |

---

## 🛠️ How to Use
1.  **Check Online Database:** **[FULL_DATABASE_EN.md](./FULL_DATABASE_EN.md)** (Global English)
2.  **Download Spreadsheet:** [Documentacao_Ultimate_Cheat_2026.xlsx](./Documentacao_Ultimate_Cheat_2026.xlsx)
3.  **Check PT-BR Version:** **[FULL_DATABASE.md](./FULL_DATABASE.md)**

---

<p align="center">
  <b>REDFLAG © 2026</b><br>
  <i>Innovation in Security and Offensive Analysis.</i>
</p>

> **Nota:** Este material é destinado exclusivamente para fins de pesquisa em segurança da informação, análise de kernel e estudos de proteção de software.

---

## 🚀 Destaques Técnicos (Vanguarda 2026)

| Técnica | Domínio | Status 2026 | Descrição |
| :--- | :--- | :--- | :--- |
| **Sayo HID Injection** | Hardware | ✅ Operacional | Bypass total de flags de injeção via barramento USB físico. |
| **EPT Hooking / VTEE** | Kernel | ✅ Indetectável | Proteção de memória via Virtualização (Extended Page Tables). |
| **Sub-tick Alignment** | Networking | ✅ Alta Precisão | Sincronia de comandos com o timestamp exato do Engine2. |
| **Ornstein-Uhlenbeck** | Humanização | ✅ Anti-AI | Modelagem estocástica de tremor muscular para vencer o VACnet 3.0. |
| **CR3 Memory Access** | Memória | ✅ Stealth | Leitura de memória sem abertura de handles via MMU Swap. |

---

## 📊 Prévia da Documentação Master
A base de dados completa (XLSX) contém 500+ entradas organizadas com os seguintes critérios:

*   **Categorização por Risco:** De "Mínimo" a "Crítico".
*   **Análise de Defasagem:** Indicação clara de métodos que já não funcionam (ex: `SendInput`, RPM convencional).
*   **Offsets Integrados:** Referências diretas às estruturas do `client.dll` e `engine2.dll` de Fevereiro/2026.

---

## 🛠️ Como Utilizar
1.  **Consulte a Base Online:** **[FULL_DATABASE.md](./FULL_DATABASE.md)** (PT-BR) | **[FULL_DATABASE_EN.md](./FULL_DATABASE_EN.md)** (EN-US)
2.  **Baixe a Planilha:** [Documentacao_Ultimate_Cheat_2026.xlsx](./Documentacao_Ultimate_Cheat_2026.xlsx) (Versão completa com filtros e branding)
3.  **Filtre por Domínio:** Utilize as abas de filtro no Excel para focar em *Kernel Evasion*, *Humanização* ou *Networking*.
3.  **Consulte os Detalhes:** Cada técnica possui uma coluna de "Por que?", detalhando a motivação técnica e a contra-medida do Anti-Cheat.

---

## 📂 Estrutura do Projeto
*   `Documentacao_Ultimate_Cheat_2026.xlsx`: Base de dados master formatada.
*   `Documentacao_Ultimate_Cheat_2026.csv`: Versão raw para análise de dados.
*   `0.2 - cs2-dumper/output/`: Contém os arquivos JSON com os offsets dinâmicos de Fevereiro/2026.

---

## ⚡ RECOMENDAÇÃO DE VISUALIZAÇÃO
Para uma experiência completa, abra o arquivo `.xlsx` localmente. O GitHub não renderiza a formatação condicional (cores de risco e branding REDFLAG) que aplicamos para facilitar a navegação rápida.

---

<p align="center">
  <b>REDFLAG © 2026</b><br>
  <i>Inovação em Segurança e Análise Ofensiva.</i>
</p>
