# 🔧 Hardware Input Methods

📅 Criado em: 2026-02-15
🔗 Tags: #conceito #hardware #input #hid

## 📌 Definição

**Hardware Input Methods** referem-se a técnicas de injeção de input que utilizam dispositivos físicos (microcontroladores, placas USB, DMA devices) ao invés de chamadas de software como `SendInput()` ou `mouse_event()`.

## 🔗 Relação com outros conceitos
- [[CS2 Reverse Engineering]]
- [[VAC Live Analysis]]
- [[DATABASE]]
- [[Técnica 002 - Hardware HID (Sayo Device)]]
- [[Técnica 001 - Windows SendInput]]

## 📚 Por que Hardware?

### Problema com Software Input
```cpp
// ❌ VAC Live detecta instantaneamente
INPUT input = {0};
input.type = INPUT_MOUSE;
input.mi.dwFlags = MOUSEEVENTF_MOVE;
// Flag LLMHF_INJECTED será setada pelo kernel
SendInput(1, &input, sizeof(INPUT));
```

### Solução: Device Físico
```
[Arduino/STM32] → [USB HID] → [Windows] → [CS2]
      ↑                              ↓
Comandos via Serial          Input "legítimo"
```

## 🛠️ Implementação: Arduino Leonardo (ATmega32U4)

### Hardware
- **Arduino Leonardo** ou **Pro Micro** (chip com USB HID nativo)
- Custo: ~$5-10 USD
- Interface: Serial UART (9600 baud)

### Firmware (sketch.ino)
```cpp
#include <Mouse.h>

void setup() {
  Serial.begin(9600);
  Mouse.begin();
}

void loop() {
  if (Serial.available() >= 3) {
    char cmd = Serial.read();
    int8_t x = Serial.read();
    int8_t y = Serial.read();
    
    if (cmd == 'M') { // Move
      Mouse.move(x, y, 0);
    } else if (cmd == 'C') { // Click
      Mouse.click();
    }
  }
}
```

### Driver Host (Rust)
```rust
use serialport::SerialPort;

pub struct HardwareMouse {
    port: Box<dyn SerialPort>,
}

impl HardwareMouse {
    pub fn new(port_name: &str) -> Result<Self, Error> {
        let port = serialport::new(port_name, 9600)
            .timeout(Duration::from_millis(10))
            .open()?;
        Ok(Self { port })
    }
    
    /// Move mouse via Arduino
    pub fn move_relative(&mut self, dx: i8, dy: i8) -> Result<(), Error> {
        self.port.write_all(&[b'M', dx as u8, dy as u8])?;
        Ok(())
    }
    
    /// Click via Arduino
    pub fn click(&mut self) -> Result<(), Error> {
        self.port.write_all(&[b'C', 0, 0])?;
        Ok(())
    }
}
```

## 🎯 Vantagens vs Software

| Aspecto | Software Input | Hardware Input |
|---------|---------------|----------------|
| **Detecção VAC** | ❌ Instantânea | ✅ Impossível |
| **LLMHF_INJECTED** | ❌ Setado | ✅ Nunca |
| **Latência** | ~1ms | ~5-8ms |
| **Custo** | Grátis | $5-10 |
| **Setup** | Fácil | Moderado |

## ⚠️ Considerações de Performance

> [!WARNING]
> Serial UART a 9600 baud tem **latência de ~5ms**. Para aimbot competitivo, considere:
> - **USB Serial a 921600 baud** (~0.5ms)
> - **DMA via PCI-E** (Screamer PCIE Squirrel) para latência sub-1ms

## 📖 Devices Avançados

### KMBox / Sayo Device
- DMA direto no barramento USB
- Latência < 1ms
- Custo: $100-300 USD
- Status: Indetectável pelo VAC (2026)

### Screamer PCIE
- Acesso DMA à memória do sistema
- Bypass total do Windows
- Custo: $300-500 USD
- Usado para read/write de memória + input simultâneo

## 📖 Ver Também
- [[Hardware_vs_Software_Input]]
- [[Kernel_Input_Injection]]
- [[Physical_Memory_Access]]

---
<p align="center">REDFLAG © 2026</p>
