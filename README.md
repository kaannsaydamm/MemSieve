MemSieve: Automated Memory Corruption Fuzzer & Crash Analyzer


MemSieve, Linux tabanlı ELF binary dosyaları üzerinde bellek bozulma (memory corruption) zafiyetlerini tespit etmek, analiz etmek ve sömürü (exploit) geliştirme sürecini hızlandırmak için tasarlanmış hibrit bir Fuzzing ve Dinamik Analiz motorudur.

Standart fuzzer'ların aksine, MemSieve sadece "çökme" (crash) yakalamaz; hedef sürecin (process) bellek alanına ptrace sistem çağrıları ile doğrudan müdahale ederek (instrumentation), çökme anındaki yazmaç (register) durumlarını ve exploit potansiyelini analiz eder.

<img width="1920" height="1080" alt="resim" src="https://github.com/user-attachments/assets/b13f512f-8884-447c-8924-6d809fc4da6b" />


🚀 Özellikler

- **Ptrace Tabanlı Instrumentation**: Hedef süreci ptrace API'si ile takip eder, sinyalleri (SIGSEGV, SIGABRT) yakalar.
- **Gerçek Zamanlı Register Analizi**: Çökme anında RIP, RSP gibi kritik yazmaçları dökümler.
- **Exploitability Triage**:
  - 🔴 **HIGH**: Instruction Pointer (RIP) kontrol ediliyor (Cyclic Pattern veya Payload içinde bulundu).
  - 🟡 **MEDIUM**: Null Dereference veya sınırlı etki.
- **Cyclic Pattern Generator**: Metasploit benzeri desenler üreterek offset'i otomatik bulur.
- **Security Checks**: Hedef binary ve sistem için ASLR ve PIE durumunu kontrol eder.
- **Akıllı Mutasyon Motoru**: Bit-flipping, byte-injection ve boundary-value analysis.
- **Wizard Mode**: `--wizard` parametresi ile interaktif yapılandırma menüsü.

🛠 Teknik Mimari

MemSieve, performans ve esnekliği birleştiren hibrit bir yapıya sahiptir:
- **The Tracer (C++)**: Ptrace ile düşük seviyeli process kontrolü.
- **The Engine (Python)**: TUI, Mutasyon ve Analiz mantığı.

⚙️ Kurulum

```bash
# Projeyi klonlayın
git clone https://github.com/kaannsaydamm/MemSieve.git
cd MemSieve

# Otomatik kurulum (Sanal ortam, derleme, bağımlılıklar)
./setup.sh

# Sanal ortamı aktif edin
source venv/bin/activate
```

💻 Kullanım

### Wizard Modu (Önerilen)
İnteraktif menü ile hedefi seçip ayarları kolayca yapabilirsiniz:
```bash
python3 memsieve.py --wizard
```

### CLI Modu
Hedef binary dosyasını varsayılan mutasyon ayarlarıyla taramak için:
```bash
python3 memsieve.py --target ./tests/mem_vault
```

Seed dosyası ile başlatmak için:
```bash
python3 memsieve.py --target ./tests/mem_vault --input sample.txt
```

### Test Uygulamaları
`tests/` klasörü altında pratik yapabileceğiniz zaafiyetli uygulamalar bulunur:
- `vulnerable_app`: Basit stack overflow.
- `mem_vault`: Heap overflow, Stack overflow, Format string ve Null dereference içeren kapsamlı test aracı.

🛡️ Sorumluluk Reddi (Disclaimer)

Bu araç yalnızca eğitim, araştırma ve yetkili güvenlik testleri amacıyla geliştirilmiştir. Yazar, bu aracın yetkisiz sistemlerde kötü niyetli kullanımından doğacak hiçbir sorumluluğu kabul etmez.

---
Made by Kaan Saydam, 2026.
