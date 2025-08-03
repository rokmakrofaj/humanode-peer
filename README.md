# 🦀 Humanode Monitoring Rust Sunucusu Rehberi

Bu döküman, bir sunucuda `humanode-peer` isimli sürecin çalışıp çalışmadığını izleyen ve bunu bir API üzerinden sunan **Rust tabanlı monitoring servisi** kurulumunu açıklar.

---

## 📦 Özellikler

- `humanode-peer` sürecini sistemde arar.
- Biometric doğrulama durumunu çeker (`bioauth_status` RPC ile).
- Tunnel (dinleme) adreslerini çeker (`system_localListenAddresses` RPC ile).
- Belirtilen cüzdanın transfer geçmişini Subscan API üzerinden çeker.
- Her 60 saniyede bir tüm verileri günceller.
- Token kontrollü basit bir HTTP API sunar:
- `GET /status?token=...`
- `GET /transfers?token=...`
- `systemd` servisi olarak yapılandırılabilir ve arkaplanda çalışır.

---

## 🛠️ Gerekli Kurulumlar

### 1. Rust kurulumu:

```bash
curl https://sh.rustup.rs -sSf | sh
```
Kurulum sırasında 1) Proceed with installation (default) seçeneğini seç.
Bitince şunu çalıştır:
```
source $HOME/.cargo/env
```

Artık şunlar çalışıyor olmalı:
```
rustc --version
cargo --version
```
> Alternatif: `sudo apt install cargo rustc` (ama eski sürüm gelebilir)

### 2. Geliştirme araçları:

```bash
sudo apt update
sudo apt install build-essential pkg-config libssl-dev
```

---

## 🚀 Proje Oluşturma

```bash
cargo new humanode_monitor
```

```
nano humanode_monitor/Cargo.toml
```

### `Cargo.toml` içeriği:

```toml
[package]
name = "humanode_monitor"
version = "0.1.0"
edition = "2021"

[dependencies]
actix-web = "4"
actix-cors = "0.6"
chrono = { version = "0.4", features = ["serde"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
tokio = { version = "1", features = ["full"] }
reqwest = { version = "0.11", features = ["json"] }
sysinfo = "0.29"
log = "0.4.27"
env_logger = "0.11.8"

```
```
cd humanode_monitor
```
```
cargo build --release
```
```
nano config.txt
```
İçeriğini kendi bilgilerinizle doldurun:
```
HUMANODE_TOKEN=sunucutokeniniz
SUBSCAN_TOKEN=SUBSCAN_API_ANAHTARINIZI_BURAYA_YAZIN
```
cargo build --release
```
cd
```
```
nano humanode_monitor/src/main.rs
```

---

## 📄 `main.rs` Kaynak Kodu

`src/main.rs` içerisine şu kodu yapıştır:

```rust
use actix_web::{web, App, HttpResponse, HttpServer, Responder};
use chrono::{DateTime, Utc, TimeZone};
use serde::Serialize;
use sysinfo::{ProcessExt, System, SystemExt};
use tokio::time::{interval, Duration};
use tokio::sync::Mutex;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufReader, BufRead};
use std::sync::Arc;
use reqwest::Client;

// --- Struct'lar ---

#[derive(Clone)]
struct Config {
    // Cüzdan adresi kaldırıldı
    subscan_api_key: String,
}

#[derive(Serialize, Clone)]
struct Transfer {
    transfer_id: u64,
    from: String,
    to: String,
    asset_symbol: String,
    amount: String,
    hash: String,
    block_timestamp: i64,
    formatted_date: String,
}

#[derive(Serialize, Clone)]
struct BiometricStatus {
    active: bool,
    expires_at: Option<String>,
}

#[derive(Serialize, Clone)]
struct TunnelStatus {
    connected: bool,
    listeners: Vec<String>,
}

#[derive(Serialize, Clone)]
struct Status {
    status: String,
    last_update: DateTime<Utc>,
    biometric: BiometricStatus,
    tunnel: TunnelStatus,
}

struct AppState {
    status: Mutex<Status>,
    // Transfer listesi artık state'de tutulmuyor
    valid_tokens: Vec<String>,
    config: Config,
}

// --- HTTP Handler Fonksiyonları ---

async fn get_status(data: web::Data<Arc<AppState>>, query: web::Query<HashMap<String, String>>) -> impl Responder {
    if !is_token_valid(&data, &query) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Yetkisiz token"}));
    }
    let status = data.status.lock().await.clone();
    HttpResponse::Ok().json(status)
}

// GÜNCELLENDİ: Bu fonksiyon artık anlık olarak veri çekecek
async fn get_transfers(data: web::Data<Arc<AppState>>, query: web::Query<HashMap<String, String>>) -> impl Responder {
    // 1. Token'ı kontrol et
    if !is_token_valid(&data, &query) {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Yetkisiz token"}));
    }

    // 2. Query'den cüzdan adresini al
    if let Some(address) = query.get("address") {
        // 3. Adres varsa, anlık olarak transferleri çek
        match fetch_transfers(&data.config, address).await {
            Ok(transfers) => HttpResponse::Ok().json(transfers),
            Err(e) => {
                log::error!("Transfer verisi çekilirken hata oluştu: {}", e);
                HttpResponse::InternalServerError().json(serde_json::json!({"error": "Sunucu hatası"}))
            }
        }
    } else {
        // 4. Adres belirtilmemişse hata döndür
        HttpResponse::BadRequest().json(serde_json::json!({"error": "Cüzdan adresi ('address' parametresi) eksik"}))
    }
}


fn is_token_valid(data: &web::Data<Arc<AppState>>, query: &web::Query<HashMap<String, String>>) -> bool {
    query.get("token").map_or(false, |token| data.valid_tokens.contains(token))
}

// --- Veri Çekme Fonksiyonları ---

fn check_humanode_running(sys: &System) -> bool {
    sys.processes().values().any(|proc| proc.name().contains("humanode-peer"))
}

async fn fetch_biometric_status() -> BiometricStatus {
    let client = Client::new();
    let res = client.post("http://127.0.0.1:9944")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "bioauth_status",
            "params": [],
            "id": 1
        }))
        .send().await;

    if let Ok(resp) = res {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            if let Some(active) = json["result"]["Active"].as_object() {
                if let Some(expires_at) = active.get("expires_at").and_then(|v| v.as_i64()) {
                    if let Some(dt) = Utc.timestamp_millis_opt(expires_at).single() {
                         return BiometricStatus {
                            active: true,
                            expires_at: Some(dt.to_rfc3339()),
                        };
                    }
                }
            }
        }
    }

    BiometricStatus {
        active: false,
        expires_at: None,
    }
}

async fn fetch_tunnel_status() -> TunnelStatus {
    let client = Client::new();
    let res = client.post("http://127.0.0.1:9944")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "method": "system_localListenAddresses",
            "params": [],
            "id": 1
        }))
        .send().await;

    if let Ok(resp) = res {
        if let Ok(json) = resp.json::<serde_json::Value>().await {
            let listeners = json["result"].as_array()
                .unwrap_or(&vec![])
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<String>>();

            return TunnelStatus {
                connected: !listeners.is_empty(),
                listeners,
            };
        }
    }

    TunnelStatus {
        connected: false,
        listeners: vec![],
    }
}

// GÜNCELLENDİ: Bu fonksiyon artık dışarıdan bir 'address' parametresi alıyor
async fn fetch_transfers(config: &Config, address: &str) -> Result<Vec<Transfer>, reqwest::Error> {
    let client = Client::builder()
        .user_agent("MyRustMonitor/1.0")
        .build()?;

    let params = serde_json::json!({
        "address": address, // Parametreden gelen adresi kullan
        "page": 0, "row": 100, "order": "desc"
    });

    let resp = client.post("https://humanode.api.subscan.io/api/v2/scan/transfers")
        .header("x-api-key", &config.subscan_api_key)
        .json(&params).send().await?;

    let json: serde_json::Value = resp.json().await?;
    if json["code"] != 0 {
        log::error!("Subscan API hatası: {:?}", json);
        return Ok(vec![]);
    }

    let mut transfers = vec![];
    if let Some(items) = json["data"]["transfers"].as_array() {
        for item in items {
            if let (Some(from), Some(to), Some(id), Some(amount), Some(hash), Some(ts)) = (
                item["from"].as_str(), item["to"].as_str(), item["transfer_id"].as_u64(),
                item["amount"].as_str(), item["hash"].as_str(), item["block_timestamp"].as_i64()
            ) {
                transfers.push(Transfer {
                    transfer_id: id, from: from.to_string(), to: to.to_string(),
                    asset_symbol: item["asset_symbol"].as_str().unwrap_or("HMND").to_string(),
                    amount: amount.to_string(), hash: hash.to_string(), block_timestamp: ts,
                    formatted_date: Utc.timestamp_opt(ts, 0).single().map_or_else(String::new, |dt| dt.format("%d/%m/%Y %H:%M").to_string()),
                });
            }
        }
    }
    Ok(transfers)
}

// --- Yardımcı Fonksiyonlar ---

// GÜNCELLENDİ: Fonksiyon artık cüzdan adresi okumuyor
fn read_config() -> std::io::Result<(Config, String)> {
    let file = File::open("config.txt")?;
    let reader = BufReader::new(file);
    let mut humanode_token = None;
    let mut subscan_api_key = None;

    for line in reader.lines() {
        let line = line?;
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "HUMANODE_TOKEN" => humanode_token = Some(value.trim().to_string()),
                "SUBSCAN_TOKEN"  => subscan_api_key = Some(value.trim().to_string()),
                _ => {}
            }
        }
    }
    
    let config = Config {
        subscan_api_key: subscan_api_key.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "config.txt'de SUBSCAN_TOKEN eksik"))?,
    };
    let token = humanode_token.ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "config.txt'de HUMANODE_TOKEN eksik"))?;
    
    Ok((config, token))
}

// --- Ana Fonksiyon ---

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    let (config, api_token) = match read_config() {
        Ok(c) => c,
        Err(e) => {
            log::error!("config.txt dosyası okunamadı veya eksik anahtar var: {}", e);
            return Err(e);
        }
    };
    log::info!("Yapılandırma başarıyla okundu.");

    let initial_status = Status {
        status: "checking".to_string(),
        last_update: Utc::now(),
        biometric: BiometricStatus { active: false, expires_at: None },
        tunnel: TunnelStatus { connected: false, listeners: vec![] },
    };

    // GÜNCELLENDİ: AppState'den 'transfers' kaldırıldı
    let state = Arc::new(AppState {
        status: Mutex::new(initial_status),
        valid_tokens: vec![api_token],
        config,
    });

    // Başlangıçta transfer çekme bölümü tamamen kaldırıldı

    let monitor_state = state.clone();
    tokio::spawn(async move {
        log::info!("Arkaplan güncelleme görevi başlatıldı.");
        let mut sys = System::new_all();
        let mut interval = interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            log::info!("Periyodik durum güncellemesi çalıştırılıyor...");
            sys.refresh_processes();

            let running = check_humanode_running(&sys);
            let biometric = fetch_biometric_status().await;
            let tunnel = fetch_tunnel_status().await;
            
            // Arka planda transfer güncelleme bölümü kaldırıldı
            
            let new_status = Status {
                status: if running { "up" } else { "down" }.to_string(),
                last_update: Utc::now(),
                biometric, tunnel,
            };
            *monitor_state.status.lock().await = new_status;
            log::info!("Durum güncellendi: {}", if running { "up" } else { "down" });
        }
    });

    log::info!("🔌 Sunucu http://0.0.0.0:8000 adresinde başlatılıyor...");
    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(state.clone()))
            .route("/status", web::get().to(get_status))
            .route("/transfers", web::get().to(get_transfers))
    })
    .bind(("0.0.0.0", 8000))?
    .run()
    .await
}
```
```
cd humanode_monitor
```
```
cargo build --release
```
```
./target/release/humanode_monitor
```
---

## 🧷 `systemd` ile arka plan servisi

```bash
sudo nano /etc/systemd/system/humanode_monitor.service
```

İçeriği şu şekilde olsun:

```ini
[Unit]
Description=Humanode Monitor Rust Servisi
After=network.target

[Service]
# BU SATIR EKSİK: Programın çalışacağı klasörü belirtir.
WorkingDirectory=/root/humanode_monitor

ExecStart=/root/humanode_monitor/target/release/humanode_monitor
Restart=always
RestartSec=5
User=root
Environment="RUST_LOG=info"

[Install]
WantedBy=multi-user.target
```

### Servisi Başlatma:

```bash
sudo systemctl daemon-reload
sudo systemctl restart humanode_monitor.service
sudo systemctl enable humanode_monitor
sudo systemctl start humanode_monitor
```



### Servis Durumunu Gör:

```bash
systemctl status humanode_monitor
```

### Logları Göster:

```bash
journalctl -u humanode_monitor -f
```

---

## ✅ Test

```bash
curl "http://SUNUCU_IP:8000/status?token=benimtokenim123"
```

Cevap:

```json
{
  "status": "up",
  "last_update": "2025-06-29T20:21:32Z"
}
```

---
🚨 Sorun Giderme (Troubleshooting)

Karşılaşabileceğiniz yaygın sorunlar ve çözümleri.

### Sorun 1: curl ile Bağlantı Kurulamıyor (Connection refused veya Komut Cevapsız Kalıyor)

Bu, en yaygın sorundur ve genellikle bir firewall engelinden kaynaklanır.

Neden: Programınız çalışsa bile, sunucunuza dışarıdan 8000 portu üzerinden gelen bağlantılar engelleniyor olabilir.

Çözüm:

Önce sunucudaki lokal firewall'u kontrol edin: sudo ufw status. Eğer active ise, sudo ufw allow 8000/tcp ile izin verin.

Eğer ufw inactive ise, sorun sunucu sağlayıcınızın (Contabo gibi) ağ panelindedir. Contabo müşteri panelinize girin, ilgili sunucuyu seçin ve "Firewall" veya "Security Groups" bölümünden 8000 portuna TCP için bir "gelen" (inbound) kuralı ekleyin.

### Sorun 2: Servis Sürekli Yeniden Başlıyor veya Address already in use Hatası

Neden: 8000 portu, düzgün kapanmamış eski bir humanode_monitor işlemi veya başka bir uygulama tarafından meşgul ediliyor. systemd servisi başlatmaya çalıştığında bu hatayı alıp çöker ve Restart=on-failure ayarı yüzünden bu bir döngüye girer.

Çözüm:

1. Portu hangi işlemin kullandığını bulun:
```
sudo ss -lptn 'sport = :8000'
```
2. Çıktıdaki pid= kısmında yazan işlem numarasını (PID) not alın.

3. O işlemi zorla sonlandırın (örneğin PID 12345 ise):
```
sudo kill -9 12345
```
4. Servisinizi yeniden başlatın: 
```
sudo systemctl restart humanode_monitor.service
```
### Sorun 3: Loglarda 403 Forbidden veya "Your request has been blocked" Hatası

    Neden: Bu hata, kodunuzun veya sunucunuzun değil, Subscan API erişiminizin sorunlu olduğunu gösterir. Olası nedenler:

        config.txt dosyasındaki SUBSCAN_TOKEN geçersiz veya yanlış.

        Subscan, kısa sürede çok fazla istek gönderdiğiniz için (rate limit) anahtarınızı/IP'nizi geçici olarak engelledi.

        Kullandığınız Subscan API adresi hatalı (webapi yerine api olmalı).

    Çözüm:

1. config.txt dosyasındaki API anahtarını ve cüzdan adresini tekrar kontrol edin.

2. Subscan panelinden yeni bir API anahtarı oluşturup onu kullanmayı deneyin.

3. Kodunuzdaki Subscan URL'sinin https://humanode.api.subscan.io/... olduğundan emin olun.

Hazırlayan: **makrofaj** 😎

