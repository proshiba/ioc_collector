# ioc_collector

脅威インテリジェンスソースから IOC（侵害指標）を収集・エンリッチするツールです。

---

## 目次

1. [セットアップ](#セットアップ)
2. [IOC の収集](#ioc-の収集)
3. [MaxMind IP データベースのダウンロード](#maxmind-ip-データベースのダウンロード)
4. [IP アドレスのエンリッチ](#ip-アドレスのエンリッチ)
5. [ディレクトリ構成](#ディレクトリ構成)

---

## セットアップ

```bash
pip install -r requirements.txt
```

---

## IOC の収集

ThreatFox から直近 1 日分の IOC を取得し、`iocs/<yyyymmdd>.json` に保存します。

```bash
python app/bin/collect_iocs.py [--source {threatfox}]
```

| オプション | 説明 | デフォルト |
|---|---|---|
| `--source` | 収集元ソース | `threatfox` |

**出力例:**

```
Fetching IOCs from threatfox for the last day …
Retrieved 120 IOC(s).
Saved to iocs/20240101.json
```

---

## MaxMind IP データベースのダウンロード

IPアドレスのエンリッチ（ASN・国情報の取得）に必要な MaxMind GeoLite2 データベースをダウンロードします。

### 事前準備：ライセンスキーの取得

1. [MaxMind アカウント登録ページ](https://www.maxmind.com/en/geolite2/signup) で無料アカウントを作成します。
2. ログイン後、「My License Key」からライセンスキーを発行します。
3. 発行したキーを環境変数 `MAXMIND_LICENSE_KEY` に設定します。

```bash
export MAXMIND_LICENSE_KEY=<your_license_key>
```

### 実行方法

```bash
python app/bin/download_maxmind_db.py [--dest-dir data/maxmind]
```

| オプション | 説明 | デフォルト |
|---|---|---|
| `--dest-dir` | `.mmdb` ファイルの保存先ディレクトリ | `data/maxmind` |

**出力例:**

```
Downloading MaxMind GeoLite2 databases to 'data/maxmind' ...
  GeoLite2-ASN: data/maxmind/GeoLite2-ASN.mmdb
  GeoLite2-Country: data/maxmind/GeoLite2-Country.mmdb
Done.
```

以下の 2 ファイルが保存されます:

- `data/maxmind/GeoLite2-ASN.mmdb` — ASN（自律システム番号・組織名）情報
- `data/maxmind/GeoLite2-Country.mmdb` — 国情報

> **注意:** ライセンスキーが設定されていない場合はエラーになります。
> ```
> Error: MAXMIND_LICENSE_KEY environment variable is not set.
> ```

---

## IP アドレスのエンリッチ

ダウンロードした `.mmdb` ファイルを使用して、IP アドレスから ASN・国情報を取得します。

### Python API

```python
from module.enrich.enrich_ip import enrich_ip

result = enrich_ip("8.8.8.8")
print(result)
# {
#   "ip": "8.8.8.8",
#   "asn": 15169,
#   "org": "GOOGLE",
#   "country_code": "US",
#   "country_name": "United States",
# }
```

個別のルックアップ関数も利用できます:

```python
from module.enrich.enrich_ip import fetch_asn, fetch_country

# ASN情報のみ取得
asn = fetch_asn("8.8.8.8")
# {"asn": 15169, "org": "GOOGLE"}

# 国情報のみ取得
country = fetch_country("8.8.8.8")
# {"country_code": "US", "country_name": "United States"}
```

### 戻り値の説明

| フィールド | 説明 | 例 |
|---|---|---|
| `ip` | 検索した IP アドレス | `"8.8.8.8"` |
| `asn` | 自律システム番号 | `15169` |
| `org` | 自律システム組織名 | `"GOOGLE"` |
| `country_code` | ISO 3166-1 alpha-2 国コード | `"US"` |
| `country_name` | 国名（英語） | `"United States"` |

> **注意:** `.mmdb` ファイルが存在しない場合は、各フィールドが `null` になります。先に `download_maxmind_db.py` を実行してください。

---

## ディレクトリ構成

```
ioc_collector/
├── app/
│   ├── bin/                         # CLIスクリプト
│   │   ├── collect_iocs.py          # IOC収集スクリプト
│   │   └── download_maxmind_db.py   # MaxMind DBダウンロードスクリプト
│   └── module/
│       ├── fetch/
│       │   ├── threatfox.py         # ThreatFox API クライアント
│       │   └── maxmind_db.py        # MaxMind DBダウンロード関数
│       └── enrich/
│           ├── enrich_domain.py     # ドメインエンリッチ（DNS・WHOIS）
│           └── enrich_ip.py         # IPエンリッチ（ASN・国情報）
├── data/
│   └── maxmind/                     # ダウンロードされた .mmdb ファイル（自動生成）
├── iocs/                            # 収集したIOCのJSONファイル（自動生成）
├── tests/                           # テストコード
└── requirements.txt
```

