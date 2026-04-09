# mkcert-rust

`mkcert-rust` 是一个使用 Rust 编写的本地开发证书生成工具，受 [mkcert](https://github.com/FiloSottile/mkcert) 启发。它支持自定义证书颁发者和持有者信息，并引入了后量子加密算法（PQC）。

## 主要特性

- **自定义证书字段**：可设置 Common Name (CN)、Organization (O) 和 Organizational Unit (OU)。
- **先进加密算法**：支持 Ed25519, ECDSA (P-256, P-384)。
- **后量子加密 (PQC)**：支持 NIST 标准的 ML-DSA (Dilithium) 算法 (`ml-dsa44`, `ml-dsa65`, `ml-dsa87`)。
- **泛域名支持**：轻松生成如 `*.example.com` 的通配符证书。

## 安装依赖

在编译此项目之前，请确保您的系统已安装以下依赖：

### 1. Rust 工具链
需要安装 Rust (建议版本 1.80+)。
```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### 2. 构建工具 (C/C++)
底层加密库 `aws-lc-rs` 需要 C 编译环境：
- **Linux (Ubuntu/Debian)**:
  ```bash
  sudo apt-get update
  sudo apt-get install build-essential cmake
  ```
- **macOS**:
  安装 Xcode 命令行工具：
  ```bash
  xcode-select --install
  ```
- **Windows**:
  安装 [Visual Studio 2017+](https://visualstudio.microsoft.com/downloads/) 的 "使用 C++ 的桌面开发" 工作负载，并安装 [NASM](https://www.nasm.us/)（用于汇编代码编译）。

## 快速开始

### 编译项目
```bash
cargo build --release
```

### 1. 生成并安装 Root CA
首次使用需要生成本地信任的 Root CA：
```bash
# 生成默认 Ed25519 Root CA
./target/release/mkcert-rust --install

# 自定义 CA 信息
./target/release/mkcert-rust --install --issuer-o "My Org" --issuer-cn "Local Development CA"
```
*注意：Root CA 文件存储在系统本地数据目录（如 Linux 上的 `~/.local/share/mkcert-rust/`）。*

### 2. 生成域名证书
```bash
# 生成普通域名证书
./target/release/mkcert-rust example.com localhost

# 生成通配符（泛域名）证书
./target/release/mkcert-rust "*.example.com" example.com

# 使用后量子加密算法 (ML-DSA-65)
./target/release/mkcert-rust dev.local --alg ml-dsa65
```

## 命令行参数

| 参数 | 描述 | 默认值 |
| :--- | :--- | :--- |
| `<domains>...` | 域名或 IP 地址列表 | (必填，除非使用 --install) |
| `--install` | 检查并生成 Root CA | `false` |
| `--alg` | 加密算法 (`ed25519`, `ecdsa-p256`, `ecdsa-p384`, `ml-dsa44`, `ml-dsa65`, `ml-dsa87`) | `ed25519` |
| `--issuer-cn` | CA 的 Common Name | `mkcert-rust development CA` |
| `--issuer-o` | CA 的 Organization | `mkcert-rust development CA` |
| `--subject-cn` | 证书的 Common Name | 第一个域名 |
| `--subject-o` | 证书的 Organization | `mkcert-rust development certificate` |

## 局限性说明
由于底层库 `rcgen` 目前的限制，ML-DSA (量子算法) 目前主要推荐用于端点证书的公钥。如果将 Root CA 设置为 ML-DSA，在重新加载 CA 签名时可能会遇到兼容性问题。建议 Root CA 使用传统算法（如 Ed25519），而域名证书使用量子算法。
