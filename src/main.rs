use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ECDSA_P521_SHA512, PKCS_ED25519, 
    PKCS_ML_DSA_44, PKCS_ML_DSA_65, PKCS_ML_DSA_87, PKCS_RSA_SHA256, PKCS_RSA_SHA384, PKCS_RSA_SHA512,
    SignatureAlgorithm,
};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use time::{Duration, OffsetDateTime};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Domain names or IP addresses for which to generate a certificate.
    #[arg(required_unless_present_any = ["install", "install_rootca"])]
    domains: Vec<String>,

    /// Generate the Root CA if it doesn't exist.
    #[arg(long)]
    install: bool,

    /// Install a Root CA certificate into the system and browser trust stores.
    #[arg(long, value_name = "FILE")]
    install_rootca: Option<PathBuf>,

    /// Common Name for the Issuer (CA).
    #[arg(long, default_value = "mkcert-rust development CA")]
    issuer_cn: String,

    /// Organization for the Issuer (CA).
    #[arg(long, default_value = "mkcert-rust development CA")]
    issuer_o: String,

    /// Organizational Unit for the Issuer (CA).
    #[arg(long, default_value = "admin")]
    issuer_ou: String,

    /// Common Name for the Subject (End-Entity).
    #[arg(long)]
    subject_cn: Option<String>,

    /// Organization for the Subject (End-Entity).
    #[arg(long, default_value = "mkcert-rust development certificate")]
    subject_o: String,

    /// Organizational Unit for the Subject (End-Entity).
    #[arg(long, default_value = "admin")]
    subject_ou: String,

    /// Algorithm to use for the certificate.
    #[arg(long, value_enum, default_value_t = Algorithm::Ed25519)]
    alg: Algorithm,
}

#[derive(ValueEnum, Clone, Debug, Copy)]
enum Algorithm {
    Ed25519,
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
    Rsa2048Sha256,
    Rsa3072Sha384,
    Rsa4096Sha512,
    /// Quantum-resistant ML-DSA-44 (Experimental, current rcgen limitation prevents signing with this CA)
    MlDsa44,
    /// Quantum-resistant ML-DSA-65 (Experimental, current rcgen limitation prevents signing with this CA)
    MlDsa65,
    /// Quantum-resistant ML-DSA-87 (Experimental, current rcgen limitation prevents signing with this CA)
    MlDsa87,
}

impl Algorithm {
    fn to_rcgen_alg(self) -> &'static SignatureAlgorithm {
        match self {
            Algorithm::Ed25519 => &PKCS_ED25519,
            Algorithm::EcdsaP256 => &PKCS_ECDSA_P256_SHA256,
            Algorithm::EcdsaP384 => &PKCS_ECDSA_P384_SHA384,
            Algorithm::EcdsaP521 => &PKCS_ECDSA_P521_SHA512,
            Algorithm::Rsa2048Sha256 => &PKCS_RSA_SHA256,
            Algorithm::Rsa3072Sha384 => &PKCS_RSA_SHA384,
            Algorithm::Rsa4096Sha512 => &PKCS_RSA_SHA512,
            Algorithm::MlDsa44 => &PKCS_ML_DSA_44,
            Algorithm::MlDsa65 => &PKCS_ML_DSA_65,
            Algorithm::MlDsa87 => &PKCS_ML_DSA_87,
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    if let Some(rootca_path) = &args.install_rootca {
        return install_root_ca(rootca_path);
    }

    let ca_dir = dirs::data_local_dir()
        .context("Could not determine local data directory")?
        .join("mkcert-rust");

    if !ca_dir.exists() {
        fs::create_dir_all(&ca_dir).context("Could not create CA directory")?;
    }

    let ca_cert_path = ca_dir.join("rootCA.pem");
    let ca_key_path = ca_dir.join("rootCA-key.pem");

    let need_generate = args.install || !ca_cert_path.exists() || !ca_key_path.exists();

    if need_generate {
        println!("Generating Root CA...");
        generate_ca(&args, &ca_cert_path, &ca_key_path)?;
        println!("Root CA generated at: {}", ca_cert_path.display());
    }

    if args.install || need_generate {
        println!("Installing Root CA into system and browser trust stores...");
        install_root_ca(&ca_cert_path)?;
    }

    if !args.domains.is_empty() {
        generate_cert(&args, &ca_cert_path, &ca_key_path)?;
    }

    Ok(())
}

fn generate_ca(args: &Args, cert_path: &Path, key_path: &Path) -> Result<()> {
    let alg = args.alg.to_rcgen_alg();
    let key_pair = KeyPair::generate_for(alg).context("Failed to generate CA key pair")?;

    let mut params = CertificateParams::default();
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(913); // Approx 2.5 years
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &args.issuer_cn);
    params.distinguished_name.push(DnType::OrganizationName, &args.issuer_o);
    params.distinguished_name.push(DnType::OrganizationalUnitName, &args.issuer_ou);

    let cert = params.self_signed(&key_pair).context("Failed to self-sign CA certificate")?;

    fs::write(cert_path, cert.pem()).context("Failed to write CA certificate")?;
    fs::write(key_path, key_pair.serialize_pem()).context("Failed to write CA key")?;
    
    // Store metadata for the CA algorithm
    let alg_str = match args.alg {
        Algorithm::Ed25519 => "ed25519",
        Algorithm::EcdsaP256 => "ecdsa-p256",
        Algorithm::EcdsaP384 => "ecdsa-p384",
        Algorithm::EcdsaP521 => "ecdsa-p521",
        Algorithm::Rsa2048Sha256 => "rsa2048",
        Algorithm::Rsa3072Sha384 => "rsa3072",
        Algorithm::Rsa4096Sha512 => "rsa4096",
        Algorithm::MlDsa44 => "ml-dsa44",
        Algorithm::MlDsa65 => "ml-dsa65",
        Algorithm::MlDsa87 => "ml-dsa87",
    };
    fs::write(cert_path.with_extension("alg"), alg_str).context("Failed to write CA algorithm metadata")?;

    Ok(())
}

fn generate_cert(args: &Args, ca_cert_path: &Path, ca_key_path: &Path) -> Result<()> {
    let alg = args.alg.to_rcgen_alg();
    
    // Load CA
    let ca_cert_pem = fs::read_to_string(ca_cert_path).context("Failed to read CA certificate")?;
    let ca_key_pem = fs::read_to_string(ca_key_path).context("Failed to read CA key")?;
    let ca_alg_name = fs::read_to_string(ca_cert_path.with_extension("alg")).context("Failed to read CA algorithm metadata")?;
    
    let ca_alg_enum = match ca_alg_name.trim() {
        "ed25519" => Algorithm::Ed25519,
        "ecdsa-p256" => Algorithm::EcdsaP256,
        "ecdsa-p384" => Algorithm::EcdsaP384,
        "ecdsa-p521" => Algorithm::EcdsaP521,
        "rsa2048" => Algorithm::Rsa2048Sha256,
        "rsa3072" => Algorithm::Rsa3072Sha384,
        "rsa4096" => Algorithm::Rsa4096Sha512,
        "ml-dsa44" => Algorithm::MlDsa44,
        "ml-dsa65" => Algorithm::MlDsa65,
        "ml-dsa87" => Algorithm::MlDsa87,
        _ => return Err(anyhow::anyhow!("Unknown algorithm in CA metadata: {}", ca_alg_name)),
    };
    let ca_alg = ca_alg_enum.to_rcgen_alg();

    // Check if loading the CA key will work (rcgen 0.14.7 limitation for ML-DSA)
    if matches!(ca_alg_enum, Algorithm::MlDsa44 | Algorithm::MlDsa65 | Algorithm::MlDsa87) {
        return Err(anyhow::anyhow!("Current version of rcgen cannot load ML-DSA (Quantum) CA keys from PEM. Please use a traditional algorithm like Ed25519 or EcdsaP384 for the Root CA, while you can still use ML-DSA for the end-entity certificate public key."));
    }

    let ca_key = KeyPair::from_pem_and_sign_algo(&ca_key_pem, ca_alg).context("Failed to parse CA key")?;
    let ca_issuer = Issuer::from_ca_cert_pem(&ca_cert_pem, ca_key).context("Failed to parse CA certificate into Issuer")?;

    // Generate End-Entity Cert
    let ee_key_pair = KeyPair::generate_for(alg).context("Failed to generate EE key pair")?;
    
    let subject_cn = args.subject_cn.clone().unwrap_or_else(|| {
        args.domains.first().cloned().unwrap_or_else(|| "localhost".to_string())
    });

    let mut params = CertificateParams::new(args.domains.clone())?;
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = params.not_before + Duration::days(913); // Approx 2.5 years
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, &subject_cn);
    params.distinguished_name.push(DnType::OrganizationName, &args.subject_o);
    params.distinguished_name.push(DnType::OrganizationalUnitName, &args.subject_ou);

    for domain in &args.domains {
        if let Ok(ip) = domain.parse::<IpAddr>() {
            params.subject_alt_names.push(rcgen::SanType::IpAddress(ip));
        }
    }

    let ee_cert = params.signed_by(&ee_key_pair, &ca_issuer).context("Failed to sign EE certificate")?;

    let base_name = if args.domains.len() > 1 {
        format!("{}+{}", args.domains[0], args.domains.len() - 1)
    } else {
        args.domains[0].clone()
    };

    let cert_out = format!("{}.pem", base_name);
    let key_out = format!("{}-key.pem", base_name);

    fs::write(&cert_out, ee_cert.pem()).context("Failed to write EE certificate")?;
    fs::write(&key_out, ee_key_pair.serialize_pem()).context("Failed to write EE key")?;

    println!("\nCreated a new certificate valid for the following names \u{2705}");
    for domain in &args.domains {
        println!(" - {}", domain);
    }
    println!("\nThe certificate is at \"{}\" and the key at \"{}\" \u{2728}\n", cert_out, key_out);

    Ok(())
}

fn install_root_ca(cert_path: &Path) -> Result<()> {
    if !cert_path.exists() {
        return Err(anyhow::anyhow!("Certificate file not found: {}", cert_path.display()));
    }

    let os = env::consts::OS;
    println!("Detected OS: {}", os);

    match os {
        "linux" => install_linux(cert_path)?,
        "macos" => install_macos(cert_path)?,
        "windows" => install_windows(cert_path)?,
        _ => println!("Unsupported OS for automatic system trust store installation: {}", os),
    }

    install_nss_browsers(cert_path)?;

    println!("Root CA installation complete.");
    Ok(())
}

fn install_linux(cert_path: &Path) -> Result<()> {
    println!("Installing to Linux system trust store (requires sudo)...");
    if Path::new("/usr/local/share/ca-certificates/").exists() {
        let target = "/usr/local/share/ca-certificates/mkcert-rust-ca.crt";
        // Remove old certificate first (ignore errors if it doesn't exist)
        let _ = run_sudo(&["rm", "-f", target]);
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["update-ca-certificates"])?;
    } else if Path::new("/etc/pki/ca-trust/source/anchors/").exists() {
        let target = "/etc/pki/ca-trust/source/anchors/mkcert-rust-ca.crt";
        // Remove old certificate first (ignore errors if it doesn't exist)
        let _ = run_sudo(&["rm", "-f", target]);
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["update-ca-trust", "extract"])?;
    } else if Path::new("/etc/ca-certificates/trust-source/anchors/").exists() {
        let target = "/etc/ca-certificates/trust-source/anchors/mkcert-rust-ca.crt";
        // Remove old certificate first (ignore errors if it doesn't exist)
        let _ = run_sudo(&["rm", "-f", target]);
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["trust", "extract-compat"])?;
    } else {
        println!("Could not determine Linux distribution for system trust store.");
    }
    Ok(())
}

fn install_macos(cert_path: &Path) -> Result<()> {
    println!("Installing to macOS System Keychain (requires sudo)...");

    // Remove any existing mkcert-rust CA certificates from the System Keychain first.
    // `security find-certificate` returns a non-zero exit code when nothing is found,
    // so we intentionally ignore errors here.
    println!("Removing old mkcert-rust CA from System Keychain (if present)...");
    let find_output = Command::new("security")
        .args(["find-certificate", "-a", "-c", "mkcert-rust development CA",
               "-Z", "/Library/Keychains/System.keychain"])
        .output();

    if let Ok(out) = find_output {
        // Each matching certificate has a "SHA-1 hash:" line; delete them all.
        let stdout = String::from_utf8_lossy(&out.stdout);
        for line in stdout.lines() {
            let trimmed = line.trim();
            if let Some(hash) = trimmed.strip_prefix("SHA-1 hash:") {
                let hash = hash.trim();
                println!("  Deleting certificate with SHA-1: {}", hash);
                // Ignore errors (certificate may already be gone)
                let _ = run_sudo(&[
                    "security", "delete-certificate",
                    "-Z", hash,
                    "/Library/Keychains/System.keychain",
                ]);
            }
        }
    }

    run_sudo(&[
        "security", "add-trusted-cert",
        "-d", "-r", "trustRoot",
        "-k", "/Library/Keychains/System.keychain",
        cert_path.to_str().unwrap(),
    ])?;
    Ok(())
}

fn install_windows(cert_path: &Path) -> Result<()> {
    println!("Installing to Windows system trust store...");

    // Remove any previously installed mkcert-rust CA certificate first.
    // certutil -delstore returns non-zero when the certificate is not found,
    // so we intentionally ignore the result.
    println!("Removing old mkcert-rust CA from Windows trust store (if present)...");
    let _ = Command::new("certutil")
        .args(["-delstore", "-user", "root", "mkcert-rust development CA"])
        .status();

    let status = Command::new("certutil")
        .args(["-addstore", "-user", "root", cert_path.to_str().unwrap()])
        .status()?;
    if !status.success() {
        println!("Failed to install on Windows.");
    }
    Ok(())
}

fn run_sudo(args: &[&str]) -> Result<()> {
    let status = Command::new("sudo")
        .args(args)
        .status()?;
    if !status.success() {
        return Err(anyhow::anyhow!("sudo command failed: {:?}", args));
    }
    Ok(())
}

/// Detect the signature algorithm used in a PEM certificate file.
/// Returns a short string like "ed25519", "ecdsa", "rsa", or "unknown".
fn detect_cert_algorithm(cert_path: &Path) -> String {
    let Ok(pem) = fs::read_to_string(cert_path) else {
        return "unknown".to_string();
    };
    // Use openssl to print the signature algorithm, fallback to "unknown"
    let out = Command::new("openssl")
        .args(["x509", "-noout", "-text", "-in", cert_path.to_str().unwrap_or("")])
        .output();
    if let Ok(out) = out {
        let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
        if text.contains("ed25519") {
            return "ed25519".to_string();
        }
        if text.contains("ml-dsa") || text.contains("mldsa") {
            return "ml-dsa".to_string();
        }
        if text.contains("ecdsa") || text.contains("id-ecpublickey") {
            return "ecdsa".to_string();
        }
        if text.contains("rsaencryption") || text.contains("rsa") {
            return "rsa".to_string();
        }
    }
    // Fallback: scan raw PEM bytes for known OID markers
    if pem.contains("Ed25519") || pem.contains("ed25519") {
        return "ed25519".to_string();
    }
    "unknown".to_string()
}

/// Returns true if the algorithm is known to be unsupported by NSS certutil.
fn is_nss_unsupported_alg(alg: &str) -> bool {
    matches!(alg, "ed25519" | "ml-dsa")
}

fn install_nss_browsers(cert_path: &Path) -> Result<()> {
    println!("Checking for NSS databases (Firefox, Chrome, Edge)...");

    // NSS / certutil does not support Ed25519 or ML-DSA certificates.
    // Attempting to import them always fails with SEC_ERROR_ADDING_CERT.
    let alg = detect_cert_algorithm(cert_path);
    if is_nss_unsupported_alg(&alg) {
        println!(
            "⚠️  Skipping NSS (Firefox/Chrome) installation: the certificate uses {} \
             which is not supported by NSS certutil.",
            alg.to_uppercase()
        );
        println!(
            "   To install the Root CA in Firefox/Chrome, regenerate it with a supported \
             algorithm, e.g.:\n   mkcert-rust --install --alg ecdsa-p256"
        );
        return Ok(());
    }

    if Command::new("certutil").arg("-H").output().is_err() {
        println!("'certutil' command not found. Skipping Firefox/Chrome NSS installation.");
        println!("To install it on Linux: sudo apt install libnss3-tools");
        println!("To install it on macOS: brew install nss");
        return Ok(());
    }

    let mut nss_dbs = Vec::new();
    let home = dirs::home_dir().unwrap_or_default();

    // Chrome/Edge/Brave on Linux
    let pki_nssdb = home.join(".pki/nssdb");
    if pki_nssdb.exists() {
        nss_dbs.push(pki_nssdb);
    }

    // Firefox on Linux/macOS
    let firefox_paths = vec![
        home.join(".mozilla/firefox"),
        home.join("snap/firefox/common/.mozilla/firefox"),
        home.join("Library/Application Support/Firefox/Profiles"),
    ];

    for base in firefox_paths {
        if base.exists() {
            if let Ok(entries) = std::fs::read_dir(&base) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.is_dir()
                        && (path.join("cert9.db").exists() || path.join("cert8.db").exists())
                    {
                        nss_dbs.push(path);
                    }
                }
            }
        }
    }

    if nss_dbs.is_empty() {
        println!("No NSS databases found.");
        return Ok(());
    }

    for db in &nss_dbs {
        println!("Updating NSS database: {}", db.display());
        let db_arg = format!("sql:{}", db.display());

        // 1. Try to delete the old certificate if it exists (ignore errors)
        let _ = Command::new("certutil")
            .args(["-d", &db_arg, "-D", "-n", "mkcert-rust-ca"])
            .output();

        // 2. Add the new certificate
        let result = Command::new("certutil")
            .args([
                "-d", &db_arg,
                "-A", "-t", "CT,C,C",
                "-n", "mkcert-rust-ca",
                "-i", cert_path.to_str().unwrap(),
            ])
            .output();

        let mut success = false;
        if let Ok(out) = &result {
            if out.status.success() {
                success = true;
                println!("  ✅ Successfully updated {}", db.display());
            }
        }

        if !success {
            println!("  ⚠️  certutil failed. Attempting fallback to pk12util...");
            let p12_path = dirs::data_local_dir().unwrap().join("mkcert-rust").join("rootCA.p12");
            let _ = Command::new("openssl")
                .args(["pkcs12", "-export", "-nokeys", "-in", cert_path.to_str().unwrap(), "-out", p12_path.to_str().unwrap(), "-passout", "pass:"])
                .status();
            
            let pk12_status = Command::new("pk12util")
                .args(["-i", p12_path.to_str().unwrap(), "-d", &db_arg, "-W", ""])
                .status();
                
            if pk12_status.map(|s| s.success()).unwrap_or(false) {
                println!("  ✅ Successfully updated {} via pk12util fallback.", db.display());
            } else {
                let err_msg = if let Ok(out) = result {
                    String::from_utf8_lossy(&out.stdout).to_string()
                } else {
                    "Execution failed".to_string()
                };
                println!(
                    "  ❌ Failed to install in {}.\n     Original certutil error: {}\n     Make sure the browser is closed and you have sufficient permissions.",
                    db.display(),
                    err_msg.trim()
                );
            }
        }
    }

    Ok(())
}
