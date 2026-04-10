use anyhow::{Context, Result};
use clap::{Parser, ValueEnum};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519, PKCS_ML_DSA_44, PKCS_ML_DSA_65,
    PKCS_ML_DSA_87, SignatureAlgorithm,
};
use std::env;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

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

    if args.install || !ca_cert_path.exists() || !ca_key_path.exists() {
        println!("Generating Root CA...");
        generate_ca(&args, &ca_cert_path, &ca_key_path)?;
        println!("Root CA generated at: {}", ca_cert_path.display());
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
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["update-ca-certificates"])?;
    } else if Path::new("/etc/pki/ca-trust/source/anchors/").exists() {
        let target = "/etc/pki/ca-trust/source/anchors/mkcert-rust-ca.crt";
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["update-ca-trust", "extract"])?;
    } else if Path::new("/etc/ca-certificates/trust-source/anchors/").exists() {
        let target = "/etc/ca-certificates/trust-source/anchors/mkcert-rust-ca.crt";
        run_sudo(&["cp", cert_path.to_str().unwrap(), target])?;
        run_sudo(&["trust", "extract-compat"])?;
    } else {
        println!("Could not determine Linux distribution for system trust store.");
    }
    Ok(())
}

fn install_macos(cert_path: &Path) -> Result<()> {
    println!("Installing to macOS System Keychain (requires sudo)...");
    run_sudo(&["security", "add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", cert_path.to_str().unwrap()])?;
    Ok(())
}

fn install_windows(cert_path: &Path) -> Result<()> {
    println!("Installing to Windows system trust store...");
    let status = Command::new("certutil")
        .args(&["-addstore", "-user", "root", cert_path.to_str().unwrap()])
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

fn install_nss_browsers(cert_path: &Path) -> Result<()> {
    println!("Checking for NSS databases (Firefox, Chrome, Edge)...");
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
                    if path.is_dir() && (path.join("cert9.db").exists() || path.join("cert8.db").exists()) {
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

    for db in nss_dbs {
        println!("Updating NSS database: {}", db.display());
        let db_arg = format!("sql:{}", db.display());
        
        // 1. Try to delete the old certificate if it exists
        let _ = Command::new("certutil")
            .args(&["-d", &db_arg, "-D", "-n", "mkcert-rust-ca"])
            .status();

        // 2. Add the new certificate
        let status = Command::new("certutil")
            .args(&["-d", &db_arg, "-A", "-t", "CT,C,C", "-n", "mkcert-rust-ca", "-i", cert_path.to_str().unwrap()])
            .status();
        
        if let Ok(s) = status {
            if !s.success() {
                println!("Warning: Failed to install in {}. Please ensure the browser is closed and you have sufficient permissions.", db.display());
            } else {
                println!("Successfully updated {}", db.display());
            }
        }
    }

    Ok(())
}
