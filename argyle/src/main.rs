use pqc_kyber as kyber;
use pqc_dilithium as dilithium;
use pqc_sphincsplus as sphincs;
use std::fs;

fn test_pqc_kyber() -> Result<(u128, u128), kyber::KyberError> {
    let mut rng = rand::thread_rng();
    let keys_bob = kyber::keypair(&mut rng)?;
    let encapsulation_timer = std::time::Instant::now();
    let (ciphertext, shared_secret_alice) = kyber::encapsulate(&keys_bob.public, &mut rng)?; 
    let encapsulation_time = encapsulation_timer.elapsed().as_micros();
    let decapsulation_timer = std::time::Instant::now();
    let shared_secret_bob = kyber::decapsulate(&ciphertext, &keys_bob.secret)?;
    let decapsulation_time = decapsulation_timer.elapsed().as_micros();
    if shared_secret_alice != shared_secret_bob {
        return Err(kyber::KyberError::Decapsulation)
    }
    Ok((encapsulation_time, decapsulation_time))
}

fn test_pqc_dilithium(msg: &[u8]) -> Result<(u128, u128), dilithium::SignError> {
    let keys = dilithium::Keypair::generate();
    let sig_timer = std::time::Instant::now();
    let sig = keys.sign(&msg);
    let sig_time = sig_timer.elapsed().as_micros();
    let ver_timer = std::time::Instant::now();
    let _ = dilithium::verify(&sig, &msg, &keys.public)?;
    let ver_time = ver_timer.elapsed().as_micros();
    Ok((sig_time, ver_time))
}

fn test_pqc_sphincsplus(msg: &[u8]) -> Result<(u128, u128), sphincs::SigError> {
    let keys = sphincs::keypair();
    let sig_timer = std::time::Instant::now();
    let sig = sphincs::sign(&msg, &keys);
    let sig_time = sig_timer.elapsed().as_micros();
    let ver_timer = std::time::Instant::now();
    let _ = sphincs::verify(&sig, &msg, &keys)?;
    let ver_time = ver_timer.elapsed().as_micros();
    Ok((sig_time, ver_time))
}

fn main() {
    let file_path = "1024KB.txt";
    let content = fs::read_to_string(file_path).expect("No se puede abrir el archivo de prueba");
    let content = content.as_bytes();
    println!("Ejecutando Kyber");
    match test_pqc_kyber() {
        Ok((e, d)) => println!("Kyber ejecutado exitosamente. Encapsulación: {} Desencapsulación: {}",e ,d),
        Err(e) => println!("Fallo al ejecutar Kyber: {}", e.to_string())
    };
    println!("Ejecutando Dilithium");
    match test_pqc_dilithium(content) {
        Ok((s, v)) => println!("Dilithium ejecutado correctamente. Firmado: {} Verificación: {}", s, v),
        Err(_) => println!("Fallo al ejecutar dilithium"),
    }
    println!("Ejecutando Sphincs+");

    match test_pqc_sphincsplus(content) {
        Ok((s, v)) => println!("Sphincs+ ejecutado correctamente. Firmado: {} Verificación: {}", s, v),
        Err(_) => println!("Fallo al ejecutar Sphincs+"),
    }
}


#[cfg(test)]
mod tests {
    use crate::test_pqc_kyber;

    #[test]
    fn cryto_test() {
        let _ = test_pqc_kyber();
    }
}