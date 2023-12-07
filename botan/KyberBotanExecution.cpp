#include <botan/kyber.h>
#include <botan/pubkey.h>
#include <botan/system_rng.h>
#include <array>
#include <iostream>

int main() {
    const size_t shared_key_len = 32;
    const std::string kdf = "HKDF(SHA-512)";

    Botan::System_RNG rng;

    std::array<uint8_t, 16> salt;
    rng.randomize(salt);

    Botan::Kyber_PrivateKey privateKey(rng, Botan::KyberMode::Kyber512);
    auto publicKey = privateKey.public_key();

    Botan::PK_KEM_Encryptor enc(*publicKey, kdf);

    const auto kem_result = enc.encrypt(rng, shared_key_len, salt);

    Botan::PK_KEM_Decryptor dec(privateKey, rng, kdf);

    auto dec_shared_key = dec.decrypt(kem_result.encapsulated_shared_key(), shared_key_len, salt);

    if (dec_shared_key != kem_result.shared_key()) {
        std::cerr << "Shared key differ\n";
        return 1;
    } else {
        std::cerr << "Shared keys are the same";
        return 0;
    }
}
