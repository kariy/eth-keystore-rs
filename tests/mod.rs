use starknet_keystore::{decrypt_key, encrypt_key, new};

use std::path::Path;

mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let (secret, id) = new(&dir, &mut rng, "thebestrandompassword", None, None, None).unwrap();

        let keypath = dir.join(&id);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(decrypt_key(&keypath, "notthebestrandompassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[test]
    fn test_new_with_name() {
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = "my_keystore";
        let (secret, _id) = new(
            &dir,
            &mut rng,
            "thebestrandompassword",
            Some(name),
            None,
            None,
        )
        .unwrap();

        let keypath = dir.join(&name);

        assert_eq!(
            decrypt_key(&keypath, "thebestrandompassword").unwrap(),
            secret
        );
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(not(feature = "starknet-compat"))]
    #[cfg(not(feature = "geth-compat"))]
    #[test]
    fn test_decrypt_pbkdf2() {
        use hex::FromHex;

        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-pbkdf2.json");
        assert_eq!(decrypt_key(&keypath, "testpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "wrongtestpassword").is_err());
    }

    #[cfg(not(feature = "starknet-compat"))]
    #[test]
    fn test_decrypt_scrypt() {
        use hex::FromHex;

        let secret =
            Vec::from_hex("80d3a6ed7b24dcd652949bc2f3827d2f883b3722e3120b15a93a2e0790f03829")
                .unwrap();
        let keypath = Path::new("./tests/test-keys/key-scrypt.json");
        assert_eq!(decrypt_key(&keypath, "grOQ8QDnGHvpYJf").unwrap(), secret);
        assert!(decrypt_key(&keypath, "thisisnotrandom").is_err());
    }

    #[cfg(not(feature = "starknet-compat"))]
    #[test]
    fn test_encrypt_decrypt_key() {
        use hex::FromHex;

        let secret =
            Vec::from_hex("7a28b5ba57c53603b0b07b56bba752f7784bf506fa95edc395f5cf6c7514fe9d")
                .unwrap();
        let dir = Path::new("./tests/test-keys");
        let mut rng = rand::thread_rng();
        let name = encrypt_key(&dir, &mut rng, &secret, "newpassword", None, None, None).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }

    #[cfg(feature = "starknet-compat")]
    #[test]
    fn test_encrypt_decrypt_starknet_compat_key() {
        use ark_ff::{BigInteger256, UniformRand};
        use starknet_crypto::FieldElement;

        let mut rng = rand::thread_rng();

        let account = FieldElement::from_mont(BigInteger256::rand(&mut rng).0);
        let secret = FieldElement::from_mont(BigInteger256::rand(&mut rng).0)
            .to_bytes_be()
            .to_vec();

        let dir = Path::new("./tests/test-keys");
        let name =
            encrypt_key(&dir, &mut rng, &secret, "newpassword", None, Some(account)).unwrap();

        let keypath = dir.join(&name);
        assert_eq!(decrypt_key(&keypath, "newpassword").unwrap(), secret);
        assert!(decrypt_key(&keypath, "notanewpassword").is_err());
        assert!(std::fs::remove_file(&keypath).is_ok());
    }
}
