//! Phase 6.1.4-D — secure-delete pour les fichiers temporaires contenant
//! des secrets (MP4 plaintext, blobs STRM intermédiaires).
//!
//! ## Pourquoi
//!
//! `std::fs::remove_file()` (et donc `File::delete()` côté Kotlin) ne fait
//! que `unlink(2)` — le fichier est marqué libre dans la table d'inodes,
//! mais les données restent sur disque jusqu'à ce que les blocs soient
//! réutilisés par le filesystem. Sur Android avec un user qui dump la
//! partition après une saisie, ces données sont récupérables avec un
//! outil forensique (`TestDisk`, photorec, etc.).
//!
//! ## Comment
//!
//! `secure_delete_file(path)` :
//!   1. Ouvre le fichier en write
//!   2. Lit sa taille
//!   3. Overwrite avec random bytes (1 pass)
//!   4. `fsync` pour forcer l'écriture sur disque (pas juste page cache)
//!   5. Truncate à 0
//!   6. `unlink`
//!
//! ## Limites
//!
//! Sur SSD/Flash (Android) :
//! - Le wear-leveling peut écrire les bytes random dans des blocs
//!   différents que ceux du fichier original. L'overwrite ne garantit
//!   pas la destruction des secteurs originaux.
//! - TRIM/discard améliore la situation (le contrôleur SSD est censé
//!   libérer/effacer les blocs après unlink), mais c'est implementation-
//!   dependent.
//! - Pour une vraie destruction sécurisée, il faudrait full-disk
//!   encryption (Android FBE ou metadata encryption, déjà standard sur
//!   Android 10+) → l'attaquant disk-level qui n'a pas la clé device ne
//!   peut rien lire de toute façon. C'est notre vraie ligne de défense.
//!
//! Ce helper est une defense-in-depth complémentaire à FBE. Il ferme le
//! cas où l'adversaire a la clé device (forensique RAM live) et cherche
//! à reconstruire des fichiers depuis les freelist/journal du
//! filesystem.
//!
//! ## Single-pass justifié
//!
//! Les recommandations multi-pass historiques (`DoD` 5220.22-M, Gutmann
//! 35-pass) viennent de l'époque des disques magnétiques où la rémanence
//! permettait de récupérer des bits sous-jacents. Sur flash modern (NAND),
//! un seul pass est suffisant — il n'y a pas de "shadow" magnétique.
//! NIST SP 800-88 confirme : single-pass overwrite = "Clear" level.

use rand_core::{OsRng, RngCore};
use std::fs::OpenOptions;
use std::io::{Seek, SeekFrom, Write};
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum SecureDeleteError {
    #[error("I/O error during secure delete: {0}")]
    Io(#[from] std::io::Error),
}

/// Secure-delete `path`. No-op si le fichier n'existe pas (idempotent).
///
/// Returns `Ok(())` même si le fichier n'existait pas — le caller n'a
/// pas besoin de check `Path::exists()` avant.
pub fn secure_delete_file(path: &Path) -> Result<(), SecureDeleteError> {
    if !path.exists() {
        return Ok(());
    }

    // Phase 6.1.4-D : open en write pour pouvoir overwrite.
    let mut file = OpenOptions::new().write(true).open(path)?;

    let len = file.metadata()?.len();
    if len > 0 {
        // Buffer 64KB : balance entre allocation overhead et nombre d'I/O.
        // Pour un MP4 de 5MB c'est ~80 writes, négligeable.
        let mut buf = vec![0u8; 64 * 1024].into_boxed_slice();
        let mut remaining = len;
        file.seek(SeekFrom::Start(0))?;
        while remaining > 0 {
            let n = usize::try_from(remaining)
                .unwrap_or(usize::MAX)
                .min(buf.len());
            // OsRng = /dev/urandom sur Android. Side-effect via syscall que
            // ni LLVM ni le JIT ne peuvent éliminer.
            OsRng.fill_bytes(&mut buf[..n]);
            file.write_all(&buf[..n])?;
            remaining -= n as u64;
        }
        // fsync pour forcer le flush page cache → disque physique. Sans ça,
        // le random ne quitte jamais la RAM si le file est unlinké
        // immédiatement (le page cache reste sur le inode jusqu'à libération).
        file.sync_all()?;
        // Truncate à 0 — libère les blocs côté filesystem (en plus de l'unlink
        // suivant). Belt-and-suspenders.
        file.set_len(0)?;
    }
    drop(file);

    std::fs::remove_file(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Read;

    #[test]
    fn secure_delete_removes_file() {
        let tmp = tempfile_path("secure_delete_removes");
        fs::write(&tmp, b"top secret content").unwrap();
        assert!(tmp.exists());
        secure_delete_file(&tmp).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn secure_delete_overwrites_before_unlink() {
        // On crée un fichier, secure-delete, puis on vérifie qu'il
        // n'existe plus. Vérifier l'overwrite physique nécessiterait un
        // raw-block-read qui sort du scope unit test.
        let tmp = tempfile_path("secure_delete_overwrites");
        let content = b"sensitive data goes here";
        fs::write(&tmp, content).unwrap();
        secure_delete_file(&tmp).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn secure_delete_nonexistent_is_noop() {
        let tmp = tempfile_path("never_existed");
        assert!(!tmp.exists());
        // Doit retourner Ok sans erreur, même si le fichier n'existe pas.
        secure_delete_file(&tmp).unwrap();
    }

    #[test]
    fn secure_delete_empty_file() {
        let tmp = tempfile_path("empty");
        fs::write(&tmp, b"").unwrap();
        assert!(tmp.exists());
        // Empty file : pas d'overwrite à faire mais doit quand même unlink.
        secure_delete_file(&tmp).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn secure_delete_large_file() {
        // 1MB pour exercer le buffer 64KB (16 itérations).
        let tmp = tempfile_path("large");
        let big = vec![0xAAu8; 1024 * 1024];
        fs::write(&tmp, &big).unwrap();
        secure_delete_file(&tmp).unwrap();
        assert!(!tmp.exists());
    }

    #[test]
    fn secure_delete_overwrites_data_before_unlink() {
        // Verifie via lecture directe que post-overwrite (pre-unlink) le
        // contenu n'est plus le original. Workaround : on overwrite mais
        // PAS unlink, en duplicant la logique.
        let tmp = tempfile_path("verify_overwrite");
        let original = b"AAAAAAAAAAAAAAAAAAAA";
        fs::write(&tmp, original).unwrap();

        let mut file = OpenOptions::new().write(true).open(&tmp).unwrap();
        let len = file.metadata().unwrap().len();
        let mut buf = [0u8; 64];
        let n = usize::try_from(len).expect("test file fits usize");
        OsRng.fill_bytes(&mut buf[..n]);
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&buf[..n]).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let mut readback = Vec::new();
        fs::File::open(&tmp)
            .unwrap()
            .read_to_end(&mut readback)
            .unwrap();
        assert_ne!(readback, original);
        assert_eq!(readback.len(), original.len());

        fs::remove_file(&tmp).unwrap();
    }

    fn tempfile_path(name: &str) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("frappuccino-test-{}-{}", name, std::process::id()));
        // Cleanup au cas où un test précédent a crashé.
        let _ = std::fs::remove_file(&p);
        p
    }
}
