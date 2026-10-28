"""Security behavior against real GnuPG, never the user's normal keyring.

Run from the project folder with ``python -m unittest discover -s tests -v``.
Set GPG_PATH if GnuPG is not on PATH or in a standard Gpg4win location.
The suite generates disposable, passwordless keys under .test-work and removes
them afterwards. Production keys and the default GNUPGHOME are never accessed.
"""

from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from cipherdesk.crypto import GPGBackend
from cipherdesk.models import CipherDeskError


def find_gpg() -> str | None:
    configured = os.environ.get("GPG_PATH")
    if configured:
        return configured if Path(configured).is_file() else None
    found = shutil.which("gpg")
    if found:
        return found
    for base in (os.environ.get("ProgramFiles(x86)"), os.environ.get("ProgramFiles")):
        if base:
            candidate = Path(base) / "GnuPG" / "bin" / "gpg.exe"
            if candidate.is_file():
                return str(candidate)
    return None


GPG_PATH = find_gpg()


@unittest.skipUnless(GPG_PATH, "Install GnuPG/Gpg4win or set GPG_PATH for integration tests")
class GnuPGIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gpg_path = str(GPG_PATH)
        cls.work_parent = Path(__file__).resolve().parents[1] / ".test-work"
        cls.work_parent.mkdir(parents=True, exist_ok=True)
        cls.temp = tempfile.TemporaryDirectory(prefix="gnupg-", dir=cls.work_parent)
        cls.root = Path(cls.temp.name)
        cls.homes: list[Path] = []
        cls.master = cls._new_home("fixture-issuer")
        cls.identities: dict[str, str] = {}

        # Nothing generated here is a real identity or an enduring credential.
        for name in ("Alice", "Bob", "Carol", "Outsider"):
            uid = f"CipherDesk Test {name} <{name.lower()}@example.invalid>"
            cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-generate-key", uid, "ed25519", "sign", "0")
            fingerprint = cls._primary_fingerprint(cls.master, uid)
            cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                     "--quick-add-key", fingerprint, "cv25519", "encr", "0")
            cls.identities[name] = fingerprint

        signing_only_uid = "CipherDesk Test Sign Only <sign-only@example.invalid>"
        cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-generate-key", signing_only_uid, "ed25519", "sign", "0")
        cls.signing_only = cls._primary_fingerprint(cls.master, signing_only_uid)

        # Expiration and revocation have distinct GnuPG semantics; check both.
        expired_uid = "CipherDesk Test Expired <expired@example.invalid>"
        fake_time = "20200101T000000"
        cls._gpg(cls.master, "--faked-system-time", fake_time,
                 "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-generate-key", expired_uid, "ed25519", "sign", "1d")
        cls.expired = cls._primary_fingerprint(cls.master, expired_uid)
        cls._gpg(cls.master, "--faked-system-time", fake_time,
                 "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-add-key", cls.expired, "cv25519", "encr", "1d")

        revoked_uid = "CipherDesk Test Revoked <revoked@example.invalid>"
        cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-generate-key", revoked_uid, "ed25519", "sign", "0")
        cls.revoked = cls._primary_fingerprint(cls.master, revoked_uid)
        cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                 "--quick-add-key", cls.revoked, "cv25519", "encr", "0")
        revocation = (cls.master / "openpgp-revocs.d" / f"{cls.revoked}.rev").read_bytes()
        marker = b":-----BEGIN PGP PUBLIC KEY BLOCK-----"
        if marker not in revocation:
            raise AssertionError("GnuPG did not create the disposable revocation fixture")
        revocation = revocation[revocation.index(marker) + 1:]
        cls._gpg(cls.master, "--import", input_data=revocation)

        public_bundle = cls._gpg(cls.master, "--export").stdout
        ownertrust = "".join(f"{fingerprint}:6:\n" for fingerprint in cls.identities.values()).encode()
        cls.user_homes: dict[str, Path] = {}
        for name, fingerprint in cls.identities.items():
            home = cls._new_home(name.lower())
            cls._gpg(home, "--import", input_data=public_bundle)
            secret = cls._gpg(cls.master, "--pinentry-mode", "loopback", "--passphrase", "",
                              "--export-secret-keys", fingerprint).stdout
            cls._gpg(home, "--import", input_data=secret)
            cls._gpg(home, "--import-ownertrust", input_data=ownertrust)
            cls.user_homes[name] = home

        cls.untrusted_home = cls._new_home("untrusted-public-only")
        cls._gpg(cls.untrusted_home, "--import", input_data=public_bundle)
        cls.backends = {
            name: GPGBackend(gpg_path=cls.gpg_path, homedir=home, timeout=60)
            for name, home in cls.user_homes.items()
        }

    @classmethod
    def tearDownClass(cls):
        # Windows agents retain open handles; stop only our disposable agents.
        gpgconf = Path(cls.gpg_path).with_name("gpgconf.exe" if os.name == "nt" else "gpgconf")
        if gpgconf.is_file():
            for home in cls.homes:
                subprocess.run([str(gpgconf), "--homedir", str(home), "--kill", "gpg-agent"],
                               capture_output=True, timeout=20, check=False)
        cls.temp.cleanup()
        try:
            cls.work_parent.rmdir()
        except OSError:
            pass

    @classmethod
    def _new_home(cls, name: str) -> Path:
        home = cls.root / name
        home.mkdir(mode=0o700)
        cls.homes.append(home)
        return home

    @classmethod
    def _gpg(cls, home: Path, *arguments: str, input_data: bytes | None = None):
        command = [cls.gpg_path, "--homedir", str(home), "--batch", "--yes", *arguments]
        result = subprocess.run(command, input=input_data, capture_output=True, timeout=60)
        if result.returncode:
            raise AssertionError(
                f"Disposable fixture command failed ({result.returncode}): {arguments!r}\n"
                + result.stderr.decode("utf-8", errors="replace")
            )
        return result

    @classmethod
    def _primary_fingerprint(cls, home: Path, uid: str) -> str:
        listing = cls._gpg(home, "--with-colons", "--list-keys", uid).stdout.decode()
        return next(line.split(":")[9] for line in listing.splitlines() if line.startswith("fpr:"))

    def setUp(self):
        self.case_temp = tempfile.TemporaryDirectory(prefix="case-", dir=self.root)
        self.case = Path(self.case_temp.name)
        self.source = self.case / "sample document.txt"
        self.content = b"CipherDesk disposable public test content.\nSecond line.\n"
        self.source.write_bytes(self.content)
        self.out = self.case / "encrypted"
        self.out.mkdir()

    def tearDown(self):
        self.case_temp.cleanup()

    def encrypt(self, recipients=None, signer=True):
        if recipients is None:
            recipients = [self.identities["Bob"], self.identities["Carol"]]
        return self.backends["Alice"].encrypt_file(
            self.source, self.out, recipients,
            signer_fingerprint=self.identities["Alice"] if signer else None,
        )

    def new_output_dir(self, name: str) -> Path:
        directory = self.case / name
        directory.mkdir()
        return directory

    def test_key_listing_rejects_expired_and_revoked_encryption_keys(self):
        keys = {key.fingerprint: key for key in self.backends["Alice"].list_keys()}
        self.assertTrue(keys[self.identities["Bob"]].can_encrypt)
        self.assertTrue(keys[self.identities["Alice"]].has_secret)
        self.assertFalse(keys[self.expired].can_encrypt)
        self.assertFalse(keys[self.revoked].can_encrypt)
        for unusable in (self.expired, self.revoked):
            with self.subTest(fingerprint=unusable):
                with self.assertRaises(CipherDeskError):
                    self.encrypt([self.identities["Bob"], unusable])
                self.assertEqual(list(self.out.iterdir()), [])

    def test_two_recipients_can_decrypt_signed_file_and_source_is_unchanged(self):
        encrypted = self.encrypt()
        self.assertTrue(Path(encrypted.output_path).is_file())
        self.assertEqual(self.source.read_bytes(), self.content)
        for name in ("Bob", "Carol"):
            with self.subTest(recipient=name):
                target = self.new_output_dir(f"decrypted-{name}")
                result = self.backends[name].decrypt_file(encrypted.output_path, target)
                self.assertEqual(Path(result.output_path).read_bytes(), self.content)
                self.assertFalse(result.unsigned)
                self.assertTrue(result.signatures)
                self.assertTrue(all(signature.valid for signature in result.signatures))

    def test_unselected_private_key_cannot_decrypt_or_create_plaintext(self):
        encrypted = self.encrypt()
        target = self.new_output_dir("wrong-recipient")
        with self.assertRaises(CipherDeskError):
            self.backends["Outsider"].decrypt_file(encrypted.output_path, target)
        self.assertEqual(list(target.iterdir()), [])

    def test_unknown_member_aborts_entire_encryption(self):
        with self.assertRaises(CipherDeskError):
            self.encrypt([self.identities["Bob"], "A" * 40])
        self.assertEqual(list(self.out.iterdir()), [])
        self.assertEqual(self.source.read_bytes(), self.content)

    def test_unverified_recipient_is_rejected(self):
        backend = GPGBackend(gpg_path=self.gpg_path, homedir=self.untrusted_home, timeout=60)
        with self.assertRaises(CipherDeskError):
            backend.encrypt_file(self.source, self.out, [self.identities["Bob"]])
        self.assertEqual(list(self.out.iterdir()), [])

    def test_include_self_allows_sender_to_decrypt(self):
        result = self.backends["Alice"].encrypt_file(
            self.source, self.out, [self.identities["Bob"]],
            include_self_fingerprint=self.identities["Alice"],
        )
        target = self.new_output_dir("sender-copy")
        decrypted = self.backends["Alice"].decrypt_file(result.output_path, target)
        self.assertEqual(Path(decrypted.output_path).read_bytes(), self.content)

    def test_include_self_requires_secret_encryption_key(self):
        backend = GPGBackend(gpg_path=self.gpg_path, homedir=self.master, timeout=60)
        # A secret signing key alone cannot recover an encrypted sender copy.
        keys = {key.fingerprint: key for key in backend.list_keys()}
        self.assertTrue(keys[self.signing_only].has_secret)
        self.assertFalse(keys[self.signing_only].can_decrypt_secret)
        with self.assertRaises(CipherDeskError):
            backend.encrypt_file(self.source, self.out, [self.identities["Bob"]],
                                 include_self_fingerprint=self.signing_only)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_unsigned_file_is_identified_explicitly(self):
        encrypted = self.encrypt(signer=False)
        result = self.backends["Bob"].decrypt_file(encrypted.output_path, self.new_output_dir("unsigned"))
        self.assertTrue(result.unsigned)
        self.assertEqual(Path(result.output_path).read_bytes(), self.content)

    def test_signature_required_rejects_unsigned_file_without_output(self):
        encrypted = self.encrypt(signer=False)
        target = self.new_output_dir("unsigned-rejected")
        with self.assertRaises(CipherDeskError) as caught:
            self.backends["Bob"].decrypt_file(encrypted.output_path, target, require_signature=True)
        self.assertEqual(caught.exception.code, "signature_required")
        self.assertEqual(list(target.iterdir()), [])

    def test_signature_required_accepts_trusted_signed_file(self):
        encrypted = self.encrypt()
        target = self.new_output_dir("trusted-signature-required")
        result = self.backends["Bob"].decrypt_file(encrypted.output_path, target, require_signature=True)
        self.assertEqual(Path(result.output_path).read_bytes(), self.content)
        self.assertTrue(all(signature.valid and signature.trusted for signature in result.signatures))

    def test_signature_required_rejects_valid_signature_from_unverified_sender(self):
        encrypted = self.encrypt()
        home = self._new_home("unverified-sender-receiver")
        self._gpg(home, "--import", input_data=self._gpg(self.master, "--export", self.identities["Alice"]).stdout)
        bob_secret = self._gpg(self.master, "--pinentry-mode", "loopback", "--passphrase", "",
                               "--export-secret-keys", self.identities["Bob"]).stdout
        self._gpg(home, "--import", input_data=bob_secret)
        self._gpg(home, "--import-ownertrust", input_data=f"{self.identities['Bob']}:6:\n".encode())
        backend = GPGBackend(gpg_path=self.gpg_path, homedir=home, timeout=60)
        target = self.new_output_dir("unverified-sender-rejected")
        with self.assertRaises(CipherDeskError) as caught:
            backend.decrypt_file(encrypted.output_path, target, require_signature=True)
        self.assertEqual(caught.exception.code, "signature_required")
        self.assertEqual(list(target.iterdir()), [])

    def test_ciphertext_tampering_releases_no_plaintext(self):
        encrypted = self.encrypt()
        packet = bytearray(Path(encrypted.output_path).read_bytes())
        packet[-8] ^= 0x40
        tampered = self.case / "tampered.gpg"
        tampered.write_bytes(packet)
        target = self.new_output_dir("tampered-output")
        with self.assertRaises(CipherDeskError):
            self.backends["Bob"].decrypt_file(tampered, target)
        self.assertEqual(list(target.iterdir()), [])

    def test_bad_signature_inside_valid_encryption_releases_no_plaintext(self):
        signed = self.case / "signed-packets.pgp"
        self._gpg(self.user_homes["Alice"], "--pinentry-mode", "loopback", "--passphrase", "",
                  "--compress-algo", "none", "--local-user", self.identities["Alice"],
                  "--output", str(signed), "--sign", str(self.source))
        packets = signed.read_bytes()
        self.assertEqual(packets.count(self.content), 1, "Fixture requires an uncompressed literal packet")
        altered = self.content.replace(b"disposable", b"DISPOSABLE", 1)
        self.assertEqual(len(altered), len(self.content))
        signed.write_bytes(packets.replace(self.content, altered, 1))
        encrypted = self.case / "bad-signature.gpg"
        # --no-literal preserves the signed packet sequence inside encryption;
        # the enclosing encryption remains valid while the signature is bad.
        self._gpg(self.user_homes["Alice"], "--trust-model", "always", "--compress-algo", "none",
                  "--no-literal", "--recipient", self.identities["Bob"],
                  "--output", str(encrypted), "--encrypt", str(signed))
        # Verify this fixture reaches real signature verification. GnuPG may
        # stop before DECRYPTION_OKAY when it encounters the bad signature.
        probe = subprocess.run(
            [self.gpg_path, "--homedir", str(self.user_homes["Bob"]), "--batch", "--no-tty",
             "--status-fd", "2", "--decrypt", str(encrypted)],
            capture_output=True, timeout=60,
        )
        self.assertEqual(probe.stdout, altered)
        self.assertIn(b"[GNUPG:] BADSIG", probe.stderr)
        target = self.new_output_dir("bad-signature-output")
        with self.assertRaises(CipherDeskError) as caught:
            self.backends["Bob"].decrypt_file(encrypted, target)
        self.assertEqual(caught.exception.code, "signature_failed")
        self.assertEqual(list(target.iterdir()), [])

    def test_local_gpg_config_cannot_add_an_unselected_recipient(self):
        config = self.user_homes["Alice"] / "gpg.conf"
        config.write_text(f"encrypt-to {self.identities['Outsider']}\n", encoding="ascii")
        try:
            encrypted = self.encrypt([self.identities["Bob"]])
            target = self.new_output_dir("hidden-config-recipient")
            with self.assertRaises(CipherDeskError):
                self.backends["Outsider"].decrypt_file(encrypted.output_path, target)
            self.assertEqual(list(target.iterdir()), [])
        finally:
            config.unlink(missing_ok=True)

    def test_embedded_pgp_filename_cannot_choose_output_path(self):
        encrypted = self.case / "transport.gpg"
        self._gpg(self.user_homes["Alice"], "--trust-model", "always",
                  "--set-filename", "../../escaped-document.txt",
                  "--recipient", self.identities["Bob"],
                  "--output", str(encrypted), "--encrypt", str(self.source))
        target = self.new_output_dir("safe-output")
        result = self.backends["Bob"].decrypt_file(encrypted, target)
        self.assertEqual(Path(result.output_path).parent, target)
        self.assertEqual(Path(result.output_path).name, "transport")
        self.assertEqual(Path(result.output_path).read_bytes(), self.content)
        self.assertFalse((self.case / "escaped-document.txt").exists())

    def test_missing_signer_public_key_releases_no_plaintext(self):
        encrypted = self.encrypt()
        home = self._new_home("missing-signer-public-key")
        bob_secret = self._gpg(self.master, "--pinentry-mode", "loopback", "--passphrase", "",
                               "--export-secret-keys", self.identities["Bob"]).stdout
        self._gpg(home, "--import", input_data=bob_secret)
        backend = GPGBackend(gpg_path=self.gpg_path, homedir=home, timeout=60)
        target = self.new_output_dir("unknown-signer-output")
        with self.assertRaises(CipherDeskError):
            backend.decrypt_file(encrypted.output_path, target)
        self.assertEqual(list(target.iterdir()), [])

    def test_existing_ciphertext_is_never_overwritten(self):
        first = self.encrypt()
        destination = Path(first.output_path)
        original_ciphertext = destination.read_bytes()
        self.source.write_bytes(b"A different document that has the same filename.\n")
        try:
            second = self.encrypt()
        except CipherDeskError:
            pass
        else:
            self.assertNotEqual(Path(second.output_path), destination)
        self.assertEqual(destination.read_bytes(), original_ciphertext)

    def test_existing_plaintext_is_never_overwritten(self):
        encrypted = self.encrypt()
        target = self.new_output_dir("existing-plaintext")
        existing = target / self.source.name
        existing.write_bytes(b"Keep this existing local file.")
        try:
            result = self.backends["Bob"].decrypt_file(encrypted.output_path, target)
        except CipherDeskError:
            pass
        else:
            self.assertNotEqual(Path(result.output_path), existing)
        self.assertEqual(existing.read_bytes(), b"Keep this existing local file.")

    def test_empty_recipient_selection_is_rejected(self):
        with self.assertRaises(CipherDeskError):
            self.encrypt([])
        self.assertEqual(list(self.out.iterdir()), [])

    def test_directory_input_is_rejected_without_output(self):
        directory = self.new_output_dir("not-a-file")
        with self.assertRaises(CipherDeskError):
            self.backends["Alice"].encrypt_file(directory, self.out, [self.identities["Bob"]])
        self.assertEqual(list(self.out.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
