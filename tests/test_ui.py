"""Qt interaction checks use example contacts and never access a real keyring."""
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from pathlib import Path
import tempfile
import time
import threading
import unittest

try:
    from PySide6.QtCore import Qt
    from PySide6.QtWidgets import QApplication
    from PySide6.QtTest import QTest
    from cipherdesk.ui import MainWindow, apply_theme
    HAS_QT = True
except ImportError:
    HAS_QT = False

from cipherdesk.models import Key, OperationReport, SignatureStatus
from cipherdesk.store import GroupStore


@unittest.skipUnless(HAS_QT, "Install PySide6-Essentials to run the GUI checks")
class InterfaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.application = QApplication.instance() or QApplication([])
        apply_theme(cls.application)

    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory(prefix="cipherdesk-ui-")
        self.root = Path(self.scratch.name)
        self.store = GroupStore(self.root / "config")
        self.alex = Key("A" * 40, name="Alex Sample", email="alex@example.test", can_encrypt=True,
                        can_sign=True, has_secret=True, validity="u", can_sign_secret=True, can_decrypt_secret=True)
        self.morgan = Key("B" * 40, name="Morgan Sample", email="morgan@example.test", can_encrypt=True, validity="f")
        self.store.save_group("Finance team", [self.alex.fingerprint, self.morgan.fingerprint])
        self.store.save_group("Reviewers", [self.morgan.fingerprint])
        self.window = MainWindow(store=self.store, backend=object(), auto_refresh=False)
        self.window.set_keys([self.alex, self.morgan])

    def tearDown(self):
        self.window.close()
        self.window.deleteLater()
        self.application.processEvents()
        self.scratch.cleanup()

    def _check_group(self, name):
        for i in range(self.window.send_groups.count()):
            item = self.window.send_groups.item(i)
            if item.data(Qt.ItemDataRole.UserRole) == name:
                item.setCheckState(Qt.CheckState.Checked)

    def _file(self):
        path = self.root / "example.txt"
        path.write_text("Public example content", encoding="utf-8")
        self.window._add_files(self.window.encrypt_files, [str(path)])
        return path

    def test_multiple_groups_merge_unique_fingerprints(self):
        self._check_group("Finance team")
        self._check_group("Reviewers")
        self._file()
        self.assertEqual(set(self.window._effective_recipients), {self.alex.fingerprint, self.morgan.fingerprint})
        self.assertEqual(self.window.recipient_tree.topLevelItemCount(), 2)
        self.assertTrue(self.window.encrypt_button.isEnabled())

    def test_missing_member_blocks_whole_group(self):
        self.window.set_keys([self.alex])
        self._check_group("Finance team")
        self._file()
        self.assertFalse(self.window.encrypt_button.isEnabled())
        self.assertIn("missing", self.window.encrypt_hint.text().lower())
        self.assertIn(self.morgan.fingerprint, self.window._effective_recipients)

    def test_untrusted_member_blocks_encryption(self):
        untrusted = Key(self.morgan.fingerprint, name="Morgan Sample", can_encrypt=True,
                        validity="-", reason="Certify this key in Kleopatra.")
        self.window.set_keys([self.alex, untrusted])
        self._check_group("Finance team")
        self._file()
        self.assertFalse(self.window.encrypt_button.isEnabled())
        self.assertIn("Certify", self.window.encrypt_hint.text())

    def test_group_create_edit_persist_full_fingerprints(self):
        self.window.new_group()
        self.window.group_name.setText("Legal review")
        for i in range(self.window.contact_tree.topLevelItemCount()):
            item = self.window.contact_tree.topLevelItem(i)
            if item.data(0, Qt.ItemDataRole.UserRole) == self.morgan.fingerprint:
                item.setCheckState(0, Qt.CheckState.Checked)
        self.window.save_group()
        self.assertEqual(self.store.get_group("Legal review").fingerprints, (self.morgan.fingerprint,))
        self.window.group_name.setText("Legal reviewers")
        self.window.save_group()
        self.assertEqual(self.store.get_group("Legal reviewers").fingerprints, (self.morgan.fingerprint,))
        self.assertNotIn("Legal review", [g.name for g in self.store.list_groups()])

    def test_search_keeps_hidden_selections(self):
        self.window.group_list.setCurrentRow(0)
        selected = set(self.window._selected_contacts())
        self.window.contact_search.setText("not a matching contact")
        self.assertEqual(set(self.window._selected_contacts()), selected)
        self.assertTrue(all(self.window.contact_tree.topLevelItem(i).isHidden()
                            for i in range(self.window.contact_tree.topLevelItemCount())))

    def test_self_and_signing_require_explicit_identity(self):
        self._check_group("Reviewers")
        self._file()
        self.window.include_self.setChecked(True)
        self.assertFalse(self.window.encrypt_button.isEnabled())
        self.window.own_key.setCurrentIndex(1)
        self.assertTrue(self.window.encrypt_button.isEnabled())
        self.assertIn(self.alex.fingerprint, self.window._effective_recipients)
        self.window.sign_files.setChecked(True)
        self.assertFalse(self.window.encrypt_button.isEnabled())
        self.window.signer_key.setCurrentIndex(1)
        self.assertTrue(self.window.encrypt_button.isEnabled())

    def test_signatures_distinguish_validity_from_trust(self):
        unsigned = OperationReport(self.root / "plain.txt", signatures=(SignatureStatus("unsigned", False),), unsigned=True)
        self.assertIn("sender not authenticated", self.window._signature_text(unsigned))
        valid = OperationReport(self.root / "plain.txt", signatures=(SignatureStatus("valid", True, signer="Example sender", trust="unknown"),))
        self.assertIn("identity not trusted", self.window._signature_text(valid))

    def test_duplicate_file_addition_does_not_duplicate_job(self):
        path = self._file()
        self.window._add_files(self.window.encrypt_files, [str(path)])
        self.assertEqual(self.window.encrypt_files.count(), 1)

    def test_encrypt_action_runs_in_worker_and_publishes_result(self):
        calls = []
        main_thread = threading.get_ident()
        class FakeBackend:
            def encrypt_file(backend, source, output, recipients, **options):
                calls.append((threading.get_ident(), tuple(recipients), options))
                target = Path(output) / (Path(source).name + ".gpg")
                target.write_bytes(b"Example ciphertext placeholder for interface testing")
                return OperationReport(target, encrypted_for=tuple(recipients))
        self.window.backend = FakeBackend()
        self._check_group("Finance team")
        source = self._file()
        original = source.read_bytes()
        self.window.encrypt_output.setText(str(self.root))
        self.window.encrypt_button.click()
        deadline = time.monotonic() + 3
        while self.window._busy and time.monotonic() < deadline:
            QTest.qWait(10)
            self.application.processEvents()
        self.assertFalse(self.window._busy, "Background operation did not finish")
        self.assertEqual(len(calls), 1)
        self.assertNotEqual(calls[0][0], main_thread)
        self.assertEqual(set(calls[0][1]), {self.alex.fingerprint, self.morgan.fingerprint})
        self.assertTrue((self.root / "example.txt.gpg").exists())
        self.assertEqual(source.read_bytes(), original)
        self.assertEqual(self.window.results_tree.topLevelItemCount(), 1)
        self.assertIn("Encrypted 1 file", self.window.result_banner.text())


if __name__ == "__main__":
    unittest.main()
