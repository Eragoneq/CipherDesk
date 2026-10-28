"""Persistence tests cover data loss and silently incomplete recipient groups."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from cipherdesk.models import Key, StoreError
from cipherdesk.store import GroupStore


ALICE = "A1" * 20
BOB = "B2" * 20
CAROL = "C3" * 20


class GroupStoreTests(unittest.TestCase):
    def setUp(self):
        self.work_parent = Path(__file__).resolve().parents[1] / ".test-work"
        self.work_parent.mkdir(parents=True, exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(prefix="groups-", dir=self.work_parent)
        self.directory = Path(self.temp.name)
        self.store = GroupStore(self.directory)

    def tearDown(self):
        self.temp.cleanup()
        try:
            self.work_parent.rmdir()
        except OSError:
            pass

    def test_saved_group_reopens_with_complete_normalized_fingerprints(self):
        self.store.save_group("  Finance  ", [ALICE.lower(), " ".join([BOB[:20], BOB[20:]]), ALICE])
        self.store.update_settings(output_dir="C:/Local test output")
        reopened = GroupStore(self.directory)
        groups = reopened.list_groups()
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].name, "Finance")
        self.assertEqual(groups[0].fingerprints, (ALICE, BOB))
        self.assertEqual(reopened.get_settings()["output_dir"], "C:/Local test output")
        saved = json.loads((self.directory / "groups.json").read_text(encoding="utf-8"))
        self.assertEqual(saved["version"], 1)
        self.assertEqual(saved["groups"][0]["fingerprints"], [ALICE, BOB])

    def test_case_insensitive_duplicate_name_cannot_replace_existing_group(self):
        self.store.save_group("Finance", [ALICE])
        before = self.store.path.read_bytes()
        with self.assertRaises(StoreError):
            self.store.save_group("finance", [BOB])
        self.assertEqual(self.store.path.read_bytes(), before)

    def test_group_rename_updates_only_requested_group(self):
        self.store.save_group("Finance", [ALICE])
        self.store.save_group("Legal", [BOB])
        self.store.save_group("Accounts", [ALICE, CAROL], original_name="Finance")
        groups = {group.name: group.fingerprints for group in GroupStore(self.directory).list_groups()}
        self.assertEqual(groups, {"Accounts": (ALICE, CAROL), "Legal": (BOB,)})

    def test_missing_member_never_resolves_to_a_smaller_recipient_subset(self):
        self.store.save_group("Finance", [ALICE, BOB])
        alice = Key(ALICE, name="Alice", can_encrypt=True, validity="f")
        with self.assertRaises(StoreError) as caught:
            self.store.resolve_group("Finance", [alice])
        self.assertEqual(caught.exception.code, "missing_key")
        self.assertEqual(self.store.list_groups()[0].fingerprints, (ALICE, BOB))

    def test_unusable_group_member_aborts_resolution(self):
        self.store.save_group("Finance", [ALICE, BOB])
        keys = [Key(ALICE, can_encrypt=True, validity="f"),
                Key(BOB, can_encrypt=False, validity="r", reason="Revoked")]
        with self.assertRaises(StoreError) as caught:
            self.store.resolve_group("Finance", keys)
        self.assertEqual(caught.exception.code, "unusable_key")

    def test_unverified_group_member_aborts_resolution(self):
        self.store.save_group("Finance", [ALICE, BOB])
        keys = [Key(ALICE, can_encrypt=True, validity="f"),
                Key(BOB, can_encrypt=True, validity="q")]
        with self.assertRaises(StoreError):
            self.store.resolve_group("Finance", keys)

    def test_complete_group_resolves_every_member_in_saved_order(self):
        self.store.save_group("Finance", [BOB, ALICE])
        keys = [Key(ALICE, can_encrypt=True, validity="f"), Key(BOB, can_encrypt=True, validity="f")]
        result = self.store.resolve_group("Finance", keys)
        self.assertEqual([key.fingerprint for key in result], [BOB, ALICE])

    def test_corrupted_json_is_reported_and_never_replaced(self):
        corrupted = b'{"version":1,"groups":[ interrupted write'
        self.store.path.write_bytes(corrupted)
        for action in (self.store.list_groups,
                       lambda: self.store.save_group("Replacement", [ALICE]),
                       lambda: self.store.update_settings(output_dir="somewhere")):
            with self.subTest(action=action):
                with self.assertRaises(StoreError) as caught:
                    action()
                self.assertEqual(caught.exception.code, "invalid_config")
                self.assertEqual(self.store.path.read_bytes(), corrupted)

    def test_invalid_stored_schema_fails_closed(self):
        invalid_documents = [
            {"version": 999, "groups": [], "settings": {}},
            {"version": 1, "groups": {}, "settings": {}},
            {"version": 1, "groups": [], "settings": []},
            {"version": 1, "groups": [{"name": "Empty", "fingerprints": []}], "settings": {}},
            {"version": 1, "groups": [{"name": "Short IDs", "fingerprints": ["DEADBEEF"]}], "settings": {}},
            {"version": 1, "groups": [
                {"name": "Team", "fingerprints": [ALICE]},
                {"name": "team", "fingerprints": [BOB]}], "settings": {}},
        ]
        for document in invalid_documents:
            with self.subTest(document=document):
                contents = json.dumps(document).encode("utf-8")
                self.store.path.write_bytes(contents)
                with self.assertRaises(StoreError):
                    self.store.list_groups()
                self.assertEqual(self.store.path.read_bytes(), contents)

    def test_invalid_user_group_selection_does_not_mutate_existing_data(self):
        self.store.save_group("Existing", [ALICE])
        before = self.store.path.read_bytes()
        for name, members in (("Empty", []), ("", [ALICE]), ("Bad\nName", [ALICE]),
                              ("Short ID", ["DEADBEEF"]), ("Email", ["bob@example.invalid"])):
            with self.subTest(name=name):
                with self.assertRaises(StoreError):
                    self.store.save_group(name, members)
                self.assertEqual(self.store.path.read_bytes(), before)

    def test_failed_atomic_replace_preserves_prior_groups_and_cleans_temporary_file(self):
        self.store.save_group("Existing", [ALICE])
        before = self.store.path.read_bytes()
        with patch("cipherdesk.store.os.replace", side_effect=OSError("Simulated disk failure")):
            with self.assertRaises(StoreError):
                self.store.save_group("New", [BOB])
        self.assertEqual(self.store.path.read_bytes(), before)
        self.assertEqual([path.name for path in self.directory.iterdir()], ["groups.json"])

    def test_delete_reopens_without_deleted_group(self):
        self.store.save_group("Finance", [ALICE])
        self.store.save_group("Legal", [BOB])
        self.store.delete_group("finance")
        self.assertEqual([group.name for group in GroupStore(self.directory).list_groups()], ["Legal"])

    def test_settings_are_copied_so_caller_cannot_mutate_saved_data(self):
        settings = {"recent": ["one"]}
        self.store.update_settings(**settings)
        settings["recent"].append("two")
        loaded = self.store.get_settings()
        loaded["recent"].append("three")
        self.assertEqual(self.store.get_settings()["recent"], ["one"])


if __name__ == "__main__":
    unittest.main()
