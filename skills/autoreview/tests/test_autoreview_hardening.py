#!/usr/bin/env python3
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
import re
import runpy
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "autoreview"
PRIVATE_KEY_BEGIN_TEXT = "BEGIN " + "PRIVATE KEY"
RSA_PRIVATE_KEY_BEGIN_TEXT = "BEGIN RSA " + "PRIVATE KEY"


def load_helper() -> dict[str, object]:
    return runpy.run_path(str(SCRIPT), run_name="autoreview_under_test")


def git(repo: Path, *args: str) -> str:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Autoreview Test",
            "GIT_AUTHOR_EMAIL": "autoreview@example.invalid",
            "GIT_COMMITTER_NAME": "Autoreview Test",
            "GIT_COMMITTER_EMAIL": "autoreview@example.invalid",
        }
    )
    result = subprocess.run(
        ["git", *args],
        cwd=repo,
        env=env,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return result.stdout


def init_repo(tempdir: Path) -> Path:
    repo = tempdir / "repo"
    repo.mkdir()
    git(repo, "init", "-q")
    git(repo, "config", "user.name", "Autoreview Test")
    git(repo, "config", "user.email", "autoreview@example.invalid")
    return repo


def realistic_secret_value() -> str:
    return "A7f9K2m4Q8v6" + "N3x5R1p0T9z8"


class AutoreviewHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self.helper = load_helper()

    def test_powershell_harness_exposes_runnable_engines_only(self) -> None:
        harness = SCRIPT.with_name("test-review-harness.ps1").read_text(encoding="utf-8")

        self.assertIn("[ValidateSet('codex', 'claude', 'pi')]", harness)
        for disabled_engine in ("droid", "copilot", "opencode", "cursor"):
            self.assertNotIn(f"'{disabled_engine}'", harness)

    def test_local_bundle_blocks_sensitive_untracked_file(self) -> None:
        for rel in (".env", "tokens/session.dat", "secrets/local.py"):
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as tempdir:
                repo = init_repo(Path(tempdir))
                path = repo / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("placeholder=true\n", encoding="utf-8")

                with self.assertRaisesRegex(SystemExit, "untracked sensitive files"):
                    self.helper["local_bundle"](repo)

    def test_local_bundle_marks_untracked_binary_input_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "image.bin").write_bytes(b"\x89PNG\r\n\0binary-content")

            bundle, truncated = self.helper["local_bundle"](repo)

            self.assertIn(
                '# Untracked File\npath: "image.bin"\n'
                'source-line 1: "[binary file omitted]"',
                bundle,
            )
            self.assertTrue(truncated)

    def test_local_bundle_rejects_non_utf8_untracked_text(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "latin.py").write_bytes(b"print('caf\xe9')\n")

            with self.assertRaisesRegex(SystemExit, "non-UTF-8 file"):
                self.helper["local_bundle"](repo)

    def test_local_bundle_uses_validated_untracked_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "notes.txt").write_text("review me\n", encoding="utf-8")
            original_read_prefix = self.helper["read_prefix"]
            reads = 0

            def read_once(path: Path, limit: int) -> tuple[bytes, bool]:
                nonlocal reads
                reads += 1
                if reads > 1:
                    raise AssertionError("untracked file was reopened after validation")
                return original_read_prefix(path, limit)

            with mock.patch.dict(
                self.helper["local_bundle"].__globals__,
                {"read_prefix": read_once},
            ):
                bundle, truncated = self.helper["local_bundle"](repo)

            expected_record = json.dumps("review me" + os.linesep)
            self.assertIn(
                '# Untracked File\npath: "notes.txt"\n'
                f"source-line 1: {expected_record}",
                bundle,
            )
            self.assertFalse(truncated)
            self.assertEqual(reads, 1)

    def test_tracked_binary_changes_are_blocked_in_all_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            binary = repo / "artifact.bin"
            binary.write_bytes(b"\0base")
            git(repo, "add", "artifact.bin")
            git(repo, "commit", "-q", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()

            binary.write_bytes(b"\0changed")
            git(repo, "add", "artifact.bin")
            with self.assertRaisesRegex(SystemExit, "refusing binary changes"):
                self.helper["local_bundle"](repo)

            git(repo, "commit", "-q", "-m", "binary change")
            with self.assertRaisesRegex(SystemExit, "refusing binary changes"):
                self.helper["commit_bundle"](repo, "HEAD")
            with self.assertRaisesRegex(SystemExit, "refusing binary changes"):
                self.helper["branch_bundle"](repo, base)

    def test_gitlink_changes_are_blocked_in_all_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            tracked = repo / "tracked.txt"
            tracked.write_text("base\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()

            git(
                repo,
                "update-index",
                "--add",
                "--cacheinfo",
                f"160000,{base},vendor/dependency",
            )
            with self.assertRaisesRegex(SystemExit, "gitlink/submodule changes"):
                self.helper["local_bundle"](repo)

            git(repo, "commit", "-q", "-m", "add gitlink")
            with self.assertRaisesRegex(SystemExit, "gitlink/submodule changes"):
                self.helper["commit_bundle"](repo, "HEAD")
            with self.assertRaisesRegex(SystemExit, "gitlink/submodule changes"):
                self.helper["branch_bundle"](repo, base)

    def test_gitlink_guard_parses_combined_raw_modes(self) -> None:
        raw_diff = (
            "::100644 100644 160000 "
            + ("a" * 40)
            + " "
            + ("b" * 40)
            + " "
            + ("c" * 40)
            + " MM\0vendor/dependency\0"
        )

        with self.assertRaisesRegex(SystemExit, "gitlink/submodule changes"):
            self.helper["require_no_gitlink_diff"]("merge diff", raw_diff)

    def test_codex_config_rejects_capability_bearing_overrides(self) -> None:
        for override in (
            'mcp_servers.review.command="touch /tmp/owned"',
            'notify=["sh", "-c", "touch /tmp/owned"]',
            'model_instructions_file="/tmp/hostile.md"',
            'model_provider="credential-sink"',
            'hooks.PreToolUse.command="touch /tmp/owned"',
        ):
            with self.subTest(override=override), self.assertRaisesRegex(
                SystemExit,
                "unsafe Codex config override refused",
            ):
                self.helper["codex_config_overrides"](
                    argparse.Namespace(codex_config=[override])
                )

    def test_codex_config_accepts_safe_tuning_overrides(self) -> None:
        args = argparse.Namespace(
            codex_config=[
                'service_tier="fast"',
                'model_verbosity="low"',
                'model_reasoning_summary="concise"',
            ]
        )

        self.assertEqual(
            self.helper["codex_config_overrides"](args),
            args.codex_config,
        )

    def test_untracked_files_respect_trusted_global_excludes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            home = root / "home"
            home.mkdir()
            excludes = root / "global-ignore"
            excludes.write_text(
                "ignored.local\n!settings.local\n",
                encoding="utf-8",
            )
            (home / ".gitconfig").write_text(
                f"[core]\n\texcludesFile = {excludes.as_posix()}\n",
                encoding="utf-8",
            )
            (repo / "ignored.local").write_text("private notes\n", encoding="utf-8")
            (repo / ".gitignore").write_text("settings.local\n", encoding="utf-8")
            (repo / "settings.local").write_text("repo private\n", encoding="utf-8")
            git(repo, "add", ".gitignore")
            (repo / "visible.txt").write_text("review me\n", encoding="utf-8")
            (repo / "hostile-gitconfig").write_text(
                "[core]\n\texcludesFile = /does/not/exist\n",
                encoding="utf-8",
            )

            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                    "GIT_CONFIG_GLOBAL": str(repo / "hostile-gitconfig"),
                },
            ):
                self.assertEqual(
                    self.helper["safe_untracked_files"](repo),
                    ["hostile-gitconfig", "visible.txt"],
                )

    def test_dirty_check_respects_trusted_global_excludes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            home = root / "home"
            home.mkdir()
            excludes = root / "global-ignore"
            excludes.write_text("ignored.local\n", encoding="utf-8")
            (home / ".gitconfig").write_text(
                f"[core]\n\texcludesFile = {excludes.as_posix()}\n",
                encoding="utf-8",
            )
            (repo / "ignored.local").write_text("private notes\n", encoding="utf-8")

            with mock.patch.dict(
                os.environ,
                {
                    "HOME": str(home),
                    "USERPROFILE": str(home),
                },
            ):
                self.assertFalse(self.helper["is_dirty"](repo))

    def test_oversized_text_is_rejected_without_scanning_binary_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            tail_secret = "\ntoken=" + "A" * 24 + "\n"
            content = "x" * (64_000 * 3 - 4) + tail_secret

            untracked = repo / "untracked.txt"
            untracked.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "file too large to scan safely"):
                self.helper["safe_untracked_files"](repo)

            untracked.unlink()
            binary = repo / "binary.bin"
            binary.write_bytes(b"\0" + content.encode())
            self.assertEqual(
                self.helper["safe_untracked_files"](repo),
                ["binary.bin"],
            )

            binary.unlink()
            evidence = repo / "evidence.txt"
            evidence.write_text(content, encoding="utf-8")
            with self.assertRaisesRegex(SystemExit, "file too large to scan safely"):
                self.helper["validate_evidence_file"](repo, "evidence.txt", "--dataset")

    def test_branch_bundle_rejects_unsafe_or_unknown_base_before_diff(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "tracked.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "tracked.txt")
            git(repo, "commit", "-q", "-m", "base")

            with self.assertRaisesRegex(SystemExit, "unsafe base ref"):
                self.helper["branch_bundle"](repo, "--help")
            with self.assertRaisesRegex(SystemExit, "unknown base ref"):
                self.helper["branch_bundle"](repo, "origin/main")

    def test_commit_bundle_rejects_merge_commits(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "base.txt")
            git(repo, "commit", "-q", "-m", "base")
            base_branch = git(repo, "branch", "--show-current").strip()
            git(repo, "checkout", "-q", "-b", "side")
            (repo / "side.txt").write_text("side\n", encoding="utf-8")
            git(repo, "add", "side.txt")
            git(repo, "commit", "-q", "-m", "side")
            git(repo, "checkout", "-q", base_branch)
            (repo / "main.txt").write_text("main\n", encoding="utf-8")
            git(repo, "add", "main.txt")
            git(repo, "commit", "-q", "-m", "main")
            git(repo, "merge", "-q", "--no-ff", "side", "-m", "merge")

            with self.assertRaisesRegex(SystemExit, "does not accept merge commits"):
                self.helper["commit_bundle"](repo, "HEAD")

    def test_git_path_list_preserves_newline_filenames(self) -> None:
        if os.name == "nt":
            self.skipTest("Windows filesystems do not support newline path components")
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            rel = "line\nbreak.txt"
            (repo / rel).write_text("content\n", encoding="utf-8")
            git(repo, "add", rel)

            paths = self.helper["git_path_list"](repo, "ls-files", "-z")

            self.assertIn(rel, paths)

    @unittest.skipUnless(sys.platform.startswith("linux"), "requires raw non-UTF-8 filename support")
    def test_git_path_list_rejects_non_utf8_output(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            rel = os.fsdecode(b"invalid-\xff.txt")
            (repo / rel).write_text("content\n", encoding="utf-8")
            git(repo, "add", "--", rel)

            with self.assertRaisesRegex(SystemExit, "non-UTF-8 Git output"):
                self.helper["git_path_list"](repo, "ls-files", "-z")

    def test_review_patch_rejects_oversized_content(self) -> None:
        with self.assertRaisesRegex(SystemExit, "too large to review safely"):
            self.helper["validate_review_patch"]("local staged diff", ["safe.txt"], "x" * 25, 10)

    def test_review_patch_limit_counts_utf8_bytes(self) -> None:
        with self.assertRaisesRegex(SystemExit, r"12 bytes; limit 10"):
            self.helper["validate_review_patch"]("local staged diff", ["safe.txt"], "界" * 4, 10)

    def test_review_patch_accepts_large_content_without_explicit_limit(self) -> None:
        patch = (
            "diff --git a/safe.txt b/safe.txt\n"
            "--- a/safe.txt\n"
            "+++ b/safe.txt\n"
            "@@ -0,0 +1,100000 @@\n"
            + "+safe review content\n" * 100_000
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local staged diff",
                ["safe.txt"],
                patch,
            ),
            patch,
        )

    def test_review_bundle_chunking_preserves_every_byte_and_diff_context(self) -> None:
        bundle = (
            "# Commit Diff\n\n"
            "diff --git a/safe.txt b/safe.txt\n"
            "--- a/safe.txt\n"
            "+++ b/safe.txt\n"
            "@@ -0,0 +1,200 @@\n"
            + "+safe review content\n" * 200
        )

        chunks = self.helper["split_review_bundle"](bundle, 300)

        self.assertGreater(len(chunks), 1)
        self.assertEqual("".join(chunk.content for chunk in chunks), bundle)
        self.assertTrue(all(len(chunk.content.encode("utf-8")) <= 300 for chunk in chunks))
        self.assertTrue(
            any(
                "+++ b/safe.txt" in chunk.context
                and "@@ -0,0 +1,200 @@" in chunk.context
                and "Continuation begins at new-file line" in chunk.context
                for chunk in chunks[1:]
            )
        )

    def test_untracked_markdown_headings_do_not_create_bundle_boundaries(self) -> None:
        bundle = (
            "# Untracked Files\n\n"
            "# Untracked File\n"
            'path: "notes.md"\n'
            'source-line 1: "# title\\n"\n'
            'source-line 2: "## section\\n"\n\n'
            "# Untracked File\n"
            'path: "todo.md"\n'
            'source-line 1: "# next\\n"'
        )

        units = self.helper["review_bundle_units"](bundle)

        self.assertEqual(len(units), 3)
        self.assertIn(r'source-line 2: "## section\n"', units[1])
        self.assertEqual("".join(units), bundle)

    def test_unicode_line_separators_do_not_create_bundle_boundaries(self) -> None:
        bundle = (
            "# Untracked Files\n\n"
            "# Untracked File\n"
            'path: "notes.txt"\n'
            'source-line 1: "before\u2028diff --git a/fake b/fake"\n\n'
            "diff --git a/real.txt b/real.txt\n"
            "--- a/real.txt\n"
            "+++ b/real.txt\n"
        )

        units = self.helper["review_bundle_units"](bundle)

        self.assertEqual(len(units), 3)
        self.assertIn("\u2028diff --git a/fake b/fake", units[1])
        self.assertEqual("".join(units), bundle)

    def test_diff_source_prefixes_do_not_replace_file_context(self) -> None:
        context: list[str] = []
        next_new_line = None
        next_old_line = None
        in_hunk = False
        lines = (
            "diff --git a/safe.txt b/safe.txt\n",
            "--- a/safe.txt\n",
            "+++ b/safe.txt\n",
            "@@ -10,2 +10,3 @@\n",
            "+++ added source beginning with pluses\n",
            "--- deleted source beginning with minuses\n",
            " context\n",
        )

        for line in lines:
            next_new_line, next_old_line, in_hunk = self.helper[
                "update_review_chunk_context"
            ](
                context,
                line,
                next_new_line,
                next_old_line,
                in_hunk,
            )

        self.assertEqual(next_new_line, 12)
        self.assertEqual(next_old_line, 12)
        self.assertIn("--- a/safe.txt\n", context)
        self.assertIn("+++ b/safe.txt\n", context)
        self.assertNotIn("--- deleted source beginning with minuses\n", context)

    def test_hunk_header_that_fits_fresh_chunk_is_not_split(self) -> None:
        unit = (
            "diff --git a/abcdefghijk b/abcdefghijk\n"
            "--- a/abcdefghijk\n"
            "+++ b/abcdefghijk\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )

        chunks = self.helper["split_oversized_review_unit"](unit, 85)

        self.assertGreater(len(chunks), 1)
        self.assertTrue(any("@@ -1 +1 @@\n" in chunk.content for chunk in chunks))
        self.assertEqual("".join(chunk.content for chunk in chunks), unit)

    def test_long_diff_line_continuations_keep_their_original_marker(self) -> None:
        for marker in ("+", "-", " "):
            with self.subTest(marker=marker):
                unit = (
                    "diff --git a/large.txt b/large.txt\n"
                    "--- a/large.txt\n"
                    "+++ b/large.txt\n"
                    "@@ -1 +1 @@\n"
                    f"{marker}{'x' * 400}\n"
                )

                chunks = self.helper["split_oversized_review_unit"](unit, 140)

                self.assertTrue(
                    any(
                        f"original marker is `{marker}`" in chunk.context
                        for chunk in chunks[1:]
                    )
                )
                self.assertEqual("".join(chunk.content for chunk in chunks), unit)

    def test_modified_file_deletion_context_keeps_old_and_new_offsets(self) -> None:
        context: list[str] = []
        next_new_line = None
        next_old_line = None
        in_hunk = False
        for line in (
            "diff --git a/safe.txt b/safe.txt\n",
            "--- a/safe.txt\n",
            "+++ b/safe.txt\n",
            "@@ -10,3 +10,2 @@\n",
            "-first deleted line\n",
        ):
            next_new_line, next_old_line, in_hunk = self.helper[
                "update_review_chunk_context"
            ](
                context,
                line,
                next_new_line,
                next_old_line,
                in_hunk,
            )

        rendered = self.helper["review_chunk_context"](
            context,
            next_new_line,
            next_old_line,
        )

        self.assertIn("new-file line 10", rendered)
        self.assertIn("old-file line 11", rendered)

    def test_multiple_long_line_tails_pack_into_following_chunks(self) -> None:
        limit = 200
        unit = (
            "diff --git a/large.txt b/large.txt\n"
            "--- a/large.txt\n"
            "+++ b/large.txt\n"
            "@@ -1,5 +1,5 @@\n"
            + ("+" + "x" * 205 + "\n") * 5
        )

        chunks = self.helper["split_oversized_review_unit"](unit, limit)
        minimum_chunks = (len(unit.encode("utf-8")) + limit - 1) // limit

        self.assertLessEqual(len(chunks), minimum_chunks + 1)
        self.assertEqual("".join(chunk.content for chunk in chunks), unit)
        self.assertTrue(all(len(chunk.content.encode("utf-8")) <= limit for chunk in chunks))

    def test_untracked_continuation_context_keeps_source_line(self) -> None:
        unit = (
            "# Untracked File\n"
            'path: "notes.txt"\n'
            'source-line 1: "short\\n"\n'
            f'source-line 2: "{"x" * 300}"\n'
        )

        chunks = self.helper["split_oversized_review_unit"](unit, 120)

        self.assertGreater(len(chunks), 2)
        self.assertTrue(
            any(
                "Continuation begins at untracked source line 2" in chunk.context
                for chunk in chunks[1:]
            )
        )
        self.assertEqual("".join(chunk.content for chunk in chunks), unit)

    def test_deleted_file_continuation_uses_positive_old_line(self) -> None:
        unit = (
            "diff --git a/removed.txt b/removed.txt\n"
            "--- a/removed.txt\n"
            "+++ /dev/null\n"
            "@@ -40,50 +0,0 @@\n"
            + "-deleted content\n" * 50
        )

        chunks = self.helper["split_oversized_review_unit"](unit, 180)

        deletion_contexts = [
            chunk.context for chunk in chunks[1:] if "old-file line" in chunk.context
        ]
        self.assertTrue(deletion_contexts)
        self.assertTrue(all("line 0" not in context for context in deletion_contexts))
        self.assertTrue(all("--- a/removed.txt" in context for context in deletion_contexts))

    def test_long_complete_context_is_retained_or_rejected(self) -> None:
        path = "nested/" + "x" * 10_000 + ".txt"
        context = [
            f'diff --git "a/{path}" "b/{path}"\n',
            f'--- "a/{path}"\n',
            f'+++ "b/{path}"\n',
            "@@ -1 +1 @@\n",
        ]

        rendered = self.helper["review_chunk_context"](context, 2, 2)

        self.assertIn(f'+++ "b/{path}"', rendered)
        self.assertIn("@@ -1 +1 @@", rendered)
        self.assertIn("Continuation begins at new-file line 2", rendered)

    def test_review_bundle_packs_oversized_unit_tails_globally(self) -> None:
        limit = 1_000
        units = []
        for index in range(5):
            header = (
                f"diff --git a/file-{index}.txt b/file-{index}.txt\n"
                f"--- a/file-{index}.txt\n"
                f"+++ b/file-{index}.txt\n"
                "@@ -0,0 +1 @@\n"
            )
            body = "+" + "x" * (1_100 - len(header.encode("utf-8")) - 2) + "\n"
            units.append(header + body)
        bundle = "".join(units)

        chunks = self.helper["split_review_bundle"](bundle, limit)

        self.assertEqual(len(chunks), 6)
        self.assertEqual("".join(chunk.content for chunk in chunks), bundle)
        self.assertTrue(all(len(chunk.content.encode("utf-8")) <= limit for chunk in chunks))

    def test_large_bundle_stays_single_pass_until_prompt_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            prompts = self.helper["build_review_prompts"](
                repo,
                "commit",
                "HEAD",
                "# Commit Diff\n" + "safe review content\n" * 18_000,
                "",
                "",
            )

        self.assertEqual(len(prompts), 1)

    def test_bundle_above_prompt_limit_uses_complete_bounded_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            prompts = self.helper["build_review_prompts"](
                repo,
                "commit",
                "HEAD",
                "# Commit Diff\n" + "safe review content\n" * 35_000,
                "",
                "",
            )

        self.assertGreater(len(prompts), 1)
        self.assertTrue(
            all(
                len(prompt.encode("utf-8"))
                <= self.helper["MAX_REVIEW_PROMPT_BYTES"]
                for prompt in prompts
            )
        )
        self.assertTrue(all("Oversized review bundle chunk:" in prompt for prompt in prompts))

    def test_review_prompt_preserves_bundle_ending_whitespace(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            bundle = "# Commit Diff\n+Markdown hard break  \n+\n"
            prompt = self.helper["render_review_prompt"](
                repo,
                "commit",
                "HEAD",
                self.helper["ReviewChunk"](bundle),
                "",
                "",
            )

        self.assertTrue(prompt.endswith(bundle))

    def test_review_pass_count_is_bounded(self) -> None:
        builder = self.helper["build_review_prompts"]
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            with mock.patch.dict(builder.__globals__, {"MAX_REVIEW_PASSES": 1}):
                with self.assertRaisesRegex(SystemExit, "more than 1 bounded passes"):
                    builder(
                        repo,
                        "commit",
                        "HEAD",
                        "# Commit Diff\n" + "safe review content\n" * 35_000,
                        "",
                        "",
                    )

    def test_review_patch_escapes_controls_in_blocked_paths(self) -> None:
        path = ".env.\x1b]52;c;VEVTVA==\x07\udc9b"

        with self.assertRaises(SystemExit) as raised:
            self.helper["validate_review_patch"](
                "local staged diff",
                [path],
                "",
            )

        message = str(raised.exception)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\x07", message)
        self.assertNotIn("\udc9b", message)
        self.assertIn(
            r".env.\x1b]52;c;VEVTVA==\x07\udc9b",
            message,
        )

    def test_review_patch_scans_reconstructed_content_not_diff_markers(
        self,
    ) -> None:
        patch = (
            "@@ -0,0 +1,4 @@\n"
            '+            "https://token=" + "hardcoded123@host/repo",\n'
            '+            "DATABASE_URL=https:"\n'
            '+            + f"//token={literal_username}:${{PASSWORD}}@host",\n'
            '+            \'curl "https:\'\n'
        )

        self.assertTrue(self.helper["secret_text_risk"](patch))
        self.assertFalse(
            any(
                self.helper["secret_text_risk"](line)
                for line in patch.splitlines()
            )
        )
        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["safe.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_scans_diff_metadata_line_by_line(self) -> None:
        credential = "AKIA" + "ABCDEFGHIJKLMNOP"
        patch = (
            f"diff --git a/{credential}.txt b/{credential}.txt\n"
            "new file mode 100644\n"
            "--- /dev/null\n"
            f"+++ b/{credential}.txt\n"
            "@@ -0,0 +1 @@\n"
            "+public content\n"
        )

        with self.assertRaisesRegex(SystemExit, "secret-like content"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["safe.txt"],
                patch,
            )

    def test_tracked_sensitive_paths_are_blocked_in_all_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "base.txt").write_text("base\n", encoding="utf-8")
            git(repo, "add", "base.txt")
            git(repo, "commit", "-q", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()

            (repo / ".env").write_text("placeholder=true\n", encoding="utf-8")
            git(repo, "add", ".env")
            with self.assertRaisesRegex(SystemExit, "tracked sensitive paths"):
                self.helper["local_bundle"](repo)

            git(repo, "commit", "-q", "-m", "sensitive path")
            with self.assertRaisesRegex(SystemExit, "tracked sensitive paths"):
                self.helper["branch_bundle"](repo, base)
            with self.assertRaisesRegex(SystemExit, "tracked sensitive paths"):
                self.helper["commit_bundle"](repo, "HEAD")

    def test_tracked_source_names_and_env_templates_remain_reviewable(self) -> None:
        for rel in (
            "tokenizer.py",
            "token_count.ts",
            "src/token/parser.py",
            "src/token/session.ts",
            "internal/tokens/types.go",
            "packages/token/package.json",
            "scripts/tokens/session.sh",
            "src/tokens/session.mjs",
            "credentials/prod.py",
            "secrets/runtime.ts",
            "src/credentials/provider.py",
            "src/secrets/scanner.ts",
            "ui/tokens/session.vue",
            "proto/token/session.proto",
            "password_validator.go",
            ".env.example",
            "private/parser.py",
            ".agents/skills/openclaw-secret-scanning-maintainer/SKILL.md",
            "design-tokens/colors.json",
            "design-tokens.json",
            "design_tokens.json",
            "tokens/default.json",
            "token_count/generated.py",
            ".docker/Dockerfile",
            ".docker/scripts/build.sh",
        ):
            with self.subTest(rel=rel):
                self.assertIsNone(self.helper["tracked_sensitive_repo_path_risk"](rel))

    def test_untracked_token_source_paths_remain_reviewable(self) -> None:
        for rel in (
            "src/token/parser.py",
            "src/token/session.ts",
            "scripts/tokens/session.sh",
            "src/tokens/session.mjs",
            "ui/tokens/session.vue",
            "proto/token/session.proto",
        ):
            with self.subTest(rel=rel):
                self.assertIsNone(self.helper["sensitive_repo_path_risk"](rel))

    def test_untracked_design_token_artifacts_remain_reviewable(self) -> None:
        for rel in (
            "design-tokens.json",
            "design_tokens.json",
            "src/styles/design-tokens.json",
            "themes/dark/design_tokens.json",
            "tokens/design-tokens.json",
            "tokens/design_tokens.json",
        ):
            with self.subTest(rel=rel):
                self.assertIsNone(self.helper["sensitive_repo_path_risk"](rel))
                self.assertIsNone(
                    self.helper["tracked_sensitive_repo_path_risk"](rel)
                )
        self.assertIsNotNone(
            self.helper["sensitive_repo_path_risk"](".env/design-tokens.json")
        )
        self.assertIsNotNone(
            self.helper["tracked_sensitive_repo_path_risk"](
                ".env/design-tokens.json"
            )
        )
        self.assertIsNotNone(
            self.helper["tracked_sensitive_repo_path_risk"](
                ".env/tokens/design-tokens.json"
            )
        )

    def test_sensitive_named_source_directories_are_blocked_untracked(self) -> None:
        for rel in (
            "credentials/prod.py",
            "secrets/runtime.ts",
            "src/credentials/provider.py",
            "src/secrets/scanner.ts",
        ):
            with self.subTest(rel=rel):
                self.assertIsNotNone(self.helper["sensitive_repo_path_risk"](rel))

    def test_secret_like_path_values_are_blocked(self) -> None:
        secret_path = "notes-" + "ghp_" + "A" * 24 + ".txt"

        self.assertEqual(
            self.helper["sensitive_repo_path_risk"](secret_path),
            "secret-like path",
        )
        self.assertEqual(
            self.helper["tracked_sensitive_repo_path_risk"](secret_path),
            "secret-like path",
        )

    def test_tracked_env_variants_remain_sensitive(self) -> None:
        for rel in (
            ".env-local",
            ".env_prod",
            ".env/production",
            ".env/example/production",
            ".env/template/prod",
        ):
            with self.subTest(rel=rel):
                self.assertIsNotNone(
                    self.helper["tracked_sensitive_repo_path_risk"](rel)
                )

    def test_suffixed_credential_data_paths_remain_sensitive(self) -> None:
        for rel in (
            "credentials-prod.json",
            "service-account-dev.yaml",
            "api-key.backup.json",
            "token-prod.json",
            "tokens.json",
            "auth-token.yaml",
            "prod-credentials.json",
            "google-service-account.json",
            "client-secret.yaml",
            "credentials/prod.json",
            "prod-credentials/client.conf",
            "client-secrets/account.ini",
            "token/production.json",
            "tokens/production.json",
            "tokens/session.dat",
            "tokens/cache.json",
            "token/user.json",
            "tokens/device.sqlite",
            "tokens/session.jwt",
            "tokens/session",
            "backup-secrets/prod.json",
            "dev_credentials/runtime.yaml",
            "client-secrets-old/account.ini",
            "client-secrets/account.properties",
            "credentials/prod.xml",
            "secrets/prod.md",
            "credentials.txt",
            "client-secret.csv",
            ".docker/config.json",
            "deployment/.docker/config.json",
            ".netrc",
            "config/.netrc",
            ".git-credentials",
            "config/.git-credentials",
        ):
            with self.subTest(rel=rel):
                self.assertIsNotNone(
                    self.helper["tracked_sensitive_repo_path_risk"](rel)
                )

    def test_secret_detector_handles_quoted_json_keys(self) -> None:
        content = '{"' + 'api_key": "' + realistic_secret_value() + '"}'

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_backtick_credential_literals(self) -> None:
        content = "const pass" + "word = `" + realistic_secret_value() + "`;"

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_op_backtick_credential_references(self) -> None:
        for content in (
            "pass" + "word=`op read op://vault/item/password`",
            "pass" + "word=`op read --no-newline 'op://vault/item/password'`",
            "pass" + "word=`op read 'op://vault/item name/password'`",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_safe_backtick_interpolation(self) -> None:
        for content in (
            "to" + "ken = `Bearer ${process.env.TOKEN}`",
            "pass"
            + "word = `${user.credentials.password}:${config.passwordSalt}`",
            "api_" + "key = `${config.primary.apiKey}-${config.secondary.apiKey}`",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_backtick_interpolation_with_literal_secret(
        self,
    ) -> None:
        literal_secret = "hardcoded" + "credential"
        for content in (
            "to" + f"ken = `{literal_secret}-${{process.env.TOKEN}}`",
            "pass"
            + f"word = `${{user.credentials.password}}-{literal_secret}`",
            "to"
            + f'ken = `Bearer ${{process.env.TOKEN || "{literal_secret}"}}`',
            "pass" + "word = `p@ssw0rd-${process.env.PASSWORD}`",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_separated_numeric_template_literal(
        self,
    ) -> None:
        content = "pass" + "word = decode(`${12_345_678}`)"

        self.assertTrue(
            self.helper["secret_text_risk"](
                content,
                javascript_dialect="typescript",
            )
        )

    def test_secret_detector_rejects_op_backtick_shell_fallbacks(self) -> None:
        content = (
            "pass"
            + "word=`op read op://vault/item/password || echo real-hardcoded-"
            + "fallback`"
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_backtick_fallback_literals(self) -> None:
        content = (
            "const pass"
            + 'word = `${user.password || "'
            + "real-hardcoded-fallback"
            + '"}`;'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_member_reference_fallback_literals(self) -> None:
        content = (
            "pass"
            + 'word = user.credentials.password || "'
            + "real-hardcoded-fallback"
            + '"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_supported_credential_member_chains(
        self,
    ) -> None:
        for dialect, value in (
            ("csharp", "credentials.Value"),
            ("csharp", "options->Credentials.Value"),
            ("java", "options.Credentials.Current"),
            ("java", "credentialStore::getPassword"),
            ("kotlin", "options.Credentials.Current"),
            ("kotlin", "credentials::password"),
            ("python", "credentials.value"),
            ("c-family", "Credentials::Value"),
            ("c-family", "options->credentials.Value"),
        ):
            with self.subTest(dialect=dialect, value=value):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        f"password = {value};",
                        javascript_dialect=dialect,
                    )
                )

    def test_secret_detector_scans_c_family_member_call_arguments(self) -> None:
        fixture_value = "CorrectHorse7" + "Battery"
        for expression in (
            f'credentials->get("{fixture_value}")',
            f'credentials::get("{fixture_value}")',
            f'credentials->get()->decode("{fixture_value}")',
        ):
            with self.subTest(expression=expression):
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        f"password = {expression}",
                        javascript_dialect="c-family",
                    )
                )

    def test_secret_detector_rejects_reference_shaped_fallback_literals(self) -> None:
        content = (
            "pass"
            + 'word = user.credentials.password || "'
            + "user.ACTUAL_SECRET_VALUE"
            + '"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_reference_shaped_backtick_literals(self) -> None:
        content = "const pass" + "word = `user.ACTUAL_SECRET_VALUE`;"

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_python_reference_fallback_literals(self) -> None:
        for operator in ("or", "and"):
            content = (
                "pass"
                + f'word = user.credentials.password {operator} "'
                + "real-hardcoded-fallback"
                + '"'
            )
            with self.subTest(operator=operator):
                self.assertTrue(self.helper["secret_text_risk"](content))

        conditional = (
            "pass"
            + 'word = user.credentials.password if user else "'
            + "real-hardcoded-fallback"
            + '"'
        )
        self.assertTrue(self.helper["secret_text_risk"](conditional))

        cast_fallback = (
            "pass"
            + 'word = user.credentials.password as string || "'
            + "real-hardcoded-fallback"
            + '"'
        )
        self.assertTrue(self.helper["secret_text_risk"](cast_fallback))

    def test_secret_detector_allows_nonsecret_fallback_values(self) -> None:
        for content in (
            "to" + "ken = retrieve_authentication_token(request) or None",
            "pass" + "word = user.credentials.password || null",
            "to" + "ken = provider.issue_token() ?? undefined",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))
        self.assertIsNone(
            self.helper["top_level_fallback_suffix"](
                'passwordGenerator("ordinary-option-value")'
            )
        )

    def test_secret_detector_stops_fallback_scan_at_sibling_commas(self) -> None:
        for content in (
            '{ password: process.env.PASSWORD, label: prefix + "production-east" }',
            'const token = runtimeToken, checksum = value || "aB3$dE5!gH7#";',
            'const password = runtimeToken, {checksum} = value || "aB3$dE5!gH7#";',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_keeps_fallbacks_before_sibling_commas(self) -> None:
        for content in (
            "const to"
            + 'ken = runtimeToken || "real-hardcoded-fallback", checksum = value;',
            "pass"
            + 'word = (lookupPrimary(), lookupSecondary()) || "hardcoded-secret"',
            "pass"
            + 'word = getSecret<string, string>() || "hardcoded-secret"',
            "pass"
            + 'word = primary, secondary == expected or "hardcoded-'
            + 'secret"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_call_fallback_literals(self) -> None:
        for content in (
            "to"
            + 'ken = generate_secure_token() || "'
            + "real-hardcoded-fallback"
            + '"',
            "to"
            + 'ken = process.env.TOKEN || choose(/\\)/, "'
            + "actual-production-secret"
            + '")',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_grouped_fallbacks_after_line_comments(
        self,
    ) -> None:
        for content in (
            "const pass"
            + "word = lookup() // comment\n "
            + "|| "
            + '"top-level-hardcoded-'
            + 'secret"',
            "const pass"
            + 'word = (lookup() // comment\n || "hardcoded-'
            + 'secret")',
            "const pass"
            + "word = (lookup(), // comment\n"
            + 'fallback = value || "real-hardcoded-'
            + 'secret")',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_does_not_cross_top_level_line_comments(self) -> None:
        for content in (
            "const pass"
            + 'word = lookup() // comment\nconst label = value || "hardcoded-'
            + 'secret"',
            "const pass"
            + "word = ({source: lookup(), // note\n"
            + 'label: value || "aB3$dE5!gH7#"});',
            "const pass"
            + "word = {source: lookup(), // note\n"
            + 'label: value || "aB3$dE5!gH7#"};',
            "const pass"
            + "word = ({source: lookup(), // note\n"
            + '["label"]: value || "aB3$dE5!gH7#"});',
            "const pass"
            + "word = ({source: lookup(), // note\n"
            + '7: value || "aB3$dE5!gH7#"});',
            "const pass"
            + "word = ({source: lookup(), // note\n"
            + "...defaults,\n"
            + 'label: value || "aB3$dE5!gH7#"});',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))
        self.assertTrue(
            self.helper["starts_sibling_assignment"](
                "...defaults,\nlabel: value"
            )
        )

    def test_secret_detector_rejects_short_call_fallback_literals(self) -> None:
        for content in (
            "pass" + 'word = getpass() || "hunter' + '2!"',
            "pass" + 'word = None or "actual-production-' + 'password"',
            "pass" + 'word = x or "actual-production-' + 'password"',
            "pass" + 'word = "" or "actual-production-' + 'password"',
            "pass" + 'word = os.getenv("PASSWORD") or "real' + 'pass9"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_literal_secrets_in_call_arguments(
        self,
    ) -> None:
        literal_value = "actual-production-" + "secret"
        opaque_value = "CORRECT" + "HORSEBATTERYSTAPLE"
        for content in (
            "pass"
            + f'word = credentialProvider?.getPassword("{literal_value}")',
            "to"
            + f'ken = provider.issue_token("{literal_value}").strip()',
            "to"
            + f'ken = provider.issue_token("scope", "{literal_value}")',
            "pass"
            + f'word = os.getenv("DATABASE_PASSWORD", "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(this.#scope, "{literal_value}")',
            "to"
            + f'ken = factory.get("DATABASE_PASSWORD")("{literal_value}")',
            "pass"
            + 'word = client.get("CORRECT'
            + 'HORSEBATTERYSTAPLE")',
            "pass" + f'word = OS.GETENV("{opaque_value}")',
            "pass" + f'word = factory().os.getenv("{opaque_value}")',
            "pass" + f'word = identity ("{literal_value}")',
            "pass" + "word=correcthorsebatterystaple\n(echo ok)",
            "pass" + "word=correcthorsebatterystaple\r(echo ok)",
            "pass" + "word: correcthorsebatterystaple (production)",
            "pass" + "word: correcthorsebatterystaple (primary)",
            "pass" + "word = correcthorsebatterystaple (primary)",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_literals_after_javascript_regex_arguments(
        self,
    ) -> None:
        literal_value = "actual-production-" + "secret"
        for content in (
            "to" + f'ken = provider.issue_token(/\\)/, "{literal_value}")',
            "to" + f'ken = provider.issue_token(/a,b/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(/[),]/gi, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(i++ / total, "{literal_value}" // note\n)',
            "to"
            + f'ken = provider.issue_token(i-- / total, "{literal_value}" // note\n)',
            "to"
            + f'ken = provider.issue_token(typeof /\\)/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ return /\\)/; }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(function*() {{ yield /\\)/; }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(of / total, "{literal_value}" // note\n)',
            "to"
            + f'ken = provider.issue_token(async () => await /\\);/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(async () => await /\\)/\n, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(await /\\)/,\n  "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(await /\\)/.test(input), "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(value! / divisor, "{literal_value}" // note\n)',
            "to"
            + f'ken = provider.issue_token(! /\\)/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(value<int> / total, "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(value<int> / total || "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(counter++ / total || "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(counter-- / total || "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(value! / total || "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(value<Array<number>> / total || "{literal_value}"[0] / count)',
            "var await = value; to"
            + f'ken = provider.issue_token(await / total || "{literal_value}"[0] / count)',
            "function f(await, d) { to"
            + 'ken = provider.issue_token(await / 2, "Abc\\\\123Def456" / d) }',
            "var yield = value; to"
            + f'ken = provider.issue_token(yield / total || "{literal_value}"[0] / count)',
            "to"
            + f'ken = provider.issue_token(() => {{ if (ok) /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ if (x === "(") /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(a<b> /\\)/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ if (ok) use(); else /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ do /\\)/.test(x); while (ok); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ for (const x of /\\)/) use(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ for await (const x of xs) /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ if /*c*/ (ok) /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => {{ if (a) /\\(/.test(x); if (b) /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(.../\\)/.source, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(() => class C extends /\\)/.constructor {{}}, "{literal_value}")',
            "// const await = harmless\n"
            + "to"
            + f'ken = provider.issue_token(await /\\)/, "{literal_value}")',
            "to"
            + "ken = provider.issue_token("
            + f'() => {{ for (of / total; ok; of++) use(); next / 2; }}, "{literal_value}")',
            "to"
            + "ken = provider.issue_token("
            + f'() => {{ for (let x = of / total; x; x++) use(); next / 2; }}, "{literal_value}")',
            "to"
            + "ken = provider.issue_token("
            + f'() => {{ var await=n; if (await / total) /\\)/.test(x); }}, "{literal_value}")',
            "to"
            + "ken = provider.issue_token(await /\\)/, "
            + "x" * 9000
            + f', "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(await /\\)/, ok /* ) */, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(wrapper(await /\\)\\)/, process.env.TOKEN), "{literal_value}")',
            "to"
            + "ken = provider.issue_token(await /\\)/,\n"
            + f'fallback = "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(await /foo(\\/a\\/bar)\\)/, "{literal_value}")',
            "to"
            + f'ken = provider.issue_token(await /\\)/, this.#field, "{literal_value}")',
            "to"
            + "ken = outer(wrapper(await /\\)/, process.env.TOKEN),\n"
            + f'  "{literal_value}",\n'
            + "  /foo/)",
            "to"
            + f'ken = get_token(await /\\)/, /x\\)/, "{literal_value}")',
            "to"
            + f'ken = get_token(await /\\)/, process.env.TOKEN) || "{literal_value}"',
            "to"
            + f'ken = get_token(this.#if(x) / total / count, "{literal_value}")',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_safe_javascript_regex_arguments(self) -> None:
        for content in (
            "to" + "ken = provider.issue_token(/\\)/, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(typeof /\\)/, process.env.TOKEN)",
            "to" + "ken = provider.issue_token(total / count, process.env.TOKEN)",
            "to" + "ken = provider.issue_token(of / total, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(async () => await /\\);/, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(async () => await /\\)/\n, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/,\n  process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/.test(input), process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(value! / divisor, process.env.TOKEN)",
            "to" + "ken = provider.issue_token(! /\\)/, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(value<int> / total, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(value<int> / total || process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { if (ok) /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "items.with(0, x) / total, process.env.TOKEN / count)",
            "to"
            + "ken = provider.issue_token("
            + "await / total, process.env.TOKEN / count)",
            "to"
            + "ken = provider.issue_token("
            + "yield / total, process.env.TOKEN / count)",
            "to"
            + "ken = provider.issue_token("
            + "value<Array<number[]>> / total, process.env.TOKEN / count)",
            "to"
            + "ken = provider.issue_token("
            + "value<Foo | Bar> / total, process.env.TOKEN / count)",
            "to"
            + "ken = provider.issue_token("
            + "a<b> /\\)/, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { if (ok) use(); else /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { do /\\)/.test(x); while (ok); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { for (const x of /\\)/) use(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { for await (const x of xs) /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { if /*c*/ (ok) /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { if (a) /\\(/.test(x); if (b) /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + ".../\\)/.source, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => class C extends /\\)/.constructor {}, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { for (of / total; ok; of++) use(); next / 2; }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { for (let x = of / total; x; x++) use(); next / 2; }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { for (const {x} of /\\)/) use(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token("
            + "() => { var await=n; if (await / total) /\\)/.test(x); }, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/, "
            + "x" * 9000
            + ", process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/, ok /* ) */, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(wrapper(await /\\)\\)/, process.env.TOKEN), process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/,\n"
            + "fallback = process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /foo(\\/a\\/bar)\\)/, process.env.TOKEN)",
            "to"
            + "ken = provider.issue_token(await /\\)/, this.#field, process.env.TOKEN)",
            "to"
            + "ken = outer(wrapper(await /\\)/, process.env.TOKEN),\n"
            + "  process.env.TOKEN,\n"
            + "  /foo/)",
            "to"
            + 'ken = get_token(a / fn(x) / b)\nreport("actual-production-secret")',
            "to"
            + 'ken = get_token(await /\\)/, /x)"actual-production-secret"/, process.env.TOKEN)',
            "to"
            + "ken = get_token(await /\\)/, process.env.TOKEN) || process.env.FALLBACK",
            "to"
            + "ken = get_token(this.#if(x) / total / count, process.env.TOKEN)",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_regex_parser_accepts_expression_keyword_contexts(self) -> None:
        for content in (
            "async function f() { return await /\\)/; }",
            "class C extends /\\)/.constructor {}",
            "export default /\\)/;",
            "function* f() { return yield /\\)/; }",
        ):
            with self.subTest(content=content):
                start = content.index("/")
                self.assertIsNotNone(
                    self.helper["javascript_regex_literal_end"](content, start)
                )

    def test_call_argument_split_preserves_secret_shaped_regex(self) -> None:
        regex = "/password=" + "actual-production-secret" + ",foo/"

        self.assertEqual(
            self.helper["split_top_level_call_arguments"](
                f"{regex}, process.env.TOKEN"
            ),
            [regex, " process.env.TOKEN"],
        )

    def test_call_argument_split_treats_contextual_of_as_identifier(self) -> None:
        self.assertEqual(
            self.helper["split_top_level_call_arguments"](
                "of / total, other / +count, final"
            ),
            ["of / total", " other / +count", " final"],
        )

    def test_control_condition_scan_is_cached_per_source(self) -> None:
        scan = self.helper["javascript_control_condition_closes"]
        scan.cache_clear()
        content = " ".join("if (ok) /a/.test(value);" for _ in range(32))
        starts = [match.start() for match in re.finditer(r"/a/", content)]

        for start in starts:
            self.assertIsNotNone(
                self.helper["javascript_regex_literal_end"](content, start)
            )

        cache = scan.cache_info()
        self.assertEqual(cache.misses, 1)
        self.assertGreaterEqual(cache.hits, len(starts) - 1)

    def test_credential_uri_contexts_are_scanned_once(self) -> None:
        scan = self.helper["string_contexts_at"]
        wrapped = mock.Mock(wraps=scan)
        content = "\n".join(
            f"URL_{index}=postgres://"
            f"user:$PASSWORD_{index}@db.example/app"
            for index in range(64)
        )
        with mock.patch.dict(
            self.helper["credentialed_uri_risk"].__globals__,
            {"string_contexts_at": wrapped},
        ):
            self.assertFalse(self.helper["credentialed_uri_risk"](content))

        wrapped.assert_called_once()

    def test_secret_detector_scopes_premature_regex_tail_to_current_call(
        self,
    ) -> None:
        literal_value = "actual-production-" + "secret"
        for content in (
            "to"
            + "ken = get_token(await /\\)/, process.env.TOKEN)\n"
            + f'const fixture = "{literal_value}"',
            "to"
            + 'ken = headers.get("Authorization"); const ratio = a / b\n'
            + f'const fixture = "{literal_value}"',
            "to"
            + "ken = get_token(await /\\)/, process.env.TOKEN)\r\n"
            + f'const fixture = "{literal_value}"',
            "to"
            + 'ken = issue(); route = "/health/status/check";',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_credential_lookup_keys(self) -> None:
        for content in (
            'pass' + 'word = os.getenv("DATABASE_PASSWORD")',
            'to' + 'ken = headers.get("Authorization")',
            'to' + 'ken = request.headers.get("Authorization")',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_public_call_arguments(self) -> None:
        for content in (
            "access_"
            + 'token = credentials.get_token("https://management.azure.com/.default")',
            "access_"
            + 'token = self._credential.get_token("https://management.azure.com/.default")',
            "access_" + 'token = credentials.get_token("scope")',
            "access_"
            + 'token = credentials.get_token("api://00000000-0000-0000-0000-000000000000/.default")',
            "access_"
            + 'token = credentials.get_token("3db474b9-6a0c-4840-96ac-1fceb342124f/.default")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("scope-a", '
            + '"https://management.azure.com/.default")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://[")',
            "pass" + 'word = input("Enter your password: ")',
            "pass" + 'word = input("Password: ")',
            "pass" + 'phrase = getpass.getpass("Passphrase: ")',
            "pass"
            + 'word = getpass.getpass(prompt="Enter your password: ")',
            "api_"
            + 'key = input("Enter your API key: ")',
            "api_"
            + 'key = getpass.getpass("Enter your API key: ")',
            "api_"
            + 'key = getpass.getpass(prompt="Enter your API key: ")',
            "to" + 'ken = input("Enter API to' + 'ken: ")',
            "to" + 'ken = input ("Enter API to' + 'ken: ")',
            "api" + 'Key = prompt("Enter API key: ")',
            "api" + 'Key = prompt("Enter API key: ", defaultApiKey)',
            "pass" + 'word = ui.prompt("Enter password for Service2")',
            "pass" + 'word = ui?.prompt("Enter password for Service2")',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_secret_shaped_public_arguments(self) -> None:
        for content in (
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://api.example.test/?access_'
            + 'token=hardcoded-secret")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://example.test:not-a-port/.default")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://example.test/.default?x=%67%68%70")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://gl'
            + 'pat-abcdefghijklmnopqrst.example.com/.default")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://gl%09'
            + 'pat-abcdefghijklmnopqrst.example.com/.default")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("https://example.test/'
            + 'correct-horse-battery-staple")',
            "access_"
            + "to"
            + 'ken = credentials.get_token("3db474b9-6a0c-4840-96ac-'
            + '1fceb342124f/actual-production-secret")',
            "pass" + 'word = decode("correct horse battery staple?")',
            "api"
            + "Key = prompt("
            + '"Enter API key: ", "real'
            + 'pass9")',
            "pass"
            + 'word = prompt("real'
            + 'pass9")',
            "api"
            + "Key = prompt({default: "
            + '"real'
            + 'pass9"})',
            "pass"
            + "word = in"
            + 'put("correct horse battery staple?")',
            "pass"
            + 'word = attacker.prompt("Enter password for Horse7battery")',
            "access_"
            + "to"
            + 'ken = custom_client.get_token("correct-horse-battery-staple")',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_short_reference_fallback_literals(self) -> None:
        for expression in ("env.TOKEN", "getToken()"):
            content = (
                "to"
                + f'ken = {expression} || "'
                + "live-secret-value-123456"
                + '"'
            )
            with self.subTest(expression=expression):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_parenthesized_fallback_literals(self) -> None:
        operator = "o" + "r"
        for opening, closing in (("(", ")"), ("((", "))")):
            content = (
                "pass"
                + f'word = {opening}os.getenv("PASS'
                + f'WORD") {operator} "real'
                + f'pass9"{closing}'
            )
            with self.subTest(opening=opening):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_bare_secret_with_reference_prefix(
        self,
    ) -> None:
        content = "to" + "ken = ab.cd-0123456789abcdefghijklmnop"

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_multiline_call_fallback_literals(self) -> None:
        content = (
            "to"
            + "ken = provider.issue_token()\n"
            + '  || "real-hardcoded-'
            + 'fallback"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_operator_only_multiline_fallbacks(self) -> None:
        content = (
            "pass"
            + "word = user.credentials.password ||\n"
            + '  "actual-production-'
            + 'secret"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_nested_multiline_fallbacks(self) -> None:
        content = (
            "pass"
            + "word = user.credentials.password || getDefault(\n"
            + '  "actual-production-'
            + 'secret"\n)'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_comment_separated_call_fallbacks(self) -> None:
        content = (
            "to"
            + "ken = provider.issue_token()\n"
            + "  // local fallback\n"
            + '  || "real-hardcoded-'
            + 'fallback"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_optional_call_fallback_literals(self) -> None:
        content = (
            "to"
            + 'ken = provider?.issue_token() || "real-hardcoded-'
            + 'fallback"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_ignores_comment_delimiters_in_calls(self) -> None:
        content = (
            "to"
            + "ken = provider.issue_token(/* ) */ request)"
            + ' || "real-hardcoded-'
            + 'fallback"'
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_bare_variable_secret_references(self) -> None:
        for prefix in (
            "cached",
            "current",
            "existing",
            "loaded",
            "previous",
            "resolved",
            "saved",
            "stored",
        ):
            with self.subTest(prefix=prefix):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        f"refresh_token = {prefix}_refresh_token"
                    )
                )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "refresh_" + "token = " + "abcdefghijklmnopqrstuvwxyz"
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                "const access_"
                + "to"
                + "ken = generated_password_"
                + "value"
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "ACCESS_"
                + "TO"
                + "KEN=generated_access_token_"
                + realistic_secret_value()
                + "_value"
            )
        )
        for content in (
            "const token = authenticationToken;",
            "const token = longVariableReference;",
            "const token = tokenFromEnvironment;",
            "const password = databasePassword;",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_raw_jwt(self) -> None:
        content = ".".join(
            (
                "eyJhbGciOiJIUzI1NiJ9",
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
                "signatureplaceholder",
            )
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_private_key_header_variants(self) -> None:
        for content in (
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
            "-----BEGIN PGP " + "PRIVATE KEY BLOCK-----",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_dotted_config_keys(self) -> None:
        self.assertFalse(
            self.helper["secret_text_risk"](
                'permissions.autoreview.filesystem={":minimal"="read"}'
            )
        )

    def test_secret_detector_allows_typescript_function_parameter_types(self) -> None:
        signature = (
            "function formatCredentialLabel("
            + "credential"
            + ": ClaudeCliReadableCredential"
            + "): string {"
        )
        access_key = "AKIA" + "ABCDEFGHIJKLMNOP"
        secret_assignment = "const api" + 'Key = "' + access_key + '";'
        literal_value = "actual-production-" + "secret"
        parameter_name = "api" + "Key"
        type_name = "Api" + "Credential"
        typed_default = (
            "function connect("
            + parameter_name
            + ": "
            + type_name
            + ' = "'
            + literal_value
            + '") {}'
        )
        benign_default = (
            "function connect("
            + parameter_name
            + ": "
            + type_name
            + " = defaultCredential) {}"
        )

        self.assertFalse(self.helper["secret_text_risk"](signature))
        self.assertFalse(self.helper["secret_text_risk"](benign_default))
        self.assertTrue(
            self.helper["secret_text_risk"](
                signature + "\n  " + secret_assignment + "\n}"
            )
        )
        self.assertTrue(self.helper["secret_text_risk"](typed_default))

    def test_secret_detector_handles_punctuation_and_multiline_diff_values(self) -> None:
        value = "Correct-Horse!" + "@Battery$Staple"
        patch = (
            "@@ -1 +1,2 @@\n"
            '+"api_key":\n'
            '+  "' + value + '"\n'
        )

        self.assertTrue(
            any(
                self.helper["secret_text_risk"](content)
                for content in self.helper["unified_diff_contents"](patch)
            )
        )

    def test_secret_detector_does_not_treat_code_expressions_as_values(self) -> None:
        for content in (
            "token = secrets.token_urlsafe(32)",
            "token = response",
            "password = undefined",
            "token = process.env.GITHUB_TOKEN",
            'token = os.environ["GITHUB_TOKEN"]',
            'password = payload.get("password")',
            "token = auth_response.credentials.access_token",
            "token = response.authentication.accessToken",
            "token = request.headers.authorization",
            "password = account.credentials.password",
            "password = user.credentials.password",
            "password = user?.credentials?.password",
            "password = `${process.env.PASSWORD}`",
            "{ password: process.env.PASSWORD, username }",
            "token = process.env.TOKEN as string",
            "self.access_token = self.authentication.access_token",
            "this.accessToken = this.authentication.accessToken",
            "api_key = client.settings.apiKey",
            'token = "$GITHUB_TOKEN"',
            'token = "$env:GITHUB_TOKEN"',
            'token = "${{ secrets.GITHUB_TOKEN }}"',
            'token = "op://Vault/Item/token"',
            'token = "op://Development/AWS/Access Keys/access_key_id"',
            'token_endpoint = "https://accounts.example.com/oauth2/token"',
            'password_policy = "minimum-twelve-characters"',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

        self.assertFalse(
            self.helper["secret_text_risk"](
                "pass"
                + "word = user.credentials."
                + "password\nif password is None:\n  reset()"
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                "pass" + "word = process.env.PASSWORD   "
            )
        )

    def test_secret_detector_allows_typescript_object_secret_references(self) -> None:
        content = (
            "async function configure(context: RuntimeContext) {\n"
            "  const cliDevice = await login();\n"
            "  const driverPassword = readPassword();\n"
            "  return {\n"
            "    access"
            + "Token"
            + ": cliDevice.access"
            + "Token,\n"
            + "    pass"
            + "word: driverPass"
            + "word,\n"
            + "    ...(context.driverPass"
            + "word ? { pass"
            + "word: context.driverPass"
            + "word } : {}),\n"
            + "  };\n"
            + "}"
        )
        yaml_literal = "pass" + "word: actualProductionSecret,"
        yaml_reference = "pass" + "word: context.driverPass" + "word"
        yaml_flow_reference = (
            "{ pass" + "word: context.driverPass" + "word, enabled: true }"
        )
        sut_reference = (
            "const pass"
            + "word = context.sutPass"
            + "word;"
        )
        literal_value = "actual-production-" + "secret"
        source_literal = (
            "function configure() { return { pass"
            + 'word: "'
            + literal_value
            + '" }; }'
        )
        jwt_like = "eyJhbGciOiJIUzI1NiJ9" + ".payload." + "signature"
        undeclared_member = (
            "const config = { pass"
            + "word: "
            + jwt_like
            + " };"
        )
        jwt_root = jwt_like.split(".", 1)[0]
        declared_member = (
            f"const {jwt_root} = {{}};\n"
            + "const config = { pass"
            + "word: "
            + jwt_like
            + " };"
        )
        prefixed_member = (
            "const session = {};\n"
            + "const config = { pass"
            + "word: session."
            + jwt_like
            + " };"
        )
        declared_identifier = "CorrectHorseBattery" + "Staple123"
        declared_identifier_value = (
            f"const {declared_identifier} = 0;\n"
            + "const config = { pass"
            + "word: "
            + declared_identifier
            + " };"
        )
        suffixed_reference = (
            "const config = { pass"
            + "word: context.driverPass"
            + "wordExtra };"
        )
        prefixed_reference = (
            "const config = { pass"
            + "word: xcontext.driverPass"
            + "word };"
        )
        final_property = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word }; }"
        )
        inline_property = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word, enabled: true }; }"
        )
        asserted_property = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word! }; }"
        )
        cast_property = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word as string }; }"
        )
        union_cast_property = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word as string | undefined }; }"
        )
        next_statement = (
            "function configure(context: RuntimeContext) {\n"
            + "  const pass"
            + "word = context.driverPass"
            + "word\n"
            + "  return consume();\n"
            + "}"
        )
        line_comment = (
            "const pass"
            + "word = context.driverPass"
            + "word // supplied by CI\n"
            + "consume();"
        )
        block_comment = (
            "const pass"
            + "word = context.driverPass"
            + "word /* supplied by CI */;"
        )
        concatenated_literal = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + 'word + "'
            + literal_value
            + '" }; }'
        )
        continued_literal = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + "word\n"
            + '  + "'
            + literal_value
            + '" }; }'
        )
        fallback_literal = (
            "function configure(context: RuntimeContext) { return { pass"
            + "word: context.driverPass"
            + 'word ?? "'
            + literal_value
            + '" }; }'
        )
        assigned_literal = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + '  = "'
            + literal_value
            + '";'
        )
        newline_cast_literal = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + "  as string + \""
            + literal_value
            + '";'
        )
        commented_continuation = (
            "const pass"
            + "word = context.driverPass"
            + "word // supplied by CI\n"
            + '  + "'
            + literal_value
            + '";'
        )
        unicode_comment_continuation = (
            "const pass"
            + "word = context.driverPass"
            + "word // supplied by CI"
            + chr(0x2028)
            + '  + "'
            + literal_value
            + '";'
        )
        unicode_space_continuation = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + chr(0x00A0)
            + '+ "'
            + literal_value
            + '";'
        )
        multiline_cast_literal = (
            "const pass"
            + "word = context.driverPass"
            + "word as string\n"
            + '+ "'
            + literal_value
            + '";'
        )
        leading_comma_statement = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + ', username = "'
            + literal_value
            + '";'
        )
        unary_statement = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + '!audit("'
            + literal_value
            + '");'
        )
        inequality_literal = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + '!== "'
            + literal_value
            + '";'
        )
        member_call_literal = (
            "const pass"
            + "word = context.driverPass"
            + 'word["concat"]("safe", "'
            + literal_value
            + '");'
        )
        continued_then_unary_statement = (
            "const pass"
            + "word = context.driverPass"
            + "word + suffix\n"
            + '!audit("'
            + literal_value
            + '");'
        )
        trailing_operator_literal = (
            "const pass"
            + "word = context.driverPass"
            + "word + suffix +\n"
            + '  "'
            + literal_value
            + '";'
        )
        plain_javascript_as_statement = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + 'as("'
            + literal_value
            + '");'
        )
        typescript_dollar_identifier = (
            "const pass"
            + "word = context.driverPass"
            + "word\n"
            + 'as$logger("'
            + literal_value
            + '");'
        )

        self.assertFalse(
            self.helper["secret_text_risk"](
                content,
                javascript_dialect="typescript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                sut_reference,
                javascript_dialect="typescript",
            )
        )
        self.assertTrue(self.helper["secret_text_risk"](sut_reference))
        self.assertFalse(
            self.helper["secret_text_risk"](
                plain_javascript_as_statement,
                javascript_dialect="javascript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                typescript_dollar_identifier,
                javascript_dialect="typescript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                final_property,
                javascript_dialect="typescript",
            )
        )
        for source_reference in (
            inline_property,
            asserted_property,
            cast_property,
            union_cast_property,
            next_statement,
            line_comment,
            block_comment,
            leading_comma_statement,
            unary_statement,
            continued_then_unary_statement,
        ):
            with self.subTest(source_reference=source_reference):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        source_reference,
                        javascript_dialect="typescript",
                    )
                )
        for unsafe_source_reference in (
            concatenated_literal,
            continued_literal,
            fallback_literal,
            assigned_literal,
            newline_cast_literal,
            commented_continuation,
            unicode_comment_continuation,
            unicode_space_continuation,
            multiline_cast_literal,
            inequality_literal,
            member_call_literal,
            trailing_operator_literal,
        ):
            with self.subTest(unsafe_source_reference=unsafe_source_reference):
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        unsafe_source_reference,
                        javascript_dialect="typescript",
                    )
                )
        self.assertTrue(self.helper["secret_text_risk"](yaml_literal))
        self.assertTrue(self.helper["secret_text_risk"](yaml_reference))
        self.assertTrue(self.helper["secret_text_risk"](yaml_flow_reference))
        self.assertTrue(self.helper["secret_text_risk"](source_literal))
        self.assertTrue(self.helper["secret_text_risk"](undeclared_member))
        self.assertTrue(self.helper["secret_text_risk"](declared_member))
        self.assertTrue(self.helper["secret_text_risk"](prefixed_member))
        self.assertTrue(
            self.helper["secret_text_risk"](declared_identifier_value)
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                suffixed_reference,
                javascript_dialect="typescript",
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                prefixed_reference,
                javascript_dialect="typescript",
            )
        )

    def test_secret_detector_allows_lifecycle_named_typescript_references(self) -> None:
        key_term = "Api" + "Key"
        key_field = key_term[0].lower() + key_term[1:]
        credential_term = "Cred" + "ential"
        source = (
            f"const resolvedStream{key_term} = resolveAttemptDispatch{key_term}({{\n"
            f"  {key_field}Info,\n"
            "  runtimeAuthState,\n"
            "});\n"
            f"const successful{credential_term} = successfulProfileId\n"
            "  ? attemptAuthProfileStore.profiles[successfulProfileId]\n"
            "  : undefined;\n"
            f"const successful{key_term}Info = get{key_term}Info();\n"
            f"const {key_field} = successful{key_term}Info?.{key_field};\n"
            f"const resolved{key_term} = resolveSecretSentinel({key_field});\n"
            "return {\n"
            f"  resolved{key_term}: resolvedStream{key_term},\n"
            f"  {credential_term.lower()}: successful{credential_term},\n"
            f"  {key_field}: resolved{key_term},\n"
            "};\n"
        )
        literal_value = "actual-production-" + "secret"
        unsafe_sources = (
            f'const resolved{key_term} = "' + literal_value + '";',
            "const config = { pass"
            + "word: resolved"
            + key_term
            + ' + "'
            + literal_value
            + "\" };",
            "const config = { pass"
            + "word: Abcdefghijklmnop.Qrstuvwxyzabcdef };",
        )

        self.assertFalse(
            self.helper["secret_text_risk"](
                source,
                javascript_dialect="typescript",
            )
        )
        for unsafe_source in unsafe_sources:
            with self.subTest(unsafe_source=unsafe_source):
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        unsafe_source,
                        javascript_dialect="typescript",
                    )
                )

        store_reference = (
            "const cred"
            + "ential = attemptAuthProfileStore.profiles[successfulProfileId];"
        )
        optional_store_reference = (
            "const cred"
            + "ential = attemptAuthProfileStore?.[successfulProfileId];"
        )
        quoted_store_reference = (
            "const cred"
            + 'ential = attemptAuthProfileStore["profiles"][successfulProfileId];'
        )
        yaml_store_literal = (
            "pass"
            + 'word: attemptAuthProfileStore["'
            + literal_value
            + '"]'
        )
        quoted_secret_key = "N7xQ2mP9vK4r" + "T8wZ"
        typescript_store_literal = (
            "const pass"
            + 'word = attemptAuthProfileStore["'
            + quoted_secret_key
            + '"];'
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                store_reference,
                javascript_dialect="typescript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                optional_store_reference,
                javascript_dialect="typescript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                quoted_store_reference,
                javascript_dialect="typescript",
            )
        )
        self.assertTrue(self.helper["secret_text_risk"](yaml_store_literal))
        self.assertTrue(
            self.helper["secret_text_risk"](
                typescript_store_literal,
                javascript_dialect="typescript",
            )
        )

    def test_lifecycle_reference_scan_is_bounded_for_non_matching_identifier(self) -> None:
        source = "const value = resolved" + "A" * 100_000 + "X;"

        started = time.monotonic()
        spans = self.helper["javascript_reference_spans"](source)

        self.assertEqual(spans, frozenset())
        self.assertLess(time.monotonic() - started, 5.0)

    def test_review_patch_scopes_source_references_to_typescript_files(self) -> None:
        property_name = "pass" + "word"
        reference = "context.driverPass" + "word"
        source_patch = (
            "diff --git a/src/runtime.ts b/src/runtime.ts\n"
            "--- a/src/runtime.ts\n"
            "+++ b/src/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            "+function configure(context: RuntimeContext) { return { "
            + property_name
            + ": "
            + reference
            + " }; }\n"
        )
        narrow_source_patch = (
            "diff --git a/src/runtime.ts b/src/runtime.ts\n"
            "--- a/src/runtime.ts\n"
            "+++ b/src/runtime.ts\n"
            "@@ -40,2 +40,3 @@ function configure(context: RuntimeContext) {\n"
            "   return {\n"
            "+    "
            + property_name
            + ": "
            + reference
            + ",\n"
            "   };\n"
        )
        config_patch = (
            "diff --git a/config.yml b/config.yml\n"
            "--- a/config.yml\n"
            "+++ b/config.yml\n"
            "@@ -0,0 +1 @@\n"
            "+"
            + property_name
            + ": "
            + reference
            + "\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local staged diff",
                ["src/runtime.ts"],
                source_patch,
            ),
            source_patch,
        )
        self.assertEqual(
            self.helper["validate_review_patch"](
                "local staged diff",
                ["src/runtime.ts"],
                narrow_source_patch,
            ),
            narrow_source_patch,
        )
        for paths in (
            ["src/runtime.ts", "config.yml"],
            ["config.yml", "src/runtime.ts"],
        ):
            with self.assertRaisesRegex(SystemExit, "known secret-like value"):
                self.helper["validate_review_patch"](
                    "local staged diff",
                    paths,
                    source_patch + config_patch,
                )

    def test_review_patch_scans_rename_sides_with_their_own_file_types(self) -> None:
        property_name = "pass" + "word"
        reference = "context.driverPass" + "word"
        patch = (
            "diff --git a/src/runtime.ts b/config.yml\n"
            "similarity index 80%\n"
            "rename from src/runtime.ts\n"
            "rename to config.yml\n"
            "--- a/src/runtime.ts\n"
            "+++ b/config.yml\n"
            "@@ -1 +1 @@\n"
            "-function configure(context: RuntimeContext) { return { "
            + property_name
            + ": "
            + reference
            + " }; }\n"
            "+"
            + property_name
            + ": "
            + reference
            + "\n"
        )

        old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](old_content)
        fragments.update(self.helper["review_secret_fragments"](new_content))
        redacted = self.helper["redact_secret_like_diff_section"](
            patch,
            {"src/runtime.ts", "config.yml"},
            fragments,
        )

        self.assertIn("-function configure", redacted)
        self.assertIn(
            "-function configure(context: RuntimeContext) { return { "
            + property_name
            + ": "
            + reference
            + " }; }",
            redacted,
        )
        self.assertIn("+" + property_name + ": redacted", redacted)
        self.assertNotIn("+" + property_name + ": " + reference, redacted)
        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "branch diff",
                ["src/runtime.ts", "config.yml"],
                patch,
            )

    def test_review_patch_decodes_git_quoted_source_paths(self) -> None:
        property_name = "pass" + "word"
        reference = "context.driverPass" + "word"
        patch = (
            'diff --git "a/\\303\\251.ts" "b/\\303\\251.ts"\n'
            '--- "a/\\303\\251.ts"\n'
            '+++ "b/\\303\\251.ts"\n'
            "@@ -40,2 +40,3 @@ function configure(context: RuntimeContext) {\n"
            "   return {\n"
            "+    "
            + property_name
            + ": "
            + reference
            + ",\n"
            "   };\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local staged diff",
                ["é.ts"],
                patch,
            ),
            patch,
        )
        self.assertEqual(
            self.helper["javascript_review_dialect"]("module.mts"),
            "typescript",
        )
        self.assertEqual(
            self.helper["javascript_review_dialect"]("module.cts"),
            "typescript",
        )
        self.assertIsNone(self.helper["javascript_review_dialect"]("module.m"))
        self.assertEqual(
            self.helper["javascript_review_dialect"]("module.mm"),
            "c-family",
        )
        for rel, dialect in (
            ("module.kt", "kotlin"),
            ("module.kts", "kotlin"),
            ("module.groovy", "groovy"),
            ("module.gradle", "groovy"),
            ("module.java", "java"),
        ):
            with self.subTest(rel=rel):
                self.assertEqual(
                    self.helper["javascript_review_dialect"](rel),
                    dialect,
                )

    def test_secret_detector_allows_generated_fixture_credentials(self) -> None:
        property_name = "pass" + "word"
        variable_name = "to" + "ken"
        access_property = "access" + "Token"
        generated_fixture = (
            f"function register() {{ return {{ {property_name}: "
            + "`matrix-qa-${randomUUID()}` }; }"
        )
        generated_marker = (
            f"const {variable_name} = "
            + 'buildMatrixQaToken("MATRIX_QA_E2EE_THREAD");'
        )
        decoy_fixture = (
            f"const config = {{ {access_property}: "
            + 'decoy-'
            + 'token" };'
        )
        invalid_recovery_fixture = (
            'const recoveryKey = "not-'
            + 'a-valid-matrix-recovery-key";'
        )
        literal_value = "actual-production-" + "secret"
        fixture_shaped_literal = "PROD_TEST_ACTUAL_" + "SECRET_0123456789"
        adversarial_label = "TEST_Q7WX9M2NK4PV8R6DH3JC"
        unsafe_template = (
            f"const {property_name} = "
            + "`prod-live-secret-${randomUUID()}`;"
        )
        unsafe_string_template = (
            f"const {property_name} = "
            + "`prod-test-live-secret-${String()}`;"
        )
        unsafe_suffix_template = (
            f"const {property_name} = "
            + "`prod-live-secret-test-${randomUUID()}`;"
        )
        unsafe_call = (
            f"const {variable_name} = "
            + f'buildToken("{literal_value}");'
        )
        unsafe_fixture_label = (
            f"const {property_name} = "
            + f'"{fixture_shaped_literal}";'
        )
        unsafe_generator_label = (
            f"const {variable_name} = "
            + f'buildMatrixQaToken("{fixture_shaped_literal}");'
        )
        unsafe_identity_call = (
            f"const {variable_name} = "
            + f'buildTestToken("{adversarial_label}");'
        )

        for content in (
            generated_fixture,
            generated_marker,
            decoy_fixture,
            invalid_recovery_fixture,
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))
        for content in (
            unsafe_template,
            unsafe_string_template,
            unsafe_suffix_template,
            unsafe_call,
            unsafe_fixture_label,
            unsafe_generator_label,
            unsafe_identity_call,
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_fallback_self_test_ignores_ambient_model_overrides(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "AUTOREVIEW_MODEL": "ambient-global-model",
                "AUTOREVIEW_CODEX_MODEL": "ambient-codex-model",
            },
            clear=False,
        ):
            self.helper["self_test_fallback_scope"]()

    def test_secret_detector_handles_bare_call_keyword_values(self) -> None:
        content = "client(api_" + "key=" + realistic_secret_value() + ")"

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_unquoted_underscore_tokens(self) -> None:
        content = "token=prod_" + realistic_secret_value()

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_dotted_calls(self) -> None:
        for content in (
            "token=secrets.token_urlsafe(32)",
            "token = provider.issue_token()",
            "token = provider?.issue_token()",
            "token = generate_secure_token()",
            "token = provider.issue_token().access_token",
            "token = generate_secure_token().strip()",
            "token = provider.issue_token()?.credentials.access_token",
            "access_token = retrieve_authentication_token(request)",
            'token = provider.issue_token(scope="review", retries=2)',
            "token = provider.issue_token(\n  request,\n  retries=2,\n)",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_spaced_calls_without_language_context(
        self,
    ) -> None:
        for content in (
            "pass" + "word = retrieve_authentication_token (request)",
            "to" + "ken: retrieve_authentication_token (request)",
            "to" + "ken: derivePBKDF2SHA256Hash (request)",
            "to" + "ken: acquireOAuth2TokenV2025 (request)",
            "to" + "ken: enterpriseOAuth2ClientV123.getToken ()",
            'pass' + 'word = os.getenv ("DATABASE_PASSWORD")',
            "to" + "ken = mint_token ()",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_rejects_ambiguous_bare_values(self) -> None:
        for content in (
            "pass" + "word=CORRECTHORSEBATTERYSTAPLE",
            "to" + "ken=prod.opaquecredentialvalue",
            "to" + "ken=TOKEN_FROM_ENVIRONMENT_SECRET",
            "to" + "ken: prod.A7f9K2m4Q8v6N3x5R1p0T9z8 (production)",
            "pass" + "word=correct.horse.battery.password",
            "pass" + "word=Correct.horse.battery.staple",
            "access_" + "token=abcDefGhijk" + "LmnoPqrst",
            "pass" + "word=\"${{ 'Correct.horse.battery.staple' }}\"",
            "pass" + "word=\"{{ 'Correct.horse.battery.staple' }}\"",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_does_not_exempt_expression_text_in_literals(self) -> None:
        for value in (
            "correct horse + battery staple",
            "prefix-${credential}-suffix",
            "secret.format(value)",
        ):
            with self.subTest(value=value):
                content = "pass" + f'word="{value}"'
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_lowercase_passphrases(self) -> None:
        content = 'password="' + "correcthorsebatterystaple" + '"'

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_low_diversity_passwords(self) -> None:
        for content in (
            'password="' + "letmeinletmein" + '"',
            'password="' + "hunter2!" + '"',
            "password=" + "hunter2!",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_credentialed_uris(self) -> None:
        for content in (
            'url="postgres://' + "user:pass@" + 'db.example/app"',
            "DATABASE_URL=postgres://" + "user:pass@" + "db.example/app",
            'url="redis://' + ":secret@" + 'db.example/app"',
            'url="postgres://' + "user:pa$$word@" + 'db.example/app"',
            'url="postgres://'
            + "user:fixed-secret:${DB_PASSWORD}@"
            + 'db.example/app"',
            'url="postgres://' + "admin:$ecret123@" + 'db.example/app"',
            'url="postgres://' + "admin:${DB_PASSWORD}@" + 'db.example/app"',
            'url="postgres://' + "admin:{password}@" + 'db.example/app"',
            'url="postgres://' + "admin:%s@" + 'db.example/app"',
            'url="postgres://' + "admin:{}@" + 'db.example/app"',
            'url="https://' + "alice@example.com:secret@" + 'host/app"',
            'url="https://admin:pass'
            + 'word@prod.example/private"',
            "'database.url': 'postgres:"
            + "//user:${DB_PASSWORD}@db.example/app'",
            "const cfg = {\n"
            + '  url: "postgres:'
            + '//admin:$ecret123@db.example/app"\n'
            + "}",
            "const marker = /`/; "
            + 'const url = "postgres:'
            + '//user:${DB_PASSWORD}@db.example/app"',
            "class C { #field = 1; "
            + 'url = "postgres:'
            + '//user:${DB_PASSWORD}@db.example/app"; }',
            "const url = `postgres:"
            + '//user:fixed-secret${process.env["SUFFIX"]}@db.example/app`',
            'const url = "https:'
            + '//alice:pa\\"ss@example.com/app"',
            "const dsn = `postgres:"
            + '//user:${String("hunter2!")}@db.example/app`',
            'return "https:'
            + '//user:${API_TOKEN}@host/app"',
            'dsn = "postgres:'
            + '//user:{password}@db.example/app".format('
            + "pass"
            + 'word="hunter2!")',
            'dsn = "postgres:'
            + '//user:{}@db.example/app".format("hunter2!")',
            'dsn = "postgres:'
            + '//user:%s@db.example/app" % ("hunter2!")',
            'dsn = fmt.Sprintf("postgres:'
            + '//user:%s@db.example/app", "hunter2!")',
            "DATABASE_URL='"
            + "postgres://"
            + "admin:$ecret123@db.example/app"
            + "'",
            '"dsn": "postgresql:\\/\\/alice:'
            + "S3nsitiveValue99@"
            + 'db.example/app"',
            "database_url: postgres://svc:{"
            + "N0tActuallyInterpolation}@db/app",
            "const dsn = `https://user:password="
            + "real-hardcoded-secret-${TOKEN}@host`",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_limits_uri_userinfo_to_authority(self) -> None:
        for content in (
            'url="https://example.com:443?email=user@example.org"',
            'url="https://example.com:443#owner=user@example.org"',
            'url="https://example.com:443" + "?email=user@example.org"',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_username_only_uri_credentials(self) -> None:
        literal_username = "real-hardcoded-" + "secret"
        hex_credential = "0123456789abcdef" + "0123456789abcdef01234567"
        uuid_credential = "550e8400-e29b-41d4-a716-" + "446655440000"

        for content in (
            "https://actual-production-"
            + "token@host/repo",
            "https://actual-production-"
            + "token"
            + ":@host/repo",
            "https://Ab9dEf2gHi4jKl6m" + "No8p@host/repo",
            "https:" + f"//{hex_credential}@host/repo",
            "https:" + f"//{uuid_credential}@host/repo",
            "https://" + "$ecret123@host/repo",
            "https://token=" + "hardcoded123@host/repo",
            "DATABASE_URL=https:"
            + f"//token={literal_username}:${{PASSWORD}}@host",
            'curl "https:'
            + "//Ab9dEf2gHi4jKl6m"
            + 'No8p:${PASSWORD}@host"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_ordinary_uri_usernames(self) -> None:
        for content in (
            "https://git@github.com/example/repo",
            "https://username@host/repo",
            "https://username:@host/repo",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_referenced_uri_credentials(self) -> None:
        for content in (
            "postgres:" + "//user:password@localhost/db",
            "url=postgres:" + "//user:test-token-placeholder@host/db",
            "url=postgres:" + "//user:placeholder@host/db",
            "url=`postgres://" + "user:${DB_PASSWORD}@db.example/app`",
            'url=f"postgres://' + 'user:{password}@db.example/app"',
            'url=f"""postgres://' + 'user:{password}@db.example/app"""',
            'dsn=f"connect to postgres://'
            + 'user:{password}@db.example/app"',
            "DATABASE_URL=postgres://" + "user:$DB_PASSWORD@db.example/app",
            "DATABASE_URL=postgres:" + "//user:${DB_PASS}@db.example/app",
            "DATABASE_URL=https://"
            + "$TOKEN"
            + ":@host/repo",
            "DATABASE_URL=https://"
            + "$TOKEN@host/repo",
            "DATABASE_URL=https://" + "${TOKEN}@host/repo",
            'curl "https://${API_USER}:'
            + '${API_TOKEN}@host/app"',
            "DATABASE_URL=https://john.smith."
            + "department1:${PASSWORD}@host",
            "DATABASE_URL: postgres://"
            + "user:${DB_PASSWORD}@db.example/app",
            "DATABASE_URL: postgres://"
            + "user:$DB_PASSWORD@db.example/app",
            'DATABASE_URL: "postgres://'
            + 'user:${DB_PASSWORD}@db.example/app"',
            'DATABASE_URL: "postgres://'
            + 'user:${DB_PASS}@db.example/app"',
            "DATABASE_URL: postgres://" + "user:${CRED}@db.example/app",
            'DATABASE_URL: "postgres://' + 'user:${AUTH}@db.example/app"',
            "url: postgres://" + "user:${CRED}@db.example/app",
            "- DATABASE_URL=postgres://"
            + "user:${DB_PASSWORD}@db.example/app",
            "url: postgres://" + "user:${DB_PASSWORD}@db.example/app",
            "uri: postgres://" + "user:${DB_PASSWORD}@db.example/app",
            "dsn: postgres://" + "user:${DB_PASSWORD}@db.example/app",
            "# DATABASE_URL: postgres://"
            + "user:${DB_PASSWORD}@db.example/app",
            "# DATABASE_URL=postgres://"
            + "user:${DB_PASSWORD}@db.example/app",
            '# DATABASE_URL="postgres://'
            + 'user:$DB_PASSWORD@db.example/app"',
            'dsn = "postgres://'
            + 'user:%s@db.example/app" % password',
            'dsn = fmt.Sprintf("postgres://'
            + 'user:%s@db.example/app", password)',
            'dsn = fmt.Sprintf("postgres://'
            + '%s:%s@db.example/app", user, password)',
            'dsn = fmt.Sprintf("postgres://'
            + 'user:%s@%s/db", password, host)',
            'dsn = "postgres://'
            + '%s:%s@db.example/app" % (user, password)',
            'dsn = "postgres://'
            + 'user:{}@db.example/app".format(password)',
            'dsn = "postgres://'
            + 'user:{}@{}/db".format(password, host)',
            'dsn = "postgres://'
            + 'user:{password}@{host}/db".format(password=password, host=host)',
            '$"postgres:' + '//user:{password}@db/app"',
            'format!("postgres:' + '//user:{}@db/app", password)',
            '$dsn = "postgres:' + '//user:$password@db/app"',
            'export DATABASE_URL="'
            + "postgres://"
            + "user:${DB_PASSWORD}@db.example/app"
            + '"',
            'DATABASE_URL="jdbc:postgresql://'
            + "user:$DB_PASSWORD@db.example/app"
            + '"',
            "url=`postgres://"
            + "user:${process.env.DB_PASSWORD}@db.example/app`",
            'url=f"postgres://' + 'user:{config.password}@db.example/app"',
            'url=f"postgres://'
            + 'user:{passwords[0]}@db.example/app"',
            "url=f'postgres://"
            + 'user:{config["password"]}@db.example/app\'',
            "// user's config\n"
            + "const url = `postgres://"
            + "user:${DB_PASSWORD}@db.example/app`",
            "const x = this.#field; "
            + "const url = `postgres://"
            + "user:${DB_PASSWORD}@db.example/app`",
            "class C { #field = 1; "
            + "url = `postgres://"
            + "user:${DB_PASSWORD}@db.example/app`; }",
            "const url = `postgres://"
            + "user:${passwords[0]}@db.example/app`",
            "const url = `postgres://"
            + 'user:${passwords["primary"]}@db.example/app`',
            "const dsn = `postgres://"
            + "user:${encodeURIComponent(process.env.DB_PASSWORD)}@db.example/app`",
            'dsn = "postgres://'
            + 'user:{password}@db.example/app".format('
            + "pass"
            + "word=password)",
            '$env:DATABASE_URL = "postgres://'
            + 'svc:$env:DB_PASSWORD@db.example/app"',
            '[string]$dsn = "postgres:'
            + '//svc:$env:DB_PASSWORD@db.example/app"',
            'var dsn = $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'var dsn = @$"postgres:'
            + '//svc:{password}@db.example/app";',
            '"dsn": "postgresql:\\/\\/alice:'
            + '${DB_PASSWORD}@db.example/app"',
            '"dsn": "postgresql:\\/\\/user:'
            + 'password@localhost\\/db"',
            'curl "https://'
            + 'user:${API_TOKEN}@host/app"',
            "curl https://" + "user:$API_TOKEN@host/app",
            'curl -X POST "https:' + '//user:$API_TOKEN@host/app"',
            'curl -X POST "https:' + '//user:$CRED@host/app"',
            'wget "https:' + '//user:${API_TOKEN}@host/app"',
            'git clone https:' + '//user:$TOKEN@host/repo',
            'sudo curl "https:' + '//user:$TOKEN@host/app"',
            'http "https:' + '//user:${API_TOKEN}@host/app"',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_uri_language_references_require_proven_interpolation_context(
        self,
    ) -> None:
        for content in (
            'const dsn = "postgres:'
            + '//svc:$env:DB_PASSWORD@db.example/app"',
            '$dsn = "postgres:'
            + '//svc:$env:Sup3rSecret@db.example/app";',
            'var dsn = @"postgres:'
            + '//svc:{password}@db.example/app";',
            "database_url: postgres://svc:{"
            + "password}@db.example/app",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_uri_shell_inference_rejects_non_shell_language_keywords(self) -> None:
        for content in (
            'assert "postgres:' + '//user:$ecret123@db/app"',
            'print "postgres:' + '//user:$ecret123@db/app"',
            'return "postgres:' + '//user:$ecret123@db/app"',
            'const url = "postgres:' + '//user:$ecret123@db/app"',
        ):
            with self.subTest(content=content):
                self.assertTrue(
                    self.helper["secret_text_risk"](content)
                )

    def test_uri_defaults_and_plain_strings_are_not_interpolation(self) -> None:
        for content in (
            "https:" + "//admin:change" + "me@production.example/",
            'url = "https:' + '//admin:$pass' + 'word@prod.example/"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_ignores_arrow_parameter_fallbacks(self) -> None:
        self.assertFalse(
            self.helper["secret_text_risk"](
                'token => token || "ordinary-option-value"'
            )
        )

    def test_uri_interpolation_rejects_literal_expressions(self) -> None:
        self.assertTrue(
            self.helper["secret_text_risk"](
                'dsn = f"postgres:' + '//user:{ \'literal-'
                + 'secret\' }@host/db"'
            )
        )

    def test_secret_detector_handles_basic_authorization_headers(self) -> None:
        for content in (
            "Author" + "ization: Basic " + "dXNlcjpwYXNz" + "d29yZA==",
            "Author" + "ization: Basic " + "dXNlcjpwYXNz" + "CXdvcmQ=",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_basic_authentication_prose(self) -> None:
        for content in (
            "Authorization: Basic authentication is required",
            '"Authorization": "Basic authentication is required"',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_template_uri_references_skip_format_scans(self) -> None:
        original = self.helper["uri_password_is_format_placeholder"]
        calls = 0

        def counted(*args: object) -> bool:
            nonlocal calls
            calls += 1
            return original(*args)

        self.helper["uri_password_is_format_placeholder"] = counted
        try:
            content = "const urls = `" + " ".join(
                "postgres:"
                + f"//user:${{PASSWORD_{index}}}@db{index}.example/app"
                for index in range(1000)
            ) + "`"
            self.assertFalse(self.helper["secret_text_risk"](content))
            self.assertEqual(calls, 0)
        finally:
            self.helper["uri_password_is_format_placeholder"] = original

    def test_format_uri_references_cache_string_boundaries(self) -> None:
        quote_end = self.helper["quoted_string_end"]
        quote_end.cache_clear()
        content = 'dsn = "' + " ".join(
            "postgres:" + f"//user:{{0}}@db{index}.example/app"
            for index in range(1000)
        ) + '".format(password)'

        self.assertFalse(self.helper["secret_text_risk"](content))
        cache_info = quote_end.cache_info()
        self.assertEqual(cache_info.misses, 1)
        self.assertGreaterEqual(cache_info.hits, 999)

    def test_secret_detector_handles_aws_secret_access_keys(self) -> None:
        content = (
            "AWS_SECRET_ACCESS_"
            + "KEY="
            + "A7f9K2m4Q8v6N3x5R1p0T9z8B2c4D6e8F0h2"
        )

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_common_fixture_literals(self) -> None:
        for content in (
            'token: "token-oversized"',
            'API_KEY = "clawrouter-e2e-secret"',
            'token: "very-long-browser-token-0123456789"',
            'token: "config-token"',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_synthetic_secret_fixture_prefixes_are_generic(self) -> None:
        for prefix in self.helper["SYNTHETIC_SECRET_PREFIXES"]:
            with self.subTest(prefix=prefix):
                self.assertTrue(
                    self.helper["synthetic_secret_fixture"](
                        f"{prefix}-token",
                        "token",
                    )
                )

        self.assertFalse(
            self.helper["synthetic_secret_fixture"](
                "test-correct-horse-battery-staple",
                "password",
            )
        )

    def test_secret_detector_does_not_trust_in_band_suppressions(self) -> None:
        for marker in ("pragma: allowlist secret", "gitleaks:allow"):
            with self.subTest(marker=marker):
                content = (
                    "pass"
                    + 'word="CorrectHorseBatteryStaple123!"  # '
                    + marker
                )
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_does_not_treat_quoted_code_text_as_a_reference(self) -> None:
        for content in (
            "pass" + 'word="' + "CORRECT_HORSE_BATTERY_STAPLE" + '"',
            "to" + 'ken="' + "process.env.PROD_TOKEN" + '"',
            "api_" + 'key="' + "config.production_key" + '"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

        self.assertFalse(
            self.helper["secret_text_risk"]('api_key="${OPENAI_API_KEY}"')
        )

    def test_secret_detector_does_not_exempt_placeholder_substrings(self) -> None:
        content = "pass" + 'word="prod-sample-' + realistic_secret_value() + '"'

        self.assertTrue(self.helper["secret_text_risk"](content))

    def test_normalized_secret_scan_does_not_cross_hunks(self) -> None:
        patch = (
            "@@ -1 +1 @@\n"
            "+password:\n"
            "@@ -20 +20 @@\n"
            '+"ordinary long string"\n'
        )

        self.assertFalse(
            any(
                self.helper["secret_text_risk"](content)
                for content in self.helper["unified_diff_contents"](patch)
            )
        )

    def test_normalized_secret_scan_handles_combined_diff_prefixes(self) -> None:
        value = "Correct-Horse!" + "@Battery$Staple"
        patch = (
            "diff --cc settings.json\n"
            "@@@ -1,1 -1,1 +1,2 @@@\n"
            '++"api_key":\n'
            '++  "' + value + '"\n'
        )

        self.assertTrue(
            any(
                self.helper["secret_text_risk"](content)
                for content in self.helper["unified_diff_contents"](patch)
            )
        )

    def test_normalized_secret_scan_separates_old_and_new_values(self) -> None:
        value = "Correct-Horse!" + "@Battery$Staple"
        patch = (
            "@@ -1,2 +1,2 @@\n"
            " password:\n"
            "-  placeholder\n"
            '+  "' + value + '"\n'
        )

        self.assertTrue(
            any(
                self.helper["secret_text_risk"](content)
                for content in self.helper["unified_diff_contents"](patch)
            )
        )

    def test_secret_detector_handles_compound_json_keys(self) -> None:
        for key in ("client_secret", "refresh_token"):
            content = '{"' + key + '": "' + realistic_secret_value() + '"}'
            with self.subTest(key=key):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_safe_self_references(self) -> None:
        self.assertFalse(
            self.helper["secret_text_risk"](
                "private" + "_key = private_key or fallback_private_key",
                javascript_dialect="javascript",
            )
        )
        self.assertFalse(
            self.helper["secret_text_risk"](
                "old_private"
                + "_key = old_private_key or old_line\nnew_private"
                + "_key = new_private_key or new_line",
                javascript_dialect="javascript",
            )
        )
        colon_assignment = self.helper["SECRET_ASSIGNMENT_PATTERN"].search(
            "pass" + "word: password"
        )
        self.assertIsNotNone(colon_assignment)
        self.assertFalse(
            self.helper["safe_self_reference_assignment"](
                "pass" + "word: password",
                colon_assignment,
                javascript_dialect="javascript",
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "client" + "secret" + "=" + "clientsecret"
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "if (ready) send({pass"
                + 'word: "'
                + realistic_secret_value()
                + '"})'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "private"
                + '_key = private_key or "'
                + realistic_secret_value()
                + '"'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "pass"
                + 'word = password\n  || "'
                + realistic_secret_value()
                + '"',
                javascript_dialect="javascript",
            )
        )
        for trivia in ("\n\n  ", "\n  /* comment */\n  ", " // comment\n  "):
            with self.subTest(trivia=trivia):
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        "pass"
                        + "word = password"
                        + trivia
                        + '|| "'
                        + realistic_secret_value()
                        + '"',
                        javascript_dialect="javascript",
                    )
                )

    def test_secret_like_patch_content_is_redacted_in_all_modes(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            path = repo / "settings.txt"
            path.write_text("base\n", encoding="utf-8")
            git(repo, "add", "settings.txt")
            git(repo, "commit", "-q", "-m", "base")
            base = git(repo, "rev-parse", "HEAD").strip()

            secret = realistic_secret_value()
            path.write_text("api" + "_key=" + secret + "\n", encoding="utf-8")
            git(repo, "add", "settings.txt")
            local_bundle, local_truncated = self.helper["local_bundle"](repo)

            git(repo, "commit", "-q", "-m", "secret content")
            branch_bundle, branch_truncated = self.helper["branch_bundle"](repo, base)
            commit_bundle, commit_truncated = self.helper["commit_bundle"](repo, "HEAD")

            for bundle, truncated in (
                (local_bundle, local_truncated),
                (branch_bundle, branch_truncated),
                (commit_bundle, commit_truncated),
            ):
                self.assertIn("api_key=redacted", bundle)
                self.assertNotIn(secret, bundle)
                self.assertFalse(truncated)

    def test_review_patch_redacts_private_key_fixture_hunk_and_continues(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,4 +1,5 @@\n"
            ' const key = ["-----BEGIN '
            + 'PRIVATE KEY-----",\n'
            '   "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890",\n'
            '   "-----END '
            + 'PRIVATE KEY-----",\n'
            " ];\n"
            "+expect(key).toBeDefined();\n"
            "@@ -20 +21 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertIn('const key = ["redacted",', redacted)
        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted)
        self.assertNotIn("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890", redacted)
        self.assertIn("+const timeout = 30_000;", redacted)

    def test_review_patch_tracks_private_key_redaction_per_diff_side(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,3 +1,3 @@\n"
            ' const key = ["-----BEGIN '
            + 'PRIVATE KEY-----",\n'
            '-  "MIIEowIBAAKCAQEArEmoved0123456789ABCDEF", "-----END '
            + 'PRIVATE KEY-----",\n'
            '+  "MIIEowIBAAKCAQEAdDed0123456789ABCDEF", "-----END '
            + 'PRIVATE KEY-----",\n'
            " ];\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted)
        self.assertNotIn("MIIEowIBAAKCAQEArEmoved0123456789ABCDEF", redacted)
        self.assertNotIn("MIIEowIBAAKCAQEAdDed0123456789ABCDEF", redacted)

    def test_review_patch_redacts_markerless_tokens_beside_pem_markers(self) -> None:
        before = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCbefore1234567890ABCDE"
        after = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCafter0987654321FGHIJ"
        private_key_begin = "-----BEGIN " + "PRIVATE KEY-----"
        private_key_end = "-----END " + "PRIVATE KEY-----"
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1 +1 @@\n"
            f'+const keys = ["{before}", "{private_key_begin}", '
            f'"AB12cd34EF56", "{private_key_end}", '
            f'"{after}"];\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertNotIn(before, redacted)
        self.assertNotIn(after, redacted)
        self.assertNotIn("AB12cd34EF56", redacted)
        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted)

    def test_review_patch_fails_closed_after_added_unmatched_private_key_begin(self) -> None:
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,3 @@\n"
            "+-----BEGIN "
            + "PRIVATE KEY-----\n"
            "+MIIEowIBAAKCAQEAunmatched0123456789ABCDEF\n"
            "+runDangerousOperation();\n"
        )

        with self.assertRaisesRegex(SystemExit, "unterminated private-key block"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.txt"],
                patch,
            )

    def test_review_patch_redacts_truncated_inherited_private_key_context(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,3 +1,4 @@\n"
            "+expect(socket.closed).toBe(true);\n"
            ' const key = ["-----BEGIN '
            + 'PRIVATE KEY-----",\n'
            '   "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890",\n'
            '   "Q5pEdChn3fuWgi7gC+pvd5VQ1eAX/7qVE72fhx14NxhaiZU3hCzXjG2S",\n'
            "+runDangerousOperation();\n"
            "@@ -20 +21 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted)
        self.assertNotIn("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890", redacted)
        self.assertIn("+expect(socket.closed).toBe(true);", redacted)
        self.assertIn("+runDangerousOperation();", redacted)
        self.assertIn("+const timeout = 30_000;", redacted)

    def test_review_patch_reuses_fragments_from_truncated_private_key_context(self) -> None:
        repeated = "AB12cd34EF56"
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,3 +1,3 @@\n"
            ' const key = ["-----BEGIN '
            + 'PRIVATE KEY-----",\n'
            f'   "{repeated}",\n'
            '   "GH78ij90KL12",\n'
            "@@ -20 +20,2 @@\n"
            " const timeout = 30_000;\n"
            f'+const duplicate = "{repeated}";\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertNotIn(repeated, redacted)
        self.assertIn('+const duplicate = "redacted";', redacted)

    def test_review_patch_redacts_interleaved_balanced_private_key_marker_edit(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,4 +1,4 @@\n"
            '-const key = "-----BEGIN RSA '
            + 'PRIVATE KEY-----";\n'
            '+const key = "-----BEGIN '
            + 'PRIVATE KEY-----";\n'
            ' const body = "AB12cd34EF56";\n'
            ' const end = "-----END '
            + 'PRIVATE KEY-----";\n'
            ' const label = "visible";\n'
            "@@ -10 +10 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.test.ts"],
            patch,
        )

        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted)
        self.assertNotIn(RSA_PRIVATE_KEY_BEGIN_TEXT, redacted)
        self.assertNotIn("AB12cd34EF56", redacted)
        self.assertIn('const label = "visible";', redacted)
        self.assertIn("+const timeout = 30_000;", redacted)

    def test_review_patch_rejects_truncated_private_key_marker_replacement(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,3 +1,3 @@\n"
            '-const key = "-----BEGIN RSA '
            + 'PRIVATE KEY-----";\n'
            '+const key = "-----BEGIN '
            + 'PRIVATE KEY-----";\n'
            ' const body = "AB12cd34EF56";\n'
            ' expect(key).toBeDefined();\n'
            "@@ -20 +20 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        with self.assertRaisesRegex(SystemExit, "private-key"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.test.ts"],
                patch,
            )

    def test_review_patch_rejects_removed_private_key_end_marker(self) -> None:
        replacement = "AB12cd34EF56gh78"
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -8,3 +8,3 @@\n"
            ' const body = "ZX90yu12WV34";\n'
            '-const end = "-----END '
            + 'PRIVATE KEY-----";\n'
            f'+const replacement = "{replacement}";\n'
            "@@ -20 +20 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        with self.assertRaisesRegex(SystemExit, "private-key"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.test.ts"],
                patch,
            )

    def test_review_patch_rejects_removed_private_key_begin_marker(self) -> None:
        replacement = "AB12cd34EF56gh78"
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1,2 +1,2 @@\n"
            '-const begin = "-----BEGIN '
            + 'PRIVATE KEY-----";\n'
            f'+const replacement = "{replacement}";\n'
            ' const body = "ZX90yu12WV34";\n'
            "@@ -20 +20 @@\n"
            "-const timeout = 0;\n"
            "+const timeout = 30_000;\n"
        )

        with self.assertRaisesRegex(SystemExit, "private-key"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.test.ts"],
                patch,
            )

    def test_review_patch_rejects_net_new_unmatched_private_key_marker(self) -> None:
        patch = (
            "diff --git a/fixture.test.ts b/fixture.test.ts\n"
            "--- a/fixture.test.ts\n"
            "+++ b/fixture.test.ts\n"
            "@@ -1 +1,2 @@\n"
            '-const first = "-----BEGIN RSA '
            + 'PRIVATE KEY-----";\n'
            '+const first = "-----BEGIN '
            + 'PRIVATE KEY-----";\n'
            '+const second = "-----BEGIN EC '
            + 'PRIVATE KEY-----";\n'
        )

        with self.assertRaisesRegex(SystemExit, "private-key"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.test.ts"],
                patch,
            )

    def test_review_patch_redacts_before_unmatched_private_key_end(self) -> None:
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -1,2 +1,2 @@\n"
            " MIIEowIBAAKCAQEAtrailing0123456789ABCDEF\n"
            " -----END "
            + "PRIVATE KEY-----\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn("MIIEowIBAAKCAQEAtrailing0123456789ABCDEF", redacted)
        self.assertNotIn("END PRIVATE KEY", redacted)

    def test_review_patch_tracks_same_line_private_key_markers_in_order(self) -> None:
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,2 @@\n"
            "+-----BEGIN "
            + "PRIVATE KEY----- AB12 -----END "
            + "PRIVATE KEY----- -----BEGIN "
            + "PRIVATE KEY-----\n"
            "+CDef3456GHij7890\n"
        )

        with self.assertRaisesRegex(SystemExit, "unterminated private-key block"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["fixture.txt"],
                patch,
            )

    def test_review_patch_redacts_secret_like_hunk_header_section(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            f'@@ -1 +1 @@ function connect(api{"Key"} = "{fixture_value}")\n'
            "-return oldValue;\n"
            "+return newValue;\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('function connect(api' + 'Key = "redacted")', redacted_patch)
        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("+return newValue;", redacted_patch)

    def test_review_patch_redaction_treats_only_lf_as_a_diff_record_boundary(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/settings.txt b/settings.txt\n"
            "--- a/settings.txt\n"
            "+++ b/settings.txt\n"
            "@@ -1 +1 @@\n"
            "-pass"
            + "word=placeholder\n"
            + f'+pass{"word"}="{fixture_value}\fremaining-secret"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["settings.txt"],
            patch,
        )

        self.assertIn('+pass' + 'word="redacted"', redacted_patch)
        self.assertNotIn(fixture_value, redacted_patch)
        self.assertNotIn("remaining-secret", redacted_patch)

    def test_review_patch_redaction_preserves_unrelated_lines_in_the_same_hunk(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1,4 @@\n"
            " export const enabled = true;\n"
            f'+const api{"Key"} = "{fixture_value}";\n'
            f'+useCredential("{fixture_value}");\n'
            "+runDangerousOperation();\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('+const api' + 'Key = "redacted";', redacted_patch)
        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('+useCredential("redacted");', redacted_patch)
        self.assertIn("+runDangerousOperation();", redacted_patch)

    def test_review_patch_rejects_too_many_secret_fragments(self) -> None:
        secrets = [f"{realistic_secret_value()}{index:03d}" for index in range(257)]
        additions = "".join(
            f'+const api{"Key"} = "{secret}";\n' for secret in secrets
        )
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,258 @@\n"
            + additions
            + "+runDangerousOperation();\n"
        )

        with self.assertRaisesRegex(SystemExit, "too many distinct secret-like values"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_never_replaces_a_secret_like_key_name(self) -> None:
        long_values = [
            f"{realistic_secret_value()}LongLiteral{index:03d}" for index in range(62)
        ]
        additions = '+const api' + 'Key = "veryLongClientSecret";\n'
        additions += "".join(
            f'+const api{"Key"} = "{value}";\n' for value in long_values
        )
        target_secret = "ShortS3cret"
        additions += f'+const veryLongClient{"Secret"} = "{target_secret}";\n'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,64 @@\n"
            + additions
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_never_rewrites_secret_fragment_inside_key(self) -> None:
        fragment = "client" + "Secret"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = "{fragment}"\n'
            + f"+{fragment}Timeout: 30\n"
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.ts"},
            fragments,
        )

        self.assertIn("+" + fragment + "Timeout: 30", redacted_patch)
        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_never_rewrites_secret_fragment_inside_identifier(
        self,
    ) -> None:
        fragment = "authorize"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = "{fragment}"\n'
            + f"+{fragment}User();\n"
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.ts"},
            fragments,
        )

        self.assertIn("+" + fragment + "User();", redacted_patch)
        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_redacts_repeated_secret_across_diff_sides(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            f'-pass{"word"} = "{fixture_value}"\n'
            f'+log("{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('+log("redacted")', redacted_patch)

    def test_review_patch_redacts_repeated_secret_across_files(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/settings.txt b/settings.txt\n"
            "--- a/settings.txt\n"
            "+++ b/settings.txt\n"
            "@@ -1 +0,0 @@\n"
            f'-pass{"word"} = "{fixture_value}"\n'
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f'+log("{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["settings.txt", "runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('+log("redacted")', redacted_patch)

    def test_review_patch_learns_bare_secret_values(self) -> None:
        fixture_value = "correct-" + "horse-battery-staple"
        patch = (
            "diff --git a/settings.txt b/settings.txt\n"
            "--- a/settings.txt\n"
            "+++ b/settings.txt\n"
            "@@ -1 +1 @@\n"
            f"-PASS{'WORD'}={fixture_value}\n"
            f'+log("{fixture_value}")\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["settings.txt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted)
        self.assertIn('+log("redacted")', redacted)

    def test_review_patch_learns_reference_shaped_config_secrets(self) -> None:
        fixture_value = "customer.actualPass" + "word"
        for path, separator in (
            ("settings.yml", ": "),
            ("settings.txt", "="),
            (".env.example", "="),
        ):
            with self.subTest(path=path):
                patch = (
                    f"diff --git a/{path} b/{path}\n"
                    f"--- a/{path}\n"
                    f"+++ b/{path}\n"
                    "@@ -0,0 +1,2 @@\n"
                    + "+PASS"
                    + f"WORD{separator}{fixture_value}\n"
                    + f'+NOTE{separator}"{fixture_value}"\n'
                )

                redacted = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [path],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted)
                self.assertIn(f'+NOTE{separator}"redacted"', redacted)

        for path in (".env", ".env.production"):
            with self.subTest(blocked_path=path):
                with self.assertRaisesRegex(SystemExit, "sensitive filename"):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [path],
                        f"diff --git a/{path} b/{path}\n",
                    )

    def test_review_patch_redacts_known_secret_used_as_quoted_key(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            f'-pass{"word"} = "{fixture_value}"\n'
            f'+const result = {{ "{fixture_value}": value }};\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('{ "redacted": value }', redacted_patch)

    def test_review_patch_redacts_unsafe_self_reference_fallback(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f'+private{"_key"} = private_key or "{fixture_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('private' + '_key = private_key or "redacted"', redacted_patch)

    def test_review_patch_preserves_and_rejects_nested_fallback_calls(self) -> None:
        primary = realistic_secret_value() + "Primary"
        backup = realistic_secret_value() + "Backup"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = getenv("PASSWORD") || choose("{primary}", "{backup}");\n'
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.ts"},
            fragments,
        )

        self.assertIn(f'choose("{primary}", "{backup}")', redacted_patch)
        with self.assertRaisesRegex(SystemExit, "secret-like content"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_never_exempts_literal_secret_as_source_reference(self) -> None:
        literal = "currentPass" + "word"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            + "-pass"
            + f'word = "{literal}";\n'
            + f"+consume({literal});\n"
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.ts"},
            fragments,
        )

        self.assertIn("+consume(" + literal + ");", redacted_patch)
        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_redacts_multiline_fallback_literal(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + "word = password\n"
            + f'+  || "{fixture_value}";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('+  || "redacted";', redacted_patch)

    def test_review_patch_redacts_multiline_triple_fallback_literal(self) -> None:
        first = "Prod" + "Secret123"
        second = "Tail" + "456"
        key = "password"
        quote = '"' * 3
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            f"+{key} = primary or {quote}{first}\n"
            f"+{second}{quote}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn(f"{quote}redacted\n+redacted{quote}", redacted_patch)

    def test_review_patch_preserves_python_fallback_interpolation_source(
        self,
    ) -> None:
        key = "pass" + "word"
        source = f'{key} = primary or f"{{exfiltrate()}}"'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_and_rejects_ambiguous_multiline_call_value(
        self,
    ) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,3 @@\n"
            + "+pass"
            + "word = decode(\n"
            + f'+    "{fixture_value}",\n'
            + "+)\n"
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.py"},
            fragments,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("+pass" + "word = decode(", redacted_patch)
        self.assertIn('+    "redacted",', redacted_patch)
        validated_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )
        self.assertIn("+pass" + "word = decode(", validated_patch)
        self.assertIn('+    "redacted",', validated_patch)

    def test_review_patch_redacts_valid_multiline_template_call(self) -> None:
        first = "".join(("Abc", "123"))
        second = "".join(("Def", "456"))
        key = "pass" + "word"
        source = f"{key} = decode(`{first}\n{second}`);"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "".join(f"+{line}\n" for line in source.splitlines())
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn("decode(`redacted-a\n+redacted-b`)", redacted_patch)

    def test_review_patch_redacts_complete_escaped_call_literal(self) -> None:
        fixture_value = 'abc123\\"); /*SensitiveTail9*/ //'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode("{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("SensitiveTail9", redacted_patch)
        self.assertIn('decode("redacted")', redacted_patch)

    def test_review_patch_redacts_nested_template_call_literal(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + "word = decode(`abc1234${`SensitiveTail9${exfiltrate()}`}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("SensitiveTail9", redacted_patch)
        self.assertIn("exfiltrate()", redacted_patch)
        self.assertIn(
            "decode(`redacted-a${`redacted-b${exfiltrate()}`}`)",
            redacted_patch,
        )

    def test_review_patch_redacts_multiline_template_literal_per_line(self) -> None:
        first = "Abc123"
        second = "Def456"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f"word = decode(`{first}\n"
            + f"+{second}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn("decode(`redacted-a\n+redacted-b`)", redacted_patch)

    def test_review_patch_redacts_bigint_template_interpolation_literal(self) -> None:
        bigint = "12345678901234567890n"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`prefix${{{bigint}}}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(bigint, redacted_patch)
        self.assertIn("${redacted-b}", redacted_patch)

    def test_review_patch_redacts_numeric_looking_template_text(self) -> None:
        fixture_value = "123456789012.0"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`{fixture_value}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("decode(`redacted`)", redacted_patch)

    def test_review_patch_repeats_numeric_looking_template_redaction(self) -> None:
        fixture_value = "123456789012.0"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            f"+password = decode(`{fixture_value}`);\n"
            f'+log("{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('+log("redacted");', redacted_patch)

    def test_review_patch_redacts_integral_javascript_decimal_literals(
        self,
    ) -> None:
        for fixture_value in ("12345678.0", "1.2345678e7"):
            with self.subTest(fixture_value=fixture_value):
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    f"+password = decode(`${{{fixture_value}}}`);\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("decode(`${redacted}`)", redacted_patch)

    def test_review_patch_preserves_numeric_source_beside_secret_literal(
        self,
    ) -> None:
        numeric_source = "0.123456789012"
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode(`${{{numeric_source}}}`, "{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(f"${{{numeric_source}}}", redacted_patch)
        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('"redacted"', redacted_patch)

    def test_review_patch_redacts_bigint_before_member_access(self) -> None:
        fixture_value = "12345678n"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + "word = decode(`${"
            + fixture_value
            + ".toString()}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("${redacted.toString()}", redacted_patch)

    def test_review_patch_redacts_decimal_integer_before_member_access(self) -> None:
        fixture_value = "12345678"
        cases = (
            (
                "runtime.ts",
                "`prefix${" + fixture_value + "..toString()}`",
                "..toString()}",
            ),
            (
                "runtime.cs",
                '$"prefix{' + fixture_value + '.ToString()}"',
                ".ToString()}",
            ),
            (
                "runtime.kt",
                '"prefix${' + fixture_value + '.toString()}"',
                ".toString()}",
            ),
            (
                "runtime.groovy",
                '"prefix${' + fixture_value + '.toString()}"',
                ".toString()}",
            ),
        )
        for rel, literal, expected in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f"word = decode({literal})\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_preserves_template_interpolation_source_expression(self) -> None:
        literal = "10000000"
        expression = f"process.env.API_TOKEN+{literal}"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`${{{expression}}}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(literal, redacted_patch)
        self.assertIn("${process.env.API_TOKEN+redacted}", redacted_patch)

    def test_review_patch_redacts_template_comment_and_regex_literals(self) -> None:
        fixture_value = "Abc123Def456"
        for expression, expected in (
            (f"value /* {fixture_value} */", "value /* redacted */"),
            (f"/{fixture_value}/.source", "/redacted/.source"),
            (f"await /{fixture_value}/", "await /redacted/"),
            (f"yield /{fixture_value}/", "yield /redacted/"),
        ):
            with self.subTest(expression=expression):
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f"word = decode(`${{{expression}}}`);\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_redacts_javascript_regex_source(self) -> None:
        fixture_value = "Abc123Def456"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+password = decode(/{fixture_value}/.source);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("decode(/redacted/.source)", redacted_patch)

    def test_review_patch_stops_javascript_regex_at_unicode_terminator(
        self,
    ) -> None:
        fixture_value = "Abc" + "1234"
        key = "pass" + "word"
        separator = chr(0x2028)
        source = f"{key} = decode(/x{separator}`{fixture_value}`/)"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(separator, redacted_patch)

    def test_review_patch_redacts_aggregated_java_and_c_family_literals(
        self,
    ) -> None:
        key = "password"
        first = "abc" + "123"
        second = "def" + "456"
        cases = (
            (
                "Runtime.java",
                f'{key} = decode("{first}" + "{second}");',
            ),
            (
                "runtime.cpp",
                f'{key} = decode("{first}" "{second}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(first, redacted_patch)
                self.assertNotIn(second, redacted_patch)

    def test_review_patch_redacts_alphabetic_template_comment_literal(self) -> None:
        fixture_value = "abcdefghijklmnop"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode(`${{value /* "{fixture_value}" */}}`)\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('/* "redacted" */', redacted_patch)

    def test_review_patch_preserves_benign_template_interpolation_comments(
        self,
    ) -> None:
        comment = "credential comes from the vault"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`${{value /* {comment} */}}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(comment, redacted_patch)

    def test_review_patch_redacts_public_call_template_comment(self) -> None:
        fixture_value = "Abc1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = prompt(`${{value/*{fixture_value}*/}}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("${value/*redacted*/}", redacted_patch)

    def test_review_patch_preserves_qualified_public_prompt_text(self) -> None:
        for target in ("ui.prompt", "ui?.prompt"):
            source = f'{target}("Enter password for Service2")'
            with self.subTest(target=target):
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f"word = {source};\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertIn(source, redacted_patch)

    def test_review_patch_redacts_structured_public_prompt_literals(self) -> None:
        fixture_value = "Abc123" + "Def456"
        key = "password"
        quote = '"' * 3
        cases = (
            (
                "Runtime.java",
                f"String {key} = ui.prompt({quote}\n{fixture_value}\n{quote});",
                f"{quote}\n+redacted\n+{quote}",
            ),
            (
                "runtime.cpp",
                f'auto {key} = ui.prompt(R"({fixture_value})");',
                'R"(redacted)"',
            ),
        )
        for rel, source, expected in cases:
            with self.subTest(rel=rel):
                added_source = "+" + source.replace("\n", "\n+")
                line_count = source.count("\n") + 1
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    f"@@ -0,0 +1,{line_count} @@\n"
                    f"{added_source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_preserves_safe_credential_lookup_arguments(self) -> None:
        key = "password"
        source = f'{key} = headers.get("Authorization")'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_noninterpolating_reference_literals(
        self,
    ) -> None:
        key = "password"
        literal = "${VERY_LONG_" + "PASSWORD_ENVIRONMENT_VARIABLE}"
        for rel in ("Runtime.java", "runtime.cpp"):
            with self.subTest(rel=rel):
                source = f'{key} = decode("{literal}")'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(literal, redacted_patch)
                self.assertIn('decode("redacted")', redacted_patch)

    def test_review_patch_allows_template_continuing_beyond_hunk(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            "+const text = `value ${name}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn("`value ${name}", redacted_patch)

    def test_review_patch_redacts_known_secret_in_incomplete_template_tail(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            + "-pass"
            + f'word = "{fixture_value}"\n'
            + f"+const text = `prefix {fixture_value}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("+const text = `prefix redacted", redacted_patch)

    def test_review_patch_allows_inner_string_continuing_beyond_hunk(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            "+const text = `value ${\"continued\\\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('`value ${"continued\\', redacted_patch)

    def test_review_patch_redacts_known_secret_in_incomplete_inner_string(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            f'-password = "{fixture_value}"\n'
            f'+const text = `prefix ${{"{fixture_value}\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('${"redacted', redacted_patch)

    def test_review_patch_handles_javascript_template_comment_terminators(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        for terminator in ("\r", "\u2028", "\u2029"):
            with self.subTest(terminator=repr(terminator)):
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f"word = decode(`${{value//{fixture_value}{terminator}}}suffix`);\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(
                    f"//redacted{terminator}}}suffix",
                    redacted_patch,
                )

    def test_review_patch_handles_unicode_terminator_in_javascript_call_comment(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        terminator = "\u2028"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = runCommand(value, // note{terminator}"{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(f'// note{terminator}"redacted"', redacted_patch)

    def test_review_patch_redacts_combined_short_template_literals(self) -> None:
        first = "Abc123"
        second = "Def456"
        interpolations = '${"' + first + '"}${"' + second + '"}'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`{interpolations}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn("decode(`${\"redacted-a\"}${\"redacted-b\"}`)", redacted_patch)

    def test_review_patch_aggregates_template_literals_across_comments(
        self,
    ) -> None:
        key = "password"
        first = "Abc" + "123"
        second = "Def" + "456"
        expressions = (
            f'${{"{first}" /* note */ + "{second}"}}',
            f'${{"{first}" // note\n + "{second}"}}',
        )
        for expression in expressions:
            with self.subTest(expression=expression):
                source = f"{key} = decode(`{expression}`);"
                lines = source.splitlines()
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                    + "".join(f"+{line}\n" for line in lines)
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertNotIn(first, redacted_patch)
                self.assertNotIn(second, redacted_patch)
                self.assertIn("note", redacted_patch)

    def test_review_patch_redacts_combined_short_numeric_template_literals(self) -> None:
        first = "1234"
        second = "5678"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(`${{{first}}}${{{second}}}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn("decode(`${redacted}${redacted}`)", redacted_patch)

    def test_review_patch_redacts_literals_inside_call_comments(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode(/* "{fixture_value}" */ value);\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode(/* "redacted" */ value)', redacted_patch)

    def test_review_patch_allows_block_comment_continuing_beyond_hunk(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            "+run(value /* comment continues beyond available context\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn("comment continues beyond available context", redacted_patch)

    def test_review_patch_redacts_distinct_literals_inside_public_call_comments(
        self,
    ) -> None:
        first = "Abc1234"
        second = "Def5678"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + f'+password = prompt(/* "{first}" */);\n'
            + "+to"
            + f'ken = prompt(/* "{second}" */);\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn('prompt(/* "redacted-a" */)', redacted_patch)
        self.assertIn('prompt(/* "redacted-b" */)', redacted_patch)

    def test_review_patch_scans_after_python_floor_division(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode(100 // 25, "{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode(100 // 25, "redacted")', redacted_patch)

    def test_review_patch_preserves_identifier_after_python_floor_division(self) -> None:
        identifier = "ProdSecret123"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode(total // {identifier})\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)

    def test_review_patch_redacts_secret_after_python_assignment_floor_division(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        key = "pass" + "word"
        source = f'{key} = seed // divisor + decode("{fixture_value}")'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('// divisor + decode("redacted")', redacted_patch)

    def test_review_patch_bounds_python_floor_division_at_semicolon(self) -> None:
        fixture_value = "Prod" + "Secret123"
        key = "pass" + "word"
        source = f'{key} = total // 2; log("{fixture_value}")'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_python_floor_division_integer_secrets(
        self,
    ) -> None:
        fixture_value = "12345678"
        cases = (
            f"password = primary // {fixture_value}",
            f"password = decode(total // {fixture_value})",
        )
        for source in cases:
            with self.subTest(source=source):
                patch = (
                    "diff --git a/runtime.py b/runtime.py\n"
                    "--- a/runtime.py\n"
                    "+++ b/runtime.py\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.py"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_redacts_python_call_floor_division_suffix(self) -> None:
        fixture_value = "Prod" + "Secret123"
        source = f'password = get_value() // divisor + "{fixture_value}"'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(' + "redacted"', redacted_patch)

    def test_review_patch_redacts_fallback_after_javascript_private_field(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        key = "pass" + "word"
        source = f'{key} = this.#primary || "{fixture_value}";'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('this.#primary || "redacted"', redacted_patch)

    def test_review_patch_preserves_slash_comment_delimiters(self) -> None:
        fixture_value = "Prod123"
        for path in ("runtime.cc", "runtime.scala"):
            with self.subTest(path=path):
                patch = (
                    f"diff --git a/{path} b/{path}\n"
                    + f"--- a/{path}\n"
                    + f"+++ b/{path}\n"
                    + "@@ -0,0 +1,2 @@\n"
                    + "+pass"
                    + "word = runCommand(value, // apparent close )\n"
                    + f'+  "{fixture_value}");\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [path],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('// apparent close )\n+  "redacted"', redacted_patch)

    def test_review_patch_keeps_unicode_separator_inside_java_comment(self) -> None:
        fixture_value = "ProdSecret123"
        separator = "\u2028"
        patch = (
            "diff --git a/runtime.java b/runtime.java\n"
            "--- a/runtime.java\n"
            "+++ b/runtime.java\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f"word = runCommand(value, // apparent close {separator})\n"
            + f'+  "{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.java"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(
            f"// apparent close {separator})\n+  \"redacted\"",
            redacted_patch,
        )

    def test_review_patch_skips_regex_delimiters_in_ruby_and_swift(self) -> None:
        fixture_value = "Prod123"
        for path in ("runtime.rb", "runtime.swift"):
            with self.subTest(path=path):
                patch = (
                    f"diff --git a/{path} b/{path}\n"
                    + f"--- a/{path}\n"
                    + f"+++ b/{path}\n"
                    + "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f'word = runCommand(/[)]/, "{fixture_value}")\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [path],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('runCommand(/[)]/, "redacted")', redacted_patch)

    def test_review_patch_splits_ruby_regex_and_call_arguments_independently(
        self,
    ) -> None:
        fixture_value = "Abc123,Def456"
        patch = (
            "diff --git a/runtime.rb b/runtime.rb\n"
            "--- a/runtime.rb\n"
            "+++ b/runtime.rb\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt(/"/, "{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.rb"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt(/"/, "redacted")', redacted_patch)

    def test_review_patch_preserves_regex_parsing_for_unclassified_language(
        self,
    ) -> None:
        fixture_value = "Abc123,Def456"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt(/[)]/, "{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt(/[)]/, "redacted")', redacted_patch)

    def test_review_patch_redacts_groovy_slashy_credentials(self) -> None:
        for literal, expected in (
            ("/ProdSecret123/", "/redacted/"),
            ("$/ProdSecret123/$", "$/redacted/$"),
        ):
            with self.subTest(literal=literal):
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -0,0 +1 @@\n"
                    f"+password = decode({literal})\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn("ProdSecret123", redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_redacts_repeated_secret_in_groovy_slashy(self) -> None:
        fixture_value = "Prod" + "Secret123"
        for literal, expected in (
            (f"/{fixture_value}/", "/redacted/"),
            (f"$/{fixture_value}/$", "$/redacted/$"),
        ):
            with self.subTest(literal=literal):
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -1 +1 @@\n"
                    f'-password = "{fixture_value}"\n'
                    f"+def copy = {literal}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(f"+def copy = {expected}", redacted_patch)

    def test_review_patch_redacts_multiline_groovy_slashy_credential(
        self,
    ) -> None:
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1,2 @@\n"
            "+pass"
            "word = decode(/ProdSecret123\n"
            "+more/)\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn("ProdSecret123", redacted_patch)
        self.assertIn("decode(/redacted-a\n+redacted-b/)", redacted_patch)

    def test_review_patch_balances_groovy_dollar_slashy_arguments(self) -> None:
        fixture_value = "Abc123,Def456"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt($/[)]/$, "{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt($/[)]/$, "redacted")', redacted_patch)

    def test_review_patch_redacts_groovy_slashy_interpolation(self) -> None:
        for literal in (
            "/ProdSecret123${exfiltrate()}/",
            "$/ProdSecret123${exfiltrate()}/$",
        ):
            with self.subTest(literal=literal):
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -0,0 +1 @@\n"
                    f"+password = decode({literal})\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn("ProdSecret123", redacted_patch)
                self.assertIn("${exfiltrate()}", redacted_patch)

    def test_review_patch_redacts_groovy_slashy_after_interpolation_division(
        self,
    ) -> None:
        fixture_value = "Abcdefgh" + "1234"
        for literal in (
            f"/${{10 / 2}}{fixture_value}/",
            f"$/${{10 / 2}}{fixture_value}/$",
        ):
            with self.subTest(literal=literal):
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -0,0 +1 @@\n"
                    f"+password = decode({literal})\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("${10 / ", redacted_patch)

    def test_review_patch_preserves_groovy_slashy_escaped_parenthesis(
        self,
    ) -> None:
        source = r"def pattern = /\(/"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.groovy"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_benign_groovy_slashy_interpolation(
        self,
    ) -> None:
        source = "def greeting = /hello $name/"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.groovy"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_unrelated_groovy_slashy_interpolation(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        key = "pass" + "word"
        source = (
            f'{key} = "{fixture_value}"\n'
            "def greeting = /hello $name/"
        )
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1,2 @@\n"
            + "".join(f"+{line}\n" for line in source.splitlines())
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("def greeting = /hello $name/", redacted_patch)

    def test_review_patch_redacts_groovy_slashy_after_double_backslash(self) -> None:
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode(/prefix\\\\/ProdSecret123/)\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn("ProdSecret123", redacted_patch)
        self.assertIn("decode(/redacted/)", redacted_patch)

    def test_review_patch_preserves_escaped_dollar_slashy_value(self) -> None:
        source = "def home = $/$$HOME/$"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.groovy"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_regex_parsing_for_php_mixed_content(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.php b/runtime.php\n"
            "--- a/runtime.php\n"
            "+++ b/runtime.php\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = runCommand(/[)]/, "{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.php"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('runCommand(/[)]/, "redacted")', redacted_patch)

    def test_review_patch_redacts_python_triple_quoted_call_literal(self) -> None:
        fixture_value = "AlphaSecret123LongEnough999"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = decode("""{fixture_value}\n'
            + '+more""")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode("""redacted-a\n+redacted-b""")', redacted_patch)

    def test_review_patch_redacts_every_python_triple_quoted_literal_line(self) -> None:
        alphabetic_fragment = "SuperSecretAlphabeticFragment"
        numeric_fragment = "version123"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = decode("""{alphabetic_fragment}\n'
            + f'+{numeric_fragment}""")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(alphabetic_fragment, redacted_patch)
        self.assertNotIn(numeric_fragment, redacted_patch)
        self.assertIn('decode("""redacted-a\n+redacted-b""")', redacted_patch)

    def test_review_patch_preserves_python_fstring_expression(self) -> None:
        fixture_value = "Abc1234"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = decode(f"""{fixture_value}\n'
            + '+{exfiltrate()}""")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('f"""redacted\n+{exfiltrate()}"""', redacted_patch)

    def test_review_patch_preserves_whitespace_only_multiline_literal_line(
        self,
    ) -> None:
        first = "Abc1234"
        second = "Def5678"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,3 @@\n"
            + "+pass"
            + f'word = decode("""{first}\n'
            + "+   \n"
            + f'+{second}""")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn('"""redacted-a\n+   \n+redacted-b"""', redacted_patch)

    def test_review_patch_rejects_source_matching_multiline_fragment(self) -> None:
        source_identifier = "SharedIdentifier"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,3 @@\n"
            + "+pass"
            + 'word = decode("""Alpha123\n'
            + f'+{source_identifier}""")\n'
            + f"+{source_identifier} = value\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            )

    def test_review_patch_redacts_c_family_raw_multiline_call_literal(self) -> None:
        fixture_value = "AlphaSecret123LongEnough999"
        patch = (
            "diff --git a/runtime.cc b/runtime.cc\n"
            "--- a/runtime.cc\n"
            "+++ b/runtime.cc\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = decode(R"tag({fixture_value}\n'
            + '+more)tag");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cc"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode(R"tag(redacted-a\n+redacted-b)tag")', redacted_patch)

    def test_review_patch_redacts_adjacent_prefixed_c_family_literals(self) -> None:
        first = "".join(("Abc", "123"))
        second = "".join(("Def", "456"))
        literals = (
            f'u8"{first}" u8"{second}"',
            f'u8R"tag({first})tag" u8R"({second})"',
        )
        for literal in literals:
            with self.subTest(literal=literal):
                patch = (
                    "diff --git a/runtime.cpp b/runtime.cpp\n"
                    "--- a/runtime.cpp\n"
                    "+++ b/runtime.cpp\n"
                    "@@ -0,0 +1 @@\n"
                    "+pass"
                    + f"word = decode({literal});\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.cpp"],
                    patch,
                )

                self.assertNotIn(first, redacted_patch)
                self.assertNotIn(second, redacted_patch)

    def test_review_patch_allows_partial_benign_c_family_raw_hunks(self) -> None:
        sources = (
            'auto payload = R"tag(\nordinary text',
            'ordinary text\n)tag";',
        )
        for source in sources:
            with self.subTest(source=source):
                lines = source.splitlines()
                patch = (
                    "diff --git a/runtime.cpp b/runtime.cpp\n"
                    "--- a/runtime.cpp\n"
                    "+++ b/runtime.cpp\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                    + "".join(f"+{line}\n" for line in lines)
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        ["runtime.cpp"],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_allows_partial_benign_raw_secret_calls(self) -> None:
        key = "pass" + "word"
        cases = (
            ("runtime.cs", f'{key} = decode("""\nordinary'),
            ("runtime.cpp", f'{key} = decode(R"tag(\nordinary'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                lines = source.splitlines()
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                    + "".join(f"+{line}\n" for line in lines)
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_scans_arguments_before_partial_raw_literal(self) -> None:
        fixture_value = "Abc123Def456"
        cases = (
            ("runtime.cs", f'password = decode("{fixture_value}", """ok'),
            ("runtime.cpp", f'password = decode("{fixture_value}", R"tag(ok'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('decode("redacted", ', redacted_patch)

    def test_review_patch_rejects_partial_alphabetic_raw_secret_calls(
        self,
    ) -> None:
        key = "pass" + "word"
        for fixture_value in (
            "abcdefghijklmnop",
            "correct horse battery staple",
        ):
            cases = (
                ("runtime.cs", f'{key} = decode("""{fixture_value}'),
                ("runtime.cpp", f'{key} = decode(R"tag({fixture_value}'),
            )
            for rel, source in cases:
                with self.subTest(rel=rel, fixture_value=fixture_value):
                    patch = (
                        f"diff --git a/{rel} b/{rel}\n"
                        f"--- a/{rel}\n"
                        f"+++ b/{rel}\n"
                        "@@ -0,0 +1 @@\n"
                        f"+{source}\n"
                    )

                    with self.assertRaisesRegex(
                        SystemExit,
                        "secret-like content|unterminated.*raw string",
                    ):
                        self.helper["validate_review_patch"](
                            "local unstaged diff",
                            [rel],
                            patch,
                        )

    def test_review_patch_handles_variable_length_csharp_raw_string(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = runCommand(""""payload"""", "{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('runCommand(""""payload"""", "redacted")', redacted_patch)

    def test_review_patch_redacts_csharp_repeated_separator_integer(self) -> None:
        fixture_value = "12__345__678"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($"{{{fixture_value}}}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode($"{redacted}")', redacted_patch)

    def test_csharp_integer_syntax_accepts_repeated_separators(self) -> None:
        syntax = self.helper["integer_literal_syntax"]

        for literal in ("12__345__678", "0B__111", "0x__abc"):
            with self.subTest(literal=literal):
                self.assertTrue(syntax(literal, dialect="csharp"))
        for literal in ("12__", "0B111__", "0xabc__"):
            with self.subTest(literal=literal):
                self.assertFalse(syntax(literal, dialect="csharp"))

    def test_scala_integer_syntax_accepts_long_and_repeated_separators(
        self,
    ) -> None:
        syntax = self.helper["integer_literal_syntax"]

        for literal in ("12__345__678L", "0B__111l", "0x__abcL"):
            with self.subTest(literal=literal):
                self.assertTrue(syntax(literal, dialect="scala"))
        for literal in ("12__", "123u", "0o777", "0B111__L", "0xabc__L"):
            with self.subTest(literal=literal):
                self.assertFalse(syntax(literal, dialect="scala"))

    def test_review_patch_redacts_scala_long_interpolation(self) -> None:
        fixture_value = "12__345__678L"
        source = f'password = decode(s"${{{fixture_value}}}")'
        patch = (
            "diff --git a/runtime.scala b/runtime.scala\n"
            "--- a/runtime.scala\n"
            "+++ b/runtime.scala\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.scala"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('decode(s"${redacted}")', redacted_patch)

    def test_review_patch_scans_scala_hash_operator_suffix(self) -> None:
        fixture_value = "Horse7battery"
        patch = (
            "diff --git a/runtime.scala b/runtime.scala\n"
            "--- a/runtime.scala\n"
            "+++ b/runtime.scala\n"
            "@@ -0,0 +1 @@\n"
            f'+password = credentials.value # "{fixture_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.scala"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('# "redacted"', redacted_patch)

    def test_c_family_preprocessor_string_keeps_string_context(self) -> None:
        text = '#define TOKEN "Horse7battery"'
        value_start = text.index("Horse7battery")

        contexts = self.helper["string_contexts_at"](
            text,
            {value_start},
            javascript_dialect="c-family",
        )

        self.assertIsNotNone(contexts[value_start])

    def test_review_patch_redacts_csharp_integer_beside_range_operator(
        self,
    ) -> None:
        fixture_value = "12345678"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($"{{..{fixture_value}}}:{{{fixture_value}..}}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("{..redacted-a}", redacted_patch)
        self.assertIn("{redacted-a..}", redacted_patch)

    def test_csharp_integer_scan_excludes_decimal_points(self) -> None:
        text = "0.12345678 12345678.0"

        spans = self.helper["integer_literal_spans"](
            text,
            0,
            len(text),
            dialect="csharp",
        )

        self.assertEqual(spans, [])

    def test_csharp_raw_literal_closes_at_end_of_quote_run(self) -> None:
        text = '"""safe"""", "ProdSecret123"'

        raw = self.helper["csharp_raw_literal_span"](
            text,
            0,
            len(text),
        )
        spans, _ = self.helper["quoted_literal_value_spans"](
            text,
            0,
            len(text),
            javascript_dialect="csharp",
            collect_all_literals=True,
        )

        self.assertIsNotNone(raw)
        assert raw is not None
        self.assertEqual(text[raw[0] : raw[1]], 'safe"')
        self.assertEqual(text[raw[2] :], ', "ProdSecret123"')
        self.assertIn("ProdSecret123", [text[start:end] for start, end in spans])

    def test_csharp_raw_context_consumes_exact_literal_boundary(self) -> None:
        text = '"""safe""""; ProdSecret123()'
        raw_value = text.index("safe")
        call_target = text.index("ProdSecret123")

        contexts = self.helper["string_contexts_at"](
            text,
            {raw_value, call_target},
            javascript_dialect="csharp",
        )

        self.assertIsNotNone(contexts[raw_value])
        self.assertIsNone(contexts[call_target])

    def test_review_patch_splits_csharp_raw_public_call_argument(self) -> None:
        fixture_value = "ProdSecret123,tail"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt(""""{fixture_value}"""");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt(""""redacted"""")', redacted_patch)

    def test_review_patch_preserves_csharp_raw_interpolation_expression(self) -> None:
        fixture_value = "Abc1234"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = decode($""""{fixture_value}\n'
            + '+{exfiltrate()}"""");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('$""""redacted\n+{exfiltrate()}""""', redacted_patch)

    def test_review_patch_balances_nested_csharp_raw_interpolation_braces(self) -> None:
        fixture_value = "Abc1234"
        expression = "(new A { B = new B { X = 1 }}).Exfiltrate()"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($$""""{fixture_value} {{{{{expression}}}}}"""");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(f'$$""""redacted{{{{{expression}}}}}""""', redacted_patch)

    def test_review_patch_parses_verbatim_string_inside_csharp_raw_interpolation(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        expression = r'Get(@"C:\")'
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($"""{fixture_value}{{{expression}}}""");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("C:\\", redacted_patch)
        self.assertIn(f'$"""redacted{{{expression}}}"""', redacted_patch)

    def test_review_patch_groups_excess_csharp_raw_braces_from_inside(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($$"""{{{{{{value:{fixture_value}}}}}}}""");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('$$"""{{{value:redacted}}}"""', redacted_patch)

    def test_review_patch_preserves_python_template_string_source(self) -> None:
        fixture_value = "Abc1234"
        expression = "exfiltrate1234()"
        for prefix in ("t", "tr", "rt"):
            with self.subTest(prefix=prefix):
                patch = (
                    "diff --git a/runtime.py b/runtime.py\n"
                    "--- a/runtime.py\n"
                    "+++ b/runtime.py\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f'word = decode({prefix}"{fixture_value}{{{expression}}}")\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.py"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(f'{prefix}"redacted{{{expression}}}"', redacted_patch)

    def test_review_patch_preserves_raw_fstring_field_after_backslash(self) -> None:
        expression = 'Evil1234("arg")'
        source = f'rf"\\{{{expression}}}"'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode({source})\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertIn(source, redacted_patch)

    def test_review_patch_closes_raw_fstring_after_even_backslashes(self) -> None:
        fixture_value = "Secret123"
        expression = "exfiltrate()"
        source = f'rf"{fixture_value}{{{expression}}}\\\\"'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f"word = decode({source})\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(f'rf"redacted{{{expression}}}\\\\"', redacted_patch)

    def test_secret_detector_checks_csharp_raw_interpolation_source(self) -> None:
        content = (
            'pass'
            + 'word = decode($$""""redacted {{Get("hardcodedcredential")}}"""")'
        )

        self.assertTrue(
            self.helper["secret_text_risk"](
                content,
                javascript_dialect="csharp",
            )
        )

    def test_secret_detector_allows_non_javascript_member_interpolation(
        self,
    ) -> None:
        cases = (
            (
                "python",
                'pass' + 'word = decode(f"{credential_store.authentication_token}")',
            ),
            (
                "csharp",
                'pass' + 'word = decode($"{credentialStore.AuthenticationToken}")',
            ),
        )

        for dialect, content in cases:
            with self.subTest(dialect=dialect):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        content,
                        javascript_dialect=dialect,
                    )
                )

    def test_review_patch_preserves_non_javascript_member_interpolation(
        self,
    ) -> None:
        cases = (
            (
                "runtime.py",
                'pass' + 'word = decode(f"{credential_store.authentication_token}")',
            ),
            (
                "runtime.cs",
                'pass' + 'word = decode($"{credentialStore.AuthenticationToken}");',
            ),
        )

        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertIn(source, redacted_patch)

    def test_review_patch_preserves_java_member_credential_reference(self) -> None:
        key = "password"
        source = f"{key} = credentialStore.authenticationToken;"
        patch = (
            "diff --git a/Runtime.java b/Runtime.java\n"
            "--- a/Runtime.java\n"
            "+++ b/Runtime.java\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.java"],
                patch,
            ),
            patch,
        )

    def test_review_patch_rejects_java_unicode_escapes(self) -> None:
        key = "password"
        quote_escape = "\\" + "u0022"
        fixture_value = "Prod" + "Secret123"
        source = (
            f"{key} = {quote_escape}"
            + fixture_value
            + f"{quote_escape};"
        )
        patch = (
            "diff --git a/Runtime.java b/Runtime.java\n"
            "--- a/Runtime.java\n"
            "+++ b/Runtime.java\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        with self.assertRaisesRegex(SystemExit, "secret-like content"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.java"],
                patch,
            )

    def test_java_unicode_translation_tracks_translated_backslashes(self) -> None:
        escape = lambda digits: "\\" + "u" + digits
        source = escape("005c") + "\\" + escape("006e")

        self.assertEqual(
            self.helper["java_unicode_escape_translation"](source),
            "\\\\n",
        )

    def test_review_patch_rejects_java_escape_after_translated_backslash(
        self,
    ) -> None:
        escape = lambda digits: "\\" + "u" + digits
        fixture_value = "Prod" + "Secret123"
        source = (
            'password = "'
            + fixture_value
            + escape("005c")
            + "\\"
            + escape("0022")
            + ";"
        )
        patch = (
            "diff --git a/Runtime.java b/Runtime.java\n"
            "--- a/Runtime.java\n"
            "+++ b/Runtime.java\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        with self.assertRaisesRegex(SystemExit, "secret-like content"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.java"],
                patch,
            )

    def test_review_patch_preserves_harmless_java_unicode_escape(self) -> None:
        escape = "\\" + "u00A9"
        source = f'String copyright = "{escape}";'
        patch = (
            "diff --git a/Runtime.java b/Runtime.java\n"
            "--- a/Runtime.java\n"
            "+++ b/Runtime.java\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.java"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_kotlin_backtick_call_target(self) -> None:
        fixture_value = "Prod" + "Secret123"
        source = f'password = decode("${{obj.`{fixture_value}`()}}")'
        patch = (
            "diff --git a/Runtime.kt b/Runtime.kt\n"
            "--- a/Runtime.kt\n"
            "+++ b/Runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.kt"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_jvm_backtick_identifier_assignments(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        for rel in ("Runtime.kt", "Runtime.scala"):
            with self.subTest(rel=rel):
                source = f"password = `{fixture_value}`"
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_kotlin_backtick_target_does_not_hide_nested_literal(self) -> None:
        fixture_value = "Prod" + "Secret123"
        source = f'password = decode("${{obj.`safe target`("{fixture_value}")}}")'

        spans, _ = self.helper["quoted_literal_value_spans"](
            source,
            0,
            len(source),
            javascript_dialect="kotlin",
        )

        self.assertIn(fixture_value, {source[start:end] for start, end in spans})
        self.assertNotIn("safe target", {source[start:end] for start, end in spans})

    def test_review_patch_preserves_scala_backtick_call_argument(self) -> None:
        fixture_value = "Prod" + "Secret123"
        source = f"password = decode(`{fixture_value}`)"
        patch = (
            "diff --git a/Runtime.scala b/Runtime.scala\n"
            "--- a/Runtime.scala\n"
            "+++ b/Runtime.scala\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.scala"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_known_triple_interpolation_source(
        self,
    ) -> None:
        def kotlin_triple_source(value: str, interpolation: str) -> str:
            key = "pass" + "word"
            return f'{key} = decode("""{value} {interpolation}""")'

        interpolations = (
            "${" + "".join(("exfil", "trate()")) + "}",
            "$" + "凭据变量" + str(12345678),
        )
        for interpolation in interpolations:
            with self.subTest(interpolation=interpolation):
                source = kotlin_triple_source("ProdSecret123", interpolation)
                lines = source.splitlines()
                patch = (
                    "diff --git a/runtime.kt b/runtime.kt\n"
                    "--- a/runtime.kt\n"
                    "+++ b/runtime.kt\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                    + "".join(f"+{line}\n" for line in lines)
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.kt"],
                    patch,
                )

                self.assertNotIn("ProdSecret123", redacted_patch)
                self.assertIn(interpolation, redacted_patch)

    def test_review_patch_redacts_nested_kotlin_raw_string_literal(self) -> None:
        key = "password"
        quote = '"' * 3
        fixture_value = "Prod" + "Secret123"
        source = (
            f"{key} = decode({quote}"
            + "${id("
            + quote
            + fixture_value
            + quote
            + ")}"
            + f"{quote})"
        )
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("${id(", redacted_patch)

    def test_review_patch_redacts_nested_groovy_triple_string_literal(self) -> None:
        key = "pass" + "word"
        quote = '"' * 3
        fixture_value = "Prod" + "Secret123"
        source = (
            f"{key} = decode({quote}"
            + "${id("
            + quote
            + fixture_value
            + quote
            + ")}"
            + f"{quote})"
        )
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("${id(", redacted_patch)

    def test_review_patch_ignores_triple_assignment_text_in_comments(self) -> None:
        source = '// password = """'
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_preserves_reference_only_swift_scala_triples(
        self,
    ) -> None:
        cases = (
            ("runtime.swift", 'password = decode("""\\(value)""")'),
            ("runtime.scala", 'password = decode(s"""$value""")'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_preserves_swift_scala_triple_interpolation_source(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        cases = (
            (
                "runtime.swift",
                f'password = decode("""{fixture_value} \\(value)""")',
                "\\(value)",
            ),
            (
                "runtime.scala",
                f'password = decode(s"""{fixture_value} $value""")',
                "$value",
            ),
        )
        for rel, source, interpolation in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(interpolation, redacted_patch)

    def test_review_patch_preserves_swift_scala_ordinary_interpolation_source(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        cases = (
            (
                "runtime.swift",
                f'password = decode("{fixture_value} \\(value)")',
                "\\(value)",
            ),
            (
                "runtime.swift",
                f'password = decode(#"{fixture_value} \\#(value)"#)',
                "\\#(value)",
            ),
            (
                "runtime.scala",
                f'password = decode(s"{fixture_value} $value")',
                "$value",
            ),
        )
        for rel, source, interpolation in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(interpolation, redacted_patch)

    def test_review_patch_rejects_swift_scala_interpolation_source_collision(
        self,
    ) -> None:
        fixture_value = "Evil" + "1234"
        cases = (
            ("runtime.swift", f'"""\\({fixture_value}())"""'),
            ("runtime.scala", f's"""${{{fixture_value}()}}"""'),
        )
        for rel, interpolation in cases:
            with self.subTest(rel=rel):
                source = f'password = "{fixture_value}"\nlet copy = {interpolation}'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1,2 @@\n"
                    + "".join(f"+{line}\n" for line in source.splitlines())
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    "known secret-like value",
                ):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    )

    def test_review_patch_rejects_swift_scala_ordinary_source_collision(
        self,
    ) -> None:
        fixture_value = "Evil" + "1234"
        cases = (
            ("runtime.swift", f'"\\({fixture_value}())"'),
            ("runtime.swift", f'#"\\#({fixture_value}())"#'),
            ("runtime.scala", f's"${{{fixture_value}()}}"'),
        )
        for rel, interpolation in cases:
            with self.subTest(rel=rel, interpolation=interpolation):
                source = f'password = "{fixture_value}"\nlet copy = {interpolation}'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1,2 @@\n"
                    + "".join(f"+{line}\n" for line in source.splitlines())
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    "known secret-like value",
                ):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    )

    def test_scala_triple_quote_closes_after_backslash(self) -> None:
        marker = '"' * 3
        source = "s" + marker + "value" + "\\" + marker + "; exfiltrate()"

        span = self.helper["triple_quoted_literal_span"](
            source,
            1,
            len(source),
            interpolation_dialect="scala",
        )

        self.assertIsNotNone(span)
        assert span is not None
        self.assertEqual(span[2], source.index(";"))

    def test_scala_interpolated_quote_escape_does_not_close_literal(self) -> None:
        source = 'password = decode(s"safe$"text")'
        patch = (
            "diff --git a/runtime.scala b/runtime.scala\n"
            "--- a/runtime.scala\n"
            "+++ b/runtime.scala\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.scala"],
                patch,
            ),
            patch,
        )

    def test_scala_triple_quote_closes_at_end_of_quote_run(self) -> None:
        marker = '"' * 3
        source = "s" + marker + "value" + '"' * 4

        span = self.helper["triple_quoted_literal_span"](
            source,
            1,
            len(source),
            interpolation_dialect="scala",
        )

        self.assertEqual(span, (4, len(source) - 3, len(source)))

    def test_swift_scala_triple_string_contexts_exclude_interpolation_source(
        self,
    ) -> None:
        cases = (
            (
                "swift",
                '"""literal \\(credentialCall("nested value"))"""',
            ),
            (
                "scala",
                's"""literal ${credentialCall("nested value")}"""',
            ),
        )
        for dialect, source in cases:
            with self.subTest(dialect=dialect):
                positions = {
                    source.index("literal"),
                    source.index("credentialCall"),
                    source.index("nested value"),
                }
                contexts = self.helper["string_contexts_at"](
                    source,
                    positions,
                    javascript_dialect=dialect,
                )

                self.assertIsNotNone(contexts[source.index("literal")])
                self.assertIsNone(contexts[source.index("credentialCall")])
                self.assertIsNotNone(contexts[source.index("nested value")])

    def test_swift_scala_ordinary_contexts_exclude_interpolation_source(
        self,
    ) -> None:
        cases = (
            (
                "swift",
                '#"literal \\#(credentialCall("nested value"))"#',
            ),
            (
                "scala",
                's"literal ${credentialCall("nested value")}"',
            ),
        )
        for dialect, source in cases:
            with self.subTest(dialect=dialect):
                positions = {
                    source.index("literal"),
                    source.index("credentialCall"),
                    source.index("nested value"),
                }
                contexts = self.helper["string_contexts_at"](
                    source,
                    positions,
                    javascript_dialect=dialect,
                )

                self.assertIsNotNone(contexts[source.index("literal")])
                self.assertIsNone(contexts[source.index("credentialCall")])
                self.assertIsNotNone(contexts[source.index("nested value")])

    def test_review_patch_redacts_standalone_comment_credential(self) -> None:
        fixture_value = "Prod" + "Secret123"
        key = "pass" + "word"
        source = f'// {key} = "{fixture_value}"'
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(f'// {key} = "redacted"', redacted_patch)

    def test_review_patch_redacts_assignment_embedded_in_literal(self) -> None:
        fixture_value = "CorrectHorse7" + "Battery"
        source = f'''const cmd = 'password="{fixture_value}"';'''
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('password="redacted"', redacted_patch)

    def test_review_patch_redacts_complex_assignment_embedded_in_literal(
        self,
    ) -> None:
        fixture_value = "CorrectHorse7" + "Battery"
        for value in (
            f'decode("{fixture_value}")',
            f'primary || "{fixture_value}"',
        ):
            with self.subTest(value=value):
                source = f"const cmd = 'password = {value}';"
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.ts"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_rejects_secret_collision_in_triple_source(self) -> None:
        fixture_value = "EvilSecret123"
        source = "pass" + f'word = "{fixture_value}"\n"""${{{fixture_value}()}}"""'
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1,2 @@\n"
            + "".join(f"+{line}\n" for line in source.splitlines())
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.kt"],
                patch,
            )

    def test_review_patch_redacts_python_field_after_backslash(self) -> None:
        fixture_value = "ProdSecret123"
        source = f'password = decode(f"\\{{get(\"{fixture_value}\")}}")'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('f"\\{get("redacted")}"', redacted_patch)

    def test_review_patch_redacts_grouped_short_numeric_fields(self) -> None:
        for rel, literal in (
            ("runtime.py", 'f"{1234}{5678}"'),
            ("runtime.cs", '$"{1234}{5678}"'),
        ):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f"word = decode({literal})\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn("1234", redacted_patch)
                self.assertNotIn("5678", redacted_patch)

    def test_review_patch_redacts_concatenated_short_template_literals(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode(`${"Abc123" + "Def456"}`)\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("Abc123", redacted_patch)
        self.assertNotIn("Def456", redacted_patch)

    def test_review_patch_redacts_prefixed_nested_string_fragments(self) -> None:
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode(f\'{f"Abc123"}{f"Def456"}\')\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn("Abc123", redacted_patch)
        self.assertNotIn("Def456", redacted_patch)

    def test_review_patch_checks_placeholder_as_part_of_template_value(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode(`redacted${"123456"}`)\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("123456", redacted_patch)

    def test_review_patch_redacts_kotlin_triple_prompt_argument(self) -> None:
        fixture_value = 'Prod"Secret123,Abc456'
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = ui.prompt("""{fixture_value}""")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('ui.prompt("""redacted""")', redacted_patch)

    def test_review_patch_rejects_incomplete_csharp_raw_string(self) -> None:
        for prefix in ("", "$", "$$"):
            with self.subTest(prefix=prefix):
                patch = (
                    "diff --git a/runtime.cs b/runtime.cs\n"
                    "--- a/runtime.cs\n"
                    "+++ b/runtime.cs\n"
                    "@@ -0,0 +1,2 @@\n"
                    + "+pass"
                    + f'word = decode({prefix}"""\n'
                    "+ProdSecret123\n"
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    "unterminated C# raw string",
                ):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        ["runtime.cs"],
                        patch,
                    )

    def test_review_patch_allows_partial_benign_csharp_raw_string_hunks(
        self,
    ) -> None:
        quote = '"' * 3
        sources = (
            f"const payload = {quote}\nordinary text",
            f"ordinary text\n{quote};",
        )
        for source in sources:
            with self.subTest(source=source):
                lines = source.splitlines()
                patch = (
                    "diff --git a/runtime.cs b/runtime.cs\n"
                    "--- a/runtime.cs\n"
                    "+++ b/runtime.cs\n"
                    f"@@ -0,0 +1,{len(lines)} @@\n"
                    + "".join(f"+{line}\n" for line in lines)
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        ["runtime.cs"],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_rejects_truncated_interpolated_csharp_raw_literal(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + f'+const payload = $"""{fixture_value}\n'
        )

        with self.assertRaisesRegex(
            SystemExit,
            "unterminated C# raw string",
        ):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.cs"],
                patch,
            )

    def test_review_patch_rejects_truncated_structured_literals(self) -> None:
        fixture_value = "a" * 19
        for rel, source in (
            (
                "runtime.py",
                "".join(("pass", f'word = decode("""{fixture_value}')),
            ),
            (
                "runtime.cs",
                "".join(("pass", f'word = decode($@"{fixture_value}')),
            ),
        ):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    "unterminated secret call",
                ):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    )

    def test_review_patch_rejects_multiline_truncated_call_tail(self) -> None:
        fixture_value = "a" * 19
        source_lines = (
            "".join(("pass", "word = decode(")),
            f'    """{fixture_value}',
        )
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            + "".join(f"+{line}\n" for line in source_lines)
        )

        with self.assertRaisesRegex(
            SystemExit,
            "unterminated secret call",
        ):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            )

    def test_review_patch_rejects_two_word_truncated_raw_secret_call(self) -> None:
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+password = decode(\"\"\"\n"
            "+alphabet soup\n"
        )

        with self.assertRaisesRegex(
            SystemExit,
            "unterminated secret call",
        ):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            )

    def test_review_patch_redacts_direct_structured_secret_assignments(
        self,
    ) -> None:
        fixture_value = "Abc123" + "Def456"
        cases = (
            ("runtime.py", f'password = \"\"\"{fixture_value}\"\"\"'),
            ("runtime.py", f'password = f\"{fixture_value}\"'),
            ("runtime.cs", f'password = $\"\"\"{fixture_value}\"\"\";'),
            ("runtime.cpp", f'password = R\"tag({fixture_value})tag\";'),
            ("runtime.swift", f'password = #\"{fixture_value}\"#'),
            ("runtime.scala", f'password = s\"{fixture_value}\"'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_applies_assignment_minimum_to_structured_literals(
        self,
    ) -> None:
        fixture_value = "abcdefgh"
        cases = (
            ("runtime.py", f'password = b"{fixture_value}"'),
            ("runtime.cs", f'password = $"{fixture_value}";'),
            ("runtime.cs", f'password = """{fixture_value}""";'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_redacts_after_swift_scala_nested_delimiters(
        self,
    ) -> None:
        fixture_value = "Prod" + "Secret123"
        cases = (
            (
                "runtime.swift",
                f'password = decode(#"safe )" inside"#, "{fixture_value}")',
            ),
            (
                "runtime.scala",
                f'password = decode(s"${{format("safe )")}}", "{fixture_value}")',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_redacts_after_swift_extended_regex(self) -> None:
        fixture_value = "Prod" + "Secret123"
        source = f'password = decode(#/)/#, "{fixture_value}")'
        patch = (
            "diff --git a/runtime.swift b/runtime.swift\n"
            "--- a/runtime.swift\n"
            "+++ b/runtime.swift\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.swift"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('#/)/#, "redacted"', redacted_patch)

    def test_review_patch_prioritizes_c_family_raw_delimiter(self) -> None:
        fixture_value = "Abc" + "12345"
        source = f'password = decode(R"""(safe"""{fixture_value})""");'
        patch = (
            "diff --git a/runtime.cpp b/runtime.cpp\n"
            "--- a/runtime.cpp\n"
            "+++ b/runtime.cpp\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cpp"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("redacted", redacted_patch)

    def test_review_patch_redacts_incomplete_direct_structured_assignments(
        self,
    ) -> None:
        fixture_value = "alphabet soup"
        cases = (
            ("runtime.py", f'password = """{fixture_value}'),
            ("runtime.cs", f'password = """{fixture_value}'),
            ("runtime.cpp", f'password = R"tag({fixture_value}'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_closes_kotlin_raw_string_after_backslash(self) -> None:
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode("""ProdSecret123\\"""); exfiltrate()\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn("ProdSecret123", redacted_patch)
        self.assertIn("exfiltrate()", redacted_patch)

    def test_review_patch_redacts_literals_inside_non_javascript_interpolations(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        cases = (
            (
                "runtime.cs",
                "pass"
                + f'word = decode($$""""{{{{Get("{fixture_value}")}}}}"""")',
            ),
            (
                "runtime.py",
                "pass"
                + f'word = decode(f"""{{get("{fixture_value}")}}""")',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                expected = (
                    'Get("redacted")'
                    if rel.endswith(".cs")
                    else 'get("redacted")'
                )
                self.assertIn(expected, redacted_patch)

    def test_review_patch_aggregates_non_javascript_interpolation_fragments(
        self,
    ) -> None:
        cases = (
            ("runtime.cs", 'pass' + 'word = decode($"""Abc123{"Def456"}""");'),
            ("runtime.py", 'pass' + 'word = decode(f"""Abc123{"Def456"}""")'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn("Abc123", redacted_patch)
                self.assertNotIn("Def456", redacted_patch)
                self.assertIn('redacted-a{"redacted-b"}', redacted_patch)

    def test_review_patch_aggregates_swift_interpolation_fragments(self) -> None:
        cases = (
            'password = decode("\\("Abc123")\\("Def456")")',
            'password = decode(#"\\#("Abc123")\\#("Def456")"#)',
        )
        for source in cases:
            with self.subTest(source=source):
                patch = (
                    "diff --git a/runtime.swift b/runtime.swift\n"
                    "--- a/runtime.swift\n"
                    "+++ b/runtime.swift\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.swift"],
                    patch,
                )

                self.assertNotIn("Abc123", redacted_patch)
                self.assertNotIn("Def456", redacted_patch)

    def test_review_patch_preserves_calls_before_nested_multiline_literals(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        cases = (
            (
                "runtime.cs",
                'pass'
                + f'word = decode($"""{fixture_value}'
                + '{Evil1234("""nested""")}""");',
            ),
            (
                "runtime.py",
                'pass'
                + f'word = decode(f"""{fixture_value}'
                + '{Evil1234("""nested""")}""")',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('Evil1234("""nested""")', redacted_patch)

    def test_review_patch_preserves_ordinary_interpolation_expressions(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        cases = (
            (
                "runtime.py",
                'pass' + f'word = decode(f"{fixture_value}{{exfiltrate()}}")',
                'f"redacted{exfiltrate()}"',
            ),
            (
                "runtime.cs",
                'pass' + f'word = decode($"{fixture_value}{{exfiltrate()}}");',
                '$"redacted{exfiltrate()}"',
            ),
        )
        for rel, source, expected in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_preserves_direct_groovy_kotlin_interpolation(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        for rel in ("runtime.groovy", "runtime.kt"):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f'+password = "{fixture_value}${{runDangerousOperation()}}"\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(
                    '"redacted${runDangerousOperation()}"',
                    redacted_patch,
                )

    def test_review_patch_preserves_groovy_gstring_expression(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.groovy b/runtime.groovy\n"
            "--- a/runtime.groovy\n"
            "+++ b/runtime.groovy\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode("{fixture_value}${{exfiltrate()}}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.groovy"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('"redacted${exfiltrate()}"', redacted_patch)

    def test_review_patch_redacts_nested_dollar_interpolation_literal(self) -> None:
        fixture_value = "ProdSecret123"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f'word = decode("${{lookup("{fixture_value}")}}")\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('${lookup("redacted")}', redacted_patch)

    def test_review_patch_balances_dollar_interpolation_call_arguments(self) -> None:
        fixture_value = "ProdSecret123"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source = (
                    'password = decode("${lookup(")")}", "'
                    + fixture_value
                    + '")'
                )
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('${lookup(")")}', redacted_patch)
                self.assertIn(', "redacted")', redacted_patch)

    def test_review_patch_redacts_dollar_interpolation_integer(self) -> None:
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + 'word = decode("${12345678}")\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn("12345678", redacted_patch)
                self.assertIn("${redacted}", redacted_patch)

    def test_review_patch_redacts_integer_before_escaped_member_access(
        self,
    ) -> None:
        key = "password"
        first = "1234"
        second = "5678"
        cases = (
            ("runtime.kt", f"`toString`", "${redacted.`toString`()}"),
            ("runtime.groovy", "'toString'", "${redacted.'toString'()}"),
        )
        for rel, member, expected in cases:
            with self.subTest(rel=rel):
                source = (
                    f'{key} = decode("${{'
                    + first
                    + second
                    + f".{member}()}}\")"
                )
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(first + second, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_redacts_integer_range_interpolations(self) -> None:
        key = "password"
        number = "1234" + "5678"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source = f'{key} = decode("${{({number}..{number}).first}}")'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(number, redacted_patch)

    def test_review_patch_redacts_aggregated_dollar_interpolation_integers(
        self,
    ) -> None:
        key = "password"
        first = "12" + "34"
        second = "56" + "78"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source = f'{key} = decode("${{{first}}}${{{second}}}")'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn("1234", redacted_patch)
                self.assertNotIn("5678", redacted_patch)
                self.assertIn('${redacted}${redacted}', redacted_patch)

    def test_review_patch_scans_groovy_single_quoted_dollars_as_literals(
        self,
    ) -> None:
        fixture_value = "$ProdSecret123"
        for marker in ("'", "'''"):
            with self.subTest(marker=marker):
                source = "pass" + f"word = runCommand({marker}{fixture_value}{marker})"
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(f"runCommand({marker}redacted{marker})", redacted_patch)

    def test_review_patch_preserves_benign_dollar_triple_strings(self) -> None:
        cases = (
            ("runtime.kt", 'val greeting = """hello $name"""'),
            ("runtime.groovy", 'def greeting = """hello $name"""'),
            ("runtime.kt", r'val regex = """\("""'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_preserves_java_text_block_placeholder(self) -> None:
        quote = '"' * 3
        patch = (
            "diff --git a/Runtime.java b/Runtime.java\n"
            "--- a/Runtime.java\n"
            "+++ b/Runtime.java\n"
            "@@ -0,0 +1,3 @@\n"
            f"+String template = {quote}\n"
            "+hello ${name}\n"
            f"+{quote};\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["Runtime.java"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_dollar_triple_string_literal_segments(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source = "pass" + f'word = """{fixture_value} $name"""'
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('"""redacted$name"""', redacted_patch)

    def test_review_patch_honors_kotlin_multi_dollar_interpolation(self) -> None:
        key = "password"
        fixture_value = "$Abc1234"
        literal_source = f'{key} = decode($$"""{fixture_value}""")'
        interpolation_source = (
            f'{key} = decode($$"""'
            + "$${credentialStore.authenticationToken}"
            + '""")'
        )
        for source, expected_redaction in (
            (literal_source, '$$"""redacted"""'),
            (interpolation_source, None),
        ):
            with self.subTest(source=source):
                patch = (
                    "diff --git a/runtime.kt b/runtime.kt\n"
                    "--- a/runtime.kt\n"
                    "+++ b/runtime.kt\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.kt"],
                    patch,
                )

                if expected_redaction is None:
                    self.assertEqual(redacted_patch, patch)
                else:
                    self.assertNotIn(fixture_value, redacted_patch)
                    self.assertIn(expected_redaction, redacted_patch)

    def test_review_patch_redacts_direct_kotlin_multi_dollar_assignment(
        self,
    ) -> None:
        fixture_value = "Abc123Def456"
        source = f'password = $$"""{fixture_value}"""'
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('password = $$"""redacted"""', redacted_patch)

    def test_review_patch_uses_trailing_kotlin_multi_dollar_marker(self) -> None:
        key = "password"
        fixture_value = "Prod" + "Secret123"
        interpolation = "$${" + "exfiltrate()" + "}"
        source = (
            f'{key} = decode($$"""{fixture_value} '
            + "$"
            + interpolation
            + '""")'
        )
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(interpolation, redacted_patch)

    def test_review_patch_preserves_kotlin_raw_backslash_interpolation(
        self,
    ) -> None:
        key = "password"
        fixture_value = "Abc1234"
        interpolation = "${exfiltrate()}"
        source = f'{key} = decode("""{fixture_value}\\{interpolation}""")'
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.kt"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(interpolation, redacted_patch)

    def test_review_patch_preserves_dollar_member_credential_references(
        self,
    ) -> None:
        key = "password"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source = (
                    f'{key} = decode("'
                    + "${credentialStore.authenticationToken}"
                    + '")'
                )
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_redacts_python_fallback_after_floor_division(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        key = "password"
        source = " ".join(
            (
                key,
                "=",
                "primary",
                "/" * 2,
                "divisor",
                "or",
                repr(fixture_value),
            )
        )
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("or 'redacted'", redacted_patch)

    def test_review_patch_rejects_excessive_dollar_interpolation_nesting(
        self,
    ) -> None:
        expression = '"safe"'
        for _ in range(66):
            expression = '"${' + expression + '}"'

        with self.assertRaisesRegex(
            SystemExit,
            "excessive interpolation nesting",
        ):
            self.helper["secret_literal_risk"](
                expression,
                javascript_dialect="kotlin",
            )

    def test_review_patch_preserves_benign_kotlin_interpolation(self) -> None:
        source = 'val greeting = "hello $name"'
        patch = (
            "diff --git a/runtime.kt b/runtime.kt\n"
            "--- a/runtime.kt\n"
            "+++ b/runtime.kt\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.kt"],
                patch,
            ),
            patch,
        )

    def test_review_patch_rejects_dollar_interpolation_source_collision(
        self,
    ) -> None:
        fixture_value = "exfiltrate1234"
        key = "pass" + "word"
        for rel in ("runtime.kt", "runtime.groovy"):
            with self.subTest(rel=rel):
                source_lines = (
                    f'{key} = "{fixture_value}"',
                    'output = "${' + fixture_value + '()}"',
                )
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1,2 @@\n"
                    + "".join(f"+{line}\n" for line in source_lines)
                )

                with self.assertRaisesRegex(
                    SystemExit,
                    "known secret-like value",
                ):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    )

    def test_review_patch_rejects_secret_collision_in_interpolation_source(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        cases = (
            (
                "runtime.ts",
                'pass'
                + f'word = decode(`{fixture_value}${{{fixture_value}()}}`);',
            ),
            (
                "runtime.py",
                'pass'
                + f'word = decode(f"{fixture_value}{{{fixture_value}()}}")',
            ),
            (
                "runtime.cs",
                'pass'
                + f'word = decode($"{fixture_value}{{{fixture_value}()}}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                with self.assertRaisesRegex(SystemExit, "known secret-like value"):
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    )

    def test_review_patch_rejects_empty_literal_interpolation_source_collision(
        self,
    ) -> None:
        fixture_value = "Evil1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + f'word = "{fixture_value}";\n'
            + f"+const out = `${{{fixture_value}()}}`;\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_rejects_multiline_interpolation_source_collision(
        self,
    ) -> None:
        fixture_value = "Evil1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,3 @@\n"
            + "+pass"
            + f'word = "{fixture_value}";\n'
            + f"+const out = `${{{fixture_value}(\n"
            + "+  value)}`;\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_retains_source_proof_before_incomplete_javascript(
        self,
    ) -> None:
        fixture_value = "Evil1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,4 @@\n"
            + "+pass"
            + f'word = "{fixture_value}";\n'
            + f"+const out = `${{{fixture_value}(\n"
            + "+  value)}`;\n"
            + "+/* incomplete\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_bounds_interpolation_nesting(self) -> None:
        nested = '"Abc1234"'
        for _ in range(70):
            nested = f'f"{{{nested}}}"'

        with self.assertRaisesRegex(SystemExit, "excessive interpolation nesting"):
            self.helper["quoted_literal_value_spans"](
                nested,
                0,
                len(nested),
                javascript_dialect="python",
            )

    def test_review_patch_parses_nested_csharp_prompt_argument_commas(self) -> None:
        fixture_value = "Alpha123,Beta456"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt($"{{Get("{fixture_value}")}}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt($"{Get("redacted")}")', redacted_patch)

    def test_review_patch_redacts_numeric_non_javascript_interpolations(
        self,
    ) -> None:
        fixture_value = "12345678"
        cases = (
            ("runtime.py", f'pass' + f'word = decode(f"{{{fixture_value}}}")'),
            ("runtime.cs", f'pass' + f'word = decode($"{{{fixture_value}}}");'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("{redacted}", redacted_patch)

    def test_review_patch_redacts_floating_point_interpolation_credentials(
        self,
    ) -> None:
        cases = (
            ("runtime.py", 'pass' + 'word = decode(f"{0.12345678}")'),
            ("runtime.py", 'pass' + 'word = decode(f"{12345678.0}")'),
            ("runtime.py", 'pass' + 'word = decode(f"{.12345678}")'),
            ("runtime.py", 'pass' + 'word = decode(f"{12345678.}")'),
            ("runtime.py", 'pass' + 'word = decode(f"{12345678.e10}")'),
            ("runtime.cs", 'pass' + 'word = decode($"{0.12345678}");'),
            ("runtime.cs", 'pass' + 'word = decode($"{12345678.0}");'),
            ("runtime.cs", 'pass' + 'word = decode($"{.12345678}");'),
            ("runtime.cs", 'pass' + 'word = decode($"{12345678.}");'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(source, redacted_patch)
                self.assertIn("{redacted}", redacted_patch)

    def test_review_patch_preserves_python_floor_division_interpolation(
        self,
    ) -> None:
        source = 'password = decode(f"{1234 // 5678}")'
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_preserves_below_threshold_separator_integers(self) -> None:
        fixture_value = "1_2_3_4_5_6_7"
        cases = (
            (
                "runtime.ts",
                'pass' + f'word = decode(`${{{fixture_value}}}`);',
            ),
            (
                "runtime.py",
                'pass' + f'word = decode(f"{{{fixture_value}}}")',
            ),
            (
                "runtime.cs",
                'pass' + f'word = decode($"{{{fixture_value}}}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertIn(source, redacted_patch)

    def test_review_patch_preserves_independent_interpolation_arithmetic(self) -> None:
        cases = (
            ("runtime.ts", 'pass' + 'word = decode(`${1234 + 5678}`);'),
            ("runtime.py", 'pass' + 'word = decode(f"{1234 + 5678}")'),
            ("runtime.cs", 'pass' + 'word = decode($"{1234 + 5678}");'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertIn(source, redacted_patch)

    def test_review_patch_preserves_formatted_interpolation_arithmetic(
        self,
    ) -> None:
        cases = (
            ("runtime.py", 'password = decode(f"{1234 + 5678:04d}")'),
            ("runtime.cs", 'password = decode($"{1234 + 5678:D4}");'),
            ("runtime.py", 'password = decode(f"{1234 + 5678=!r}")'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        [rel],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_redacts_numeric_string_coercion(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode(`${String(1234)+5678}`);\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("1234", redacted_patch)
        self.assertNotIn("5678", redacted_patch)

    def test_review_patch_redacts_numeric_array_coercion(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + "word = decode(`${[] + 1234 + 5678}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("1234", redacted_patch)
        self.assertNotIn("5678", redacted_patch)

    def test_review_patch_redacts_numeric_fields_after_unary_plus(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + "word = decode(`${1234}${+5678}`);\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn("1234", redacted_patch)
        self.assertNotIn("5678", redacted_patch)

    def test_review_patch_redacts_based_non_javascript_interpolation_integers(
        self,
    ) -> None:
        cases = (
            ("runtime.py", "0xA1B2C3D4"),
            ("runtime.py", "0x_A1B2C3D4"),
            ("runtime.py", "0b10101010110011001111000011110000"),
            ("runtime.py", "0b_10101010110011001111000011110000"),
            ("runtime.py", "0o12345670123"),
            ("runtime.py", "0o_12345670123"),
            ("runtime.cs", "0xA1B2C3D4"),
            ("runtime.cs", "0x_A1B2C3D4"),
            ("runtime.cs", "0b10101010110011001111000011110000"),
            ("runtime.cs", "0b_10101010110011001111000011110000"),
        )
        for rel, fixture_value in cases:
            marker = "f" if rel.endswith(".py") else "$"
            terminator = "" if rel.endswith(".py") else ";"
            source = (
                "pass"
                + f'word = decode({marker}"{{{fixture_value}}}"){terminator}'
            )
            with self.subTest(rel=rel, fixture_value=fixture_value):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("{redacted}", redacted_patch)

    def test_review_patch_redacts_based_integers_rendering_as_eight_digits(
        self,
    ) -> None:
        fixture_value = "0xFFFFFF"
        cases = (
            (
                "runtime.ts",
                'pass' + f'word = decode(`${{{fixture_value}}}`);',
            ),
            (
                "runtime.py",
                'pass' + f'word = decode(f"{{{fixture_value}}}")',
            ),
            (
                "runtime.cs",
                'pass' + f'word = decode($"{{{fixture_value}}}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("{redacted}", redacted_patch)

    def test_review_patch_redacts_interpolation_format_spec_literals(self) -> None:
        fixture_value = "Abc123Def456"
        cases = (
            (
                "runtime.py",
                'pass'
                + f'word = prompt(f"{{value:{{width}}{fixture_value}}}")',
            ),
            (
                "runtime.cs",
                'pass' + f'word = prompt($"{{value:{fixture_value}}}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_redacts_format_specs_beginning_with_punctuation(
        self,
    ) -> None:
        fixture_value = "Abc123Def456"
        cases = (
            ("runtime.py", f'pass' + f'word = decode(f"{{value:={fixture_value}}}")'),
            ("runtime.py", f'pass' + f'word = decode(f"{{value::{fixture_value}}}")'),
            ("runtime.cs", f'pass' + f'word = decode($"{{value:={fixture_value}}}");'),
        )
        for rel, source in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn("redacted", redacted_patch)

    def test_review_patch_preserves_csharp_alias_qualifier_colons(self) -> None:
        for expression in (
            "global::Namespace.Value",
            "Vendor::Namespace.Value",
            "@vendor::Namespace.Value",
            "new global::VeryLongNamespace.Type()",
            "Get<global::VeryLongNamespace.Type>()",
        ):
            with self.subTest(expression=expression):
                format_start = self.helper["top_level_interpolation_format_start"](
                    expression,
                    0,
                    len(expression),
                    dialect="csharp",
                )

                self.assertIsNone(format_start)

    def test_review_patch_preserves_csharp_alias_qualifier_source(self) -> None:
        expression = "new global::VeryLongNamespace.Type()"
        source = "pass" + f'word = decode($"{{{expression}}}");'
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.cs"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_csharp_format_starting_with_colon(self) -> None:
        fixture_value = "Abc123Def456"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = decode($"{(x)::'
            + fixture_value
            + '}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('$"{(x):redacted}"', redacted_patch)

    def test_review_patch_preserves_csharp_conditional_colon_as_source(self) -> None:
        source = (
            "pass"
            + 'word = decode($"{(flag ? SafeIdentifier1234 : OtherIdentifier5678)}");'
        )
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertIn(source, redacted_patch)

    def test_review_patch_redacts_csharp_format_after_nullable_generic(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($"{{Get<int?>():{fixture_value}}}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('{Get<int?>():redacted}', redacted_patch)

    def test_review_patch_preserves_unicode_interpolation_identifiers(self) -> None:
        identifier = "变量12345678"
        cases = (
            ("runtime.ts", 'pass' + f'word = decode(`${{{identifier}}}`);'),
            ("runtime.py", 'pass' + f'word = decode(f"{{{identifier}}}")'),
            ("runtime.cs", 'pass' + f'word = decode($"{{{identifier}}}");'),
            (
                "runtime.ts",
                r"password = decode(`${\u{53D8}\u{91CF}12345678}`);",
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel, source=source):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertIn(source, redacted_patch)

    def test_review_patch_balances_ordinary_interpolated_call_parentheses(
        self,
    ) -> None:
        fixture_value = "Prod)Secret123"
        cases = (
            (
                "runtime.py",
                'pass'
                + f'word = runCommand(f"{{get("{fixture_value}")}}")',
            ),
            (
                "runtime.cs",
                'pass'
                + f'word = runCommand($"{{Get("{fixture_value}")}}");',
            ),
        )
        for rel, source in cases:
            with self.subTest(rel=rel):
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn('("redacted")', redacted_patch)

    def test_review_patch_parses_non_interpolated_csharp_verbatim_strings(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = runCommand(@"C:\\\", "{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('runCommand(@"C:\\\", "redacted")', redacted_patch)

    def test_review_patch_handles_csharp_interpolation_comment_terminator(
        self,
    ) -> None:
        fixture_value = "Abc1234"
        terminator = "\u0085"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = decode($"{fixture_value}'
            + f'{{Get(value // note{terminator} ?? fallback)}}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(
            f'{{Get(value // note{terminator} ?? fallback)}}',
            redacted_patch,
        )

    def test_review_patch_handles_unicode_terminator_in_csharp_call_comment(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        terminator = "\u0085"
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = runCommand(value, // note{terminator}"{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn(f'// note{terminator}"redacted"', redacted_patch)

    def test_review_patch_does_not_parse_python_raw_string_as_c_family(self) -> None:
        fixture_value = "Abc123(payload)Abc123"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = prompt(R"{fixture_value}")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('prompt(R"redacted")', redacted_patch)

    def test_review_patch_preserves_prose_comment_inside_pem_context(self) -> None:
        identifier = "AuthenticationConfigurationIdentifier"
        body = "MIIEowIBAAKCAQEAcommented0123456789ABCDEF"
        patch = (
            "diff --git a/fixture.cc b/fixture.cc\n"
            "--- a/fixture.cc\n"
            "+++ b/fixture.cc\n"
            "@@ -0,0 +1,4 @@\n"
            "+// -----BEGIN "
            + "PRIVATE KEY-----\n"
            + f"+// note {identifier} stays visible\n"
            + f"+// {body}\n"
            + "+// -----END "
            + "PRIVATE KEY-----\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.cc"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)
        self.assertIn("+// redacted", redacted_patch)

    def test_review_patch_redacts_short_and_unquoted_fallbacks(self) -> None:
        for fallback in ('"hunter2"', "12345678"):
            with self.subTest(fallback=fallback):
                patch = (
                    "diff --git a/runtime.py b/runtime.py\n"
                    "--- a/runtime.py\n"
                    "+++ b/runtime.py\n"
                    "@@ -0,0 +1 @@\n"
                    + "+pass"
                    + f'word = getenv("PASSWORD") or {fallback}\n'
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.py"],
                    patch,
                )

                self.assertNotIn(fallback.strip('"'), redacted_patch)
                expected = '"redacted"' if fallback.startswith('"') else "redacted"
                self.assertIn(
                    f'getenv("PASSWORD") or {expected}',
                    redacted_patch,
                )

    def test_review_patch_redacts_fallbacks_after_unicode_line_comments(
        self,
    ) -> None:
        fixture_value = "Secret" + "123"
        key = "password"
        cases = (
            ("runtime.ts", "\u2028", "||"),
            ("runtime.js", "\u2029", "||"),
            ("runtime.cs", "\u0085", "??"),
        )
        for rel, terminator, operator in cases:
            with self.subTest(rel=rel):
                source = (
                    f"{key} = primary // note{terminator} "
                    f'{operator} "{fixture_value}"'
                )
                patch = (
                    f"diff --git a/{rel} b/{rel}\n"
                    f"--- a/{rel}\n"
                    f"+++ b/{rel}\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    [rel],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(
                    f'{terminator} {operator} "redacted"',
                    redacted_patch,
                )

    def test_review_patch_preserves_redaction_placeholder_fallback(self) -> None:
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + 'word = getenv("PASSWORD") or "redacted"\n'
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_rejects_arbitrary_redacted_prefix_as_placeholder(self) -> None:
        arbitrary_value = "redacted-production"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = "{arbitrary_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(arbitrary_value, redacted_patch)
        self.assertIn('pass' + 'word = "redacted"', redacted_patch)

    def test_review_patch_ignores_nested_fallback_operator_text(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + "+pass"
            + f'word = defaults["x || y"] || "{fixture_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('defaults["x || y"] || "redacted"', redacted_patch)

    def test_review_patch_ignores_fallback_operator_inside_regex(self) -> None:
        source = "password = /Abc123||Def456/;"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_composed_template_literals(self) -> None:
        first = "Abc123"
        second = "Def456"
        source = (
            'password = decode(`${"'
            + first
            + '".concat("'
            + second
            + '")}`)'
        )
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(first, redacted_patch)
        self.assertNotIn(second, redacted_patch)
        self.assertIn(".concat(", redacted_patch)

    def test_review_patch_preserves_regex_delimiters_during_redaction(self) -> None:
        fixture_value = "Abc12345Def67890"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f"+password = primary || /{fixture_value}/i;\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("password = primary || /redacted/i;", redacted_patch)

    def test_review_patch_preserves_groovy_slashy_assignment_delimiters(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        cases = (
            (
                f"password = /{fixture_value}/",
                "password = /redacted/",
            ),
            (
                f"password = $/{fixture_value}/$",
                "password = $/redacted/$",
            ),
            (
                f"password = /{fixture_value}${{name}}/",
                "password = /redacted${name}/",
            ),
        )
        for source, expected in cases:
            with self.subTest(source=source):
                patch = (
                    "diff --git a/runtime.groovy b/runtime.groovy\n"
                    "--- a/runtime.groovy\n"
                    "+++ b/runtime.groovy\n"
                    "@@ -0,0 +1 @@\n"
                    f"+{source}\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["runtime.groovy"],
                    patch,
                )

                self.assertNotIn(fixture_value, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_scans_subscript_after_member_call(self) -> None:
        fixture_value = "CorrectHorse7Battery"
        source = f'password = credentials->get()["{fixture_value}"]'
        patch = (
            "diff --git a/runtime.cpp b/runtime.cpp\n"
            "--- a/runtime.cpp\n"
            "+++ b/runtime.cpp\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cpp"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('credentials->get()["redacted"]', redacted_patch)

    def test_review_patch_preserves_chained_credential_lookup_keys(self) -> None:
        for lookup in ('["access_token"]', '.get("access_token")'):
            with self.subTest(lookup=lookup):
                patch = (
                    "diff --git a/runtime.ts b/runtime.ts\n"
                    "--- a/runtime.ts\n"
                    "+++ b/runtime.ts\n"
                    "@@ -0,0 +1 @@\n"
                    f"+password = response.json(){lookup};\n"
                )

                self.assertEqual(
                    self.helper["validate_review_patch"](
                        "local unstaged diff",
                        ["runtime.ts"],
                        patch,
                    ),
                    patch,
                )

    def test_review_patch_scans_csharp_pointer_member_call(self) -> None:
        fixture_value = "CorrectHorse7Battery"
        source = f'password = provider->Get()->Decode("{fixture_value}")'
        patch = (
            "diff --git a/runtime.cs b/runtime.cs\n"
            "--- a/runtime.cs\n"
            "+++ b/runtime.cs\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.cs"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('provider->Get()->Decode("redacted")', redacted_patch)

    def test_review_patch_scans_fallback_after_swift_raw_string(self) -> None:
        fixture_value = "CorrectHorse7Battery"
        patch = (
            "diff --git a/runtime.swift b/runtime.swift\n"
            "--- a/runtime.swift\n"
            "+++ b/runtime.swift\n"
            "@@ -0,0 +1 @@\n"
            f'+password = (#"safe"# as String?) ?? "{fixture_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.swift"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('(#"safe"# as String?) ?? "redacted"', redacted_patch)

    def test_review_patch_redacts_swift_regex_inside_interpolation(self) -> None:
        fixture_value = "CorrectHorse7Battery"
        source = (
            'password = "\\(String(describing: #/'
            + fixture_value
            + '/#))"'
        )
        patch = (
            "diff --git a/runtime.swift b/runtime.swift\n"
            "--- a/runtime.swift\n"
            "+++ b/runtime.swift\n"
            "@@ -0,0 +1 @@\n"
            f"+{source}\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.swift"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("#/redacted/#", redacted_patch)

    def test_review_patch_ignores_fallback_literals_inside_comments(self) -> None:
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + "+pass"
            + 'word = primary || secondary // "evil-package"\n'
            + '+import("evil-package");\n'
        )

        _old_content, new_content = self.helper["unified_diff_contents"](patch)
        fragments = self.helper["review_secret_fragments"](new_content)
        redacted_patch = self.helper["redact_secret_like_diff_section"](
            patch,
            {"runtime.ts"},
            fragments,
        )
        self.assertIn('+import("evil-package");', redacted_patch)
        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            ),
            patch,
        )

    def test_review_patch_redacts_secret_like_fallback_comment(self) -> None:
        fixture_value = "CorrectHorse7Battery"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f'+password = primary || secondary // "{fixture_value}"\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('// "redacted"', redacted_patch)

    def test_review_patch_learns_bearer_credential_without_prefix(self) -> None:
        bearer_value = "AbcdEFGHijklMNOPqrstUVWX+SensitiveTail123=="
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + f'+const authorization = "Bearer {bearer_value}";\n'
            + f'+log("{bearer_value}");\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(bearer_value, redacted)
        self.assertIn('"Bearer redacted"', redacted)
        self.assertIn('+log("redacted");', redacted)

    def test_review_patch_preserves_safe_assignment_on_mixed_risk_line(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            f'+const options = {{ creden{"tials"}: "include", api{"Key"}: "{fixture_value}" }};\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('creden' + 'tials: "include"', redacted_patch)
        self.assertIn('api' + 'Key: "redacted"', redacted_patch)

    def test_review_patch_redacts_commented_private_key_body(self) -> None:
        body = "MIIEowIBAAKCAQEAcommented0123456789ABCDEF"
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,4 @@\n"
            "+# -----BEGIN "
            + "PRIVATE KEY-----\n"
            f"+# {body}\n"
            "+# -----END "
            + "PRIVATE KEY-----\n"
            "+runDangerousOperation();\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn(body, redacted)
        self.assertIn("+# redacted", redacted)
        self.assertIn("+runDangerousOperation();", redacted)

    def test_review_patch_redacts_block_commented_private_key_body(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890"
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,3 @@\n"
            "+/* -----BEGIN "
            + "PRIVATE KEY----- */\n"
            + f"+/* {body} */\n"
            + "+/* -----END "
            + "PRIVATE KEY----- */\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn(body, redacted)
        self.assertIn("+/* redacted */", redacted)

    def test_review_patch_normalizes_escaped_private_key_body_fragment(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890"
        patch = (
            "diff --git a/fixture.ts b/fixture.ts\n"
            "--- a/fixture.ts\n"
            "+++ b/fixture.ts\n"
            "@@ -0,0 +1,2 @@\n"
            "+const pem = \"-----BEGIN "
            + f"PRIVATE KEY-----\\n{body}\\n-----END "
            + "PRIVATE KEY-----\";\n"
            + f'+log("{body}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertIn('+log("redacted");', redacted_patch)

    def test_review_patch_redacts_escaped_private_key_tail_quanta(self) -> None:
        for tail in ("AQ==", "AQI="):
            with self.subTest(tail=tail):
                patch = (
                    "diff --git a/fixture.ts b/fixture.ts\n"
                    "--- a/fixture.ts\n"
                    "+++ b/fixture.ts\n"
                    "@@ -0,0 +1 @@\n"
                    "+const pem = \"-----BEGIN "
                    + f"PRIVATE KEY-----\\n{tail}\\n-----END "
                    + "PRIVATE KEY-----\";\n"
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["fixture.ts"],
                    patch,
                )

                self.assertNotIn(tail, redacted_patch)
                self.assertIn("\\nredacted\\n", redacted_patch)

    def test_review_patch_redacts_short_private_key_chunks(self) -> None:
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,3 @@\n"
            "+-----BEGIN "
            + "PRIVATE KEY-----\n"
            "+AB12 CDef3456GHij7890\n"
            "+-----END "
            + "PRIVATE KEY-----\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn("AB12", redacted)
        self.assertNotIn("CDef3456GHij7890", redacted)

    def test_review_patch_redacts_short_known_private_key_chunk_in_comment(
        self,
    ) -> None:
        patch = (
            "diff --git a/fixture.ts b/fixture.ts\n"
            "--- a/fixture.ts\n"
            "+++ b/fixture.ts\n"
            "@@ -0,0 +1,5 @@\n"
            "+-----BEGIN "
            + "PRIVATE KEY-----\n"
            "+AB12\n"
            "+-----END "
            + "PRIVATE KEY-----\n"
            "+// AB12\n"
            "+const output = `${value /* AB12 */}`;\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.ts"],
            patch,
        )

        self.assertNotIn("AB12", redacted)
        self.assertIn("+// redacted", redacted)
        self.assertIn("`${value /* redacted */}`", redacted)

    def test_review_patch_redacts_padded_private_key_tail_quanta(self) -> None:
        for tail in ("AQ==", "AQI="):
            with self.subTest(tail=tail):
                patch = (
                    "diff --git a/fixture.txt b/fixture.txt\n"
                    "--- a/fixture.txt\n"
                    "+++ b/fixture.txt\n"
                    "@@ -0,0 +1,3 @@\n"
                    "+-----BEGIN "
                    + "PRIVATE KEY-----\n"
                    + f"+{tail}\n"
                    + "+-----END "
                    + "PRIVATE KEY-----\n"
                )

                redacted = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["fixture.txt"],
                    patch,
                )

                self.assertNotIn(tail, redacted)

    def test_review_patch_redacts_private_key_body_without_visible_markers(self) -> None:
        chunks = "AB12 CDef3456GHij7890 KLmn1234OPqr5678"
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -8 +8,2 @@\n"
            + f"+{chunks}\n"
            + f'+log("{chunks}")\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn(chunks, redacted)
        self.assertIn("+redacted-a redacted-b redacted-c", redacted)
        self.assertIn(
            '+log("redacted-a redacted-b redacted-c")',
            redacted,
        )

    def test_review_patch_redacts_markerless_private_key_body_in_string(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890abcdef"
        patch = (
            "diff --git a/fixture.ts b/fixture.ts\n"
            "--- a/fixture.ts\n"
            "+++ b/fixture.ts\n"
            "@@ -0,0 +1,2 @@\n"
            + f'+const fixture = "{body}";\n'
            + f'+log("{body}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertIn('+const fixture = "redacted";', redacted_patch)
        self.assertIn('+log("redacted");', redacted_patch)

    def test_review_patch_preserves_ambiguous_short_markerless_lines(self) -> None:
        chunks = ["AB12", "CDef", "GH34", "ijKL", "MN56", "opQR"]
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            f"@@ -0,0 +1,{len(chunks)} @@\n"
            + "".join(f"+{chunk}\n" for chunk in chunks)
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertEqual(redacted_patch, patch)

    def test_review_patch_redacts_long_key_with_source_wrappers(self) -> None:
        body = "".join(
            (
                "MIIEvQIBADAN",
                "BgkqhkiG9w0B",
                "AQEFAASC1234",
                "567890abcdef",
            )
        )
        cases = (
            (f"+/* {body} */\n", "+/* redacted */\n"),
            (f"+/* {body} */;\\\n", "+/* redacted */;\\\n"),
            (f"+{body}\\\n", "+redacted\\\n"),
        )
        for addition, expected in cases:
            with self.subTest(addition=addition[-4:]):
                patch = (
                    "diff --git a/fixture.txt b/fixture.txt\n"
                    "--- a/fixture.txt\n"
                    "+++ b/fixture.txt\n"
                    "@@ -0,0 +1,1 @@\n"
                    + addition
                )

                redacted_patch = self.helper["validate_review_patch"](
                    "local unstaged diff",
                    ["fixture.txt"],
                    patch,
                )

                self.assertNotIn(body, redacted_patch)
                self.assertIn(expected, redacted_patch)

    def test_review_patch_preserves_long_non_pem_identifier_lines(self) -> None:
        identifier = "runDangerousOperationWithLongIdentifier"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + f"+{identifier}\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn("+" + identifier, redacted)

    def test_review_patch_preserves_hash_and_submodule_lines(self) -> None:
        digest = "abcdef0123456789abcdef0123456789abcdef01"
        patch = (
            "diff --git a/vendor b/vendor\n"
            "--- a/vendor\n"
            "+++ b/vendor\n"
            "@@ -1 +1,2 @@\n"
            + f"+{digest}\n"
            + f"+Subproject commit {digest}\n"
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["vendor"],
            patch,
        )

        self.assertIn("+" + digest, redacted)
        self.assertIn("+Subproject commit " + digest, redacted)

    def test_review_patch_learns_private_key_body_chunks(self) -> None:
        body = "MIIEowIBAAKCAQEAshared0123456789ABCDEF"
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            "@@ -0,0 +1,4 @@\n"
            "+-----BEGIN "
            + "PRIVATE KEY-----\n"
            f"+{body}\n"
            "+-----END "
            + "PRIVATE KEY-----\n"
            f'+log("{body}")\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn(body, redacted)
        self.assertIn('+log("redacted")', redacted)

    def test_review_patch_redacts_known_secret_in_bare_comment(self) -> None:
        fixture_value = "qjvmtzplskdwoeirutyghbnx"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@\n"
            f'-pass{"word"} = "{fixture_value}"\n'
            f"+# rotated value {fixture_value}\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_redacts_known_secret_after_python_floor_division(
        self,
    ) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -1 +1 @@\n"
            + "-pass"
            + f'word = "{fixture_value}"\n'
            + f'+values = [total // divisor, "{fixture_value}"]\n'
        )

        redacted = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted)
        self.assertIn('+values = [total // divisor, "redacted"]', redacted)

    def test_review_patch_rejects_cross_dialect_comment_source_collision(
        self,
    ) -> None:
        fixture_value = "Evil1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.py\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.py\n"
            "@@ -1,2 +1,2 @@\n"
            + " pass"
            + f'word = "{fixture_value}"\n'
            + f" value // {fixture_value}\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts", "runtime.py"],
                patch,
            )

    def test_review_patch_redacts_known_secret_in_hunk_header(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            f"@@ -1 +1 @@ function rotate_{fixture_value}()\n"
            f'-pass{"word"} = "{fixture_value}"\n'
            "+return true;\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn("function rotate_redacted()", redacted_patch)

    def test_review_patch_redacts_overlapping_known_secret_fragments(self) -> None:
        prefix = "XAbcd" + "123"
        longer = "Abcd123Sensitive" + "Tail9"
        combined = "XAbcd123Sensitive" + "Tail9"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1,2 +1 @@\n"
            + f'-api{"Key"} = "{prefix}"\n'
            + f'-access{"Token"} = "{longer}"\n'
            + f'+log("{combined}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(prefix, redacted_patch)
        self.assertNotIn(longer, redacted_patch)
        self.assertNotIn("SensitiveTail9", redacted_patch)
        self.assertRegex(redacted_patch, r'\+log\("redacted-[a-z-]+"\);')

    def test_review_patch_keeps_distinct_secret_fragment_identity(self) -> None:
        old_value = "AlphaSecret123"
        new_value = "MuchLongerBetaSecret456" + "Value"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1,2 +1,2 @@\n"
            + f'-pass{"word"} = "{old_value}";\n'
            + f'-runCommand("{old_value}");\n'
            + f'+pass{"word"} = "{new_value}";\n'
            + f'+runCommand("{new_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        old_pattern = r'-pass' + r'word = "(redacted-[a-z]+)";'
        new_pattern = r'\+pass' + r'word = "(redacted-[a-z]+)";'
        old_match = re.search(old_pattern, redacted_patch)
        new_match = re.search(new_pattern, redacted_patch)
        self.assertIsNotNone(old_match)
        self.assertIsNotNone(new_match)
        assert old_match is not None and new_match is not None
        old_label = old_match.group(1)
        new_label = new_match.group(1)
        self.assertEqual(old_label, "redacted-a")
        self.assertEqual(new_label, "redacted-b")
        self.assertIn(f'-runCommand("{old_label}");', redacted_patch)
        self.assertIn(f'+runCommand("{new_label}");', redacted_patch)

    def test_review_patch_keeps_private_key_body_identity(self) -> None:
        old_body = "AB12cd34EF56"
        new_body = "ZX98yx76WV54"
        private_key_end = "END " + "PRIVATE KEY"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1,3 +1,6 @@\n"
            f" -----{PRIVATE_KEY_BEGIN_TEXT}-----\n"
            f"-{old_body}\n"
            f"+{new_body}\n"
            f" -----{private_key_end}-----\n"
            f"+-----{PRIVATE_KEY_BEGIN_TEXT}-----\n"
            f"+{old_body}\n"
            f"+-----{private_key_end}-----\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(old_body, redacted_patch)
        self.assertNotIn(new_body, redacted_patch)
        self.assertEqual(redacted_patch.count("redacted-a"), 2)
        self.assertEqual(redacted_patch.count("redacted-b"), 1)

    def test_review_patch_keeps_secret_identity_across_files(self) -> None:
        first = "AlphaSecret123"
        second = "MuchLongerBetaSecret456Value"
        patch = (
            "diff --git a/a.ts b/a.ts\n"
            "--- a/a.ts\n"
            "+++ b/a.ts\n"
            "@@ -1 +1 @@\n"
            + f'-pass{"word"} = "{first}";\n'
            + f'+pass{"word"} = "{second}";\n'
            + "diff --git a/b.ts b/b.ts\n"
            + "--- a/b.ts\n"
            + "+++ b/b.ts\n"
            + "@@ -1 +1 @@\n"
            + f'-pass{"word"} = "{second}";\n'
            + f'+pass{"word"} = "{first}";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["a.ts", "b.ts"],
            patch,
        )

        self.assertEqual(redacted_patch.count('pass' + 'word = "redacted-a";'), 2)
        self.assertEqual(redacted_patch.count('pass' + 'word = "redacted-b";'), 2)

    def test_review_patch_reserves_existing_placeholder_labels(self) -> None:
        first = "AlphaSecret123"
        second = "BetaSecret456"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1,2 @@\n"
            + f'-pass{"word"} = "{first}";\n'
            + f'+pass{"word"} = "{second}";\n'
            + '+const marker = "redacted-a";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('const marker = "redacted-a";', redacted_patch)
        self.assertIn('pass' + 'word = "redacted-b";', redacted_patch)
        self.assertIn('pass' + 'word = "redacted-c";', redacted_patch)

    def test_review_patch_labels_lone_secret_beside_bare_placeholder(self) -> None:
        fixture_value = "ProdSecret123"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,2 @@\n"
            '+const marker = "redacted";\n'
            + f'+pass{"word"} = "{fixture_value}";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('const marker = "redacted";', redacted_patch)
        self.assertIn('pass' + 'word = "redacted-a";', redacted_patch)

    def test_review_patch_keeps_hunk_header_fragment_identity(self) -> None:
        first = "AlphaSecret123"
        second = "BetaSecret456"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            + f'@@ -0,0 +1,2 @@ pass{"word"} = "{first}"\n'
            + f'+pass{"word"} = "{first}";\n'
            + "+to"
            + f'ken = "{second}";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn('@@ -0,0 +1,2 @@ password = "redacted-a"', redacted_patch)
        self.assertIn('+password = "redacted-a";', redacted_patch)
        self.assertIn('+token = "redacted-b";', redacted_patch)

    def test_review_patch_learns_secret_from_hunk_header(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            + f'@@ -1 +1 @@ function f(pass{"word"} = "{fixture_value}")\n'
            + f'+log("{fixture_value}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('function f(pass' + 'word = "redacted")', redacted_patch)
        self.assertIn('+log("redacted");', redacted_patch)

    def test_review_patch_redacts_markerless_private_key_hunk_header(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890abcdef"
        patch = (
            "diff --git a/fixture.txt b/fixture.txt\n"
            "--- a/fixture.txt\n"
            "+++ b/fixture.txt\n"
            f"@@ -1 +1 @@ {body}\n"
            "+return true\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["fixture.txt"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertIn("@@ -1 +1 @@ redacted", redacted_patch)

    def test_review_patch_redacts_private_key_hunk_header_and_repeats(self) -> None:
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC1234567890"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -1 +1 @@ function f() { return \"-----BEGIN "
            + f"PRIVATE KEY-----\\n{body}\"; }}\n"
            + f'+log("{body}");\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertNotIn(PRIVATE_KEY_BEGIN_TEXT, redacted_patch)
        self.assertIn('+log("redacted-a");', redacted_patch)

    def test_review_patch_redacts_escaped_alphabetic_explicit_pem_body(self) -> None:
        body = "AbCdEfGh" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            '+const fixture = "-----BEGIN '
            + "PRIVATE KEY-----\\n"
            + body
            + "\\n-----END "
            + 'PRIVATE KEY-----";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertNotIn("PRIVATE KEY", redacted_patch)

    def test_review_patch_preserves_unwrapped_alphabetic_identifier(self) -> None:
        identifier = "AbCdEfGh" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + f"+const {identifier} = true;\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)

    def test_review_patch_preserves_punctuation_wrapped_alphabetic_identifier(self) -> None:
        identifier = "AbCdEfGh" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + f"+  {identifier},\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)

    def test_review_patch_preserves_escaped_newline_beside_alphabetic_identifier(self) -> None:
        identifier = "AbCdEfGh" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            + f'+[{identifier}, "\\\\n"];\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)

    def test_review_patch_preserves_bare_identifier_in_escaped_pem_concatenation(self) -> None:
        identifier = "AbCdEfGh" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1 @@\n"
            '+const fixture = "-----BEGIN '
            + "PRIVATE KEY-----\\n\" + "
            + identifier
            + ' + "\\n-----END '
            + 'PRIVATE KEY-----";\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(identifier, redacted_patch)

    def test_review_patch_preserves_call_target_inside_explicit_pem_context(self) -> None:
        identifier = "evilCall" + "1234"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,3 @@\n"
            "+// -----BEGIN "
            + "PRIVATE KEY-----\n"
            + f"+{identifier}();\n"
            + "+// -----END "
            + "PRIVATE KEY-----\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertIn(f"+{identifier}();", redacted_patch)

    def test_review_patch_redacts_call_like_private_key_text_inside_string(
        self,
    ) -> None:
        body = "AbCdEfGhIjKlMnOpQrStUvWxYz" + "012345"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,3 @@\n"
            "+// -----BEGIN PRIVATE KEY-----\n"
            f'+const payload = "{body}(";\n'
            "+// -----END PRIVATE KEY-----\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertIn('"redacted("', redacted_patch)

    def test_review_patch_redacts_pem_body_before_later_parenthesis(self) -> None:
        body = "AbCdEfGh1234" + "IjKlMnOp"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            "@@ -0,0 +1,4 @@\n"
            "+// -----BEGIN "
            + "PRIVATE KEY-----\n"
            + f"+{body}\n"
            + "+(\n"
            + "+// -----END "
            + "PRIVATE KEY-----\n"
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.ts"],
            patch,
        )

        self.assertNotIn(body, redacted_patch)
        self.assertIn("+redacted\n+(\n", redacted_patch)

    def test_review_patch_rejects_residual_hunk_header_secret_risk(self) -> None:
        primary = "CorrectHorse7" + "Battery"
        backup = "BackupHorse8" + "Battery"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            '@@ -1 +1 @@ function f(pass'
            + 'word = getenv("PASSWORD") '
            + f'|| choose("{primary}", "{backup}"))\n'
            + f'+log("{primary}");\n'
        )

        with self.assertRaisesRegex(SystemExit, "review diff hunk header"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_private_marker_redaction_does_not_hide_residual_header_risk(self) -> None:
        primary = "CorrectHorse7" + "Battery"
        backup = "BackupHorse8" + "Battery"
        patch = (
            "diff --git a/runtime.ts b/runtime.ts\n"
            "--- a/runtime.ts\n"
            "+++ b/runtime.ts\n"
            '@@ -1 +1 @@ function f(pass'
            + 'word = getenv("PASSWORD") '
            + f'|| choose("{primary}", "{backup}")) {{ return "-----BEGIN '
            + 'PRIVATE KEY-----"; }\n'
            + f'+log("{primary}");\n'
        )

        with self.assertRaisesRegex(SystemExit, "review diff hunk header"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["runtime.ts"],
                patch,
            )

    def test_review_patch_rejects_known_secret_in_diff_metadata(self) -> None:
        secret = realistic_secret_value()
        patch = (
            "diff --git a/settings.txt b/settings.txt\n"
            "--- a/settings.txt\n"
            "+++ b/settings.txt\n"
            "@@ -1 +0,0 @@\n"
            f'-pass{"word"} = "{secret}"\n'
            f"diff --git a/{secret}.txt b/{secret}.txt\n"
            f"--- a/{secret}.txt\n"
            f"+++ b/{secret}.txt\n"
            "@@ -0,0 +1 @@\n"
            "+safe\n"
        )

        with self.assertRaisesRegex(SystemExit, "known secret-like value"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["settings.txt", f"{secret}.txt"],
                patch,
            )

    def test_review_patch_redacts_non_self_reference_fallback(self) -> None:
        fixture_value = realistic_secret_value()
        patch = (
            "diff --git a/runtime.py b/runtime.py\n"
            "--- a/runtime.py\n"
            "+++ b/runtime.py\n"
            "@@ -0,0 +1 @@\n"
            f'+pass{"word"} = getenv("PASSWORD") or "{fixture_value}"; '
            + 'execute("DROP DATABASE production")\n'
        )

        redacted_patch = self.helper["validate_review_patch"](
            "local unstaged diff",
            ["runtime.py"],
            patch,
        )

        self.assertNotIn(fixture_value, redacted_patch)
        self.assertIn('getenv("PASSWORD") or "redacted"', redacted_patch)
        self.assertIn('execute("DROP DATABASE production")', redacted_patch)

    def test_local_bundle_allows_deleted_test_token_fixture(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            path = repo / "fixture.test.ts"
            path.write_text('const request = { token: "test-token" };\n', encoding="utf-8")
            git(repo, "add", path.name)
            git(repo, "commit", "-q", "-m", "base")

            path.write_text('const request = { token: String() };\n', encoding="utf-8")

            bundle, truncated = self.helper["local_bundle"](repo)

            self.assertIn('-const request = { token: "test-token" };', bundle)
            self.assertFalse(truncated)

    def test_pi_refuses_truncated_review_input(self) -> None:
        reviewer = argparse.Namespace(engine="pi", tools=True)

        with self.assertRaisesRegex(SystemExit, "pi engine refused truncated review input"):
            self.helper["ensure_reviewer_input_complete"](
                reviewer,
                True,
            )

        self.helper["ensure_reviewer_input_complete"](
            reviewer,
            False,
        )
        with self.assertRaisesRegex(SystemExit, "codex engine refused truncated review input"):
            self.helper["ensure_reviewer_input_complete"](
                argparse.Namespace(engine="codex", tools=True),
                True,
            )
        with self.assertRaisesRegex(SystemExit, "claude engine refused truncated review input"):
            self.helper["ensure_reviewer_input_complete"](
                argparse.Namespace(engine="claude", tools=True),
                True,
            )
        with self.assertRaisesRegex(SystemExit, "droid engine refused truncated review input"):
            self.helper["ensure_reviewer_input_complete"](
                argparse.Namespace(engine="droid", tools=False),
                True,
            )

    def test_safe_git_env_preserves_trusted_platform_and_helper_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            repo_bin = repo / "bin"
            trusted_bin = root / "trusted-bin"
            repo_bin.mkdir()
            trusted_bin.mkdir()
            with mock.patch.dict(
                os.environ,
                {
                    "PATH": os.pathsep.join((str(repo_bin), str(trusted_bin))),
                    "SYSTEMROOT": "C:\\Windows",
                    "GIT_DIR": str(repo / ".git"),
                    "OPENAI_API_KEY": "must-not-reach-git",
                },
                clear=False,
            ):
                env = self.helper["safe_git_env"](repo)

        self.assertNotIn(str(repo_bin.resolve()), env["PATH"].split(os.pathsep))
        self.assertIn(str(trusted_bin.resolve()), env["PATH"].split(os.pathsep))
        self.assertEqual(env["SYSTEMROOT"], "C:\\Windows")
        self.assertNotIn("GIT_DIR", env)
        self.assertNotIn("OPENAI_API_KEY", env)

    def test_boolean_environment_values_fail_closed(self) -> None:
        with mock.patch.dict(os.environ, {"AUTOREVIEW_TEST_BOOL": "flase"}):
            with self.assertRaisesRegex(SystemExit, "invalid boolean environment value"):
                self.helper["env_truthy"]("AUTOREVIEW_TEST_BOOL")

    def test_droid_fails_closed_without_complete_isolation(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "AGENTS.md").write_text("hostile instructions\n", encoding="utf-8")

            with self.assertRaisesRegex(
                SystemExit,
                r"droid engine is unavailable.*use codex, claude, or pi",
            ) as error:
                self.helper["run_droid"](argparse.Namespace(), repo, "prompt")
            self.assertNotIn("opencode", str(error.exception))

    def test_prompt_file_keeps_recoverable_repo_path(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            (repo / "review.md").write_text("review context\n", encoding="utf-8")
            args = argparse.Namespace(prompt=[], prompt_file=["review.md"])

            prompt, truncated = self.helper["load_extra_prompt"](args, repo)

            self.assertIn("# Prompt file: review.md", prompt)
            self.assertFalse(truncated)

    def test_build_prompt_omits_absolute_repo_path_and_caps_aggregate_input(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            prompt = self.helper["build_prompt"](repo, "local", None, "diff", "", "")

            self.assertIn(
                "Review sandbox: . (intentionally contains no reviewed repository files)",
                prompt,
            )
            self.assertIn("Read-only tools cannot access unchanged repository files", prompt)
            self.assertIn(
                "Do not report a missing import, symbol, definition, call site, config entry",
                prompt,
            )
            self.assertNotIn(str(repo), prompt)
            with self.assertRaisesRegex(SystemExit, "aggregate limit"):
                self.helper["build_prompt"](
                    repo,
                    "local",
                    None,
                    "x" * self.helper["MAX_REVIEW_PROMPT_BYTES"],
                    "",
                    "",
                )

    def test_cursor_refuses_global_mcp_config(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            global_mcp = root / ".cursor" / "mcp.json"
            global_mcp.parent.mkdir()
            global_mcp.write_text("{}\n", encoding="utf-8")
            args = argparse.Namespace(
                thinking=None,
                tools=True,
                web_search=True,
                cursor_allow_workspace_instructions=True,
            )

            with mock.patch.object(Path, "home", return_value=root), mock.patch.dict(
                os.environ,
                {"HOME": str(root), "USERPROFILE": str(root)},
            ):
                with self.assertRaisesRegex(SystemExit, "cursor engine is unavailable"):
                    self.helper["run_cursor"](args, repo, "prompt")

    def test_cursor_refuses_user_level_hooks(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            settings = root / ".claude" / "settings.json"
            settings.parent.mkdir()
            settings.write_text('{"hooks":{"PreToolUse":[{"command":"unsafe"}]}}\n', encoding="utf-8")
            args = argparse.Namespace(
                thinking=None,
                tools=True,
                web_search=True,
                cursor_allow_workspace_instructions=True,
            )

            with mock.patch.object(Path, "home", return_value=root), mock.patch.dict(
                os.environ,
                {"HOME": str(root), "USERPROFILE": str(root)},
            ):
                with self.assertRaisesRegex(SystemExit, "cursor engine is unavailable"):
                    self.helper["run_cursor"](args, repo, "prompt")

            settings.write_text('{"permissions":{"allow":["Read(**)"]}}\n', encoding="utf-8")
            with mock.patch.object(Path, "home", return_value=root), mock.patch.dict(
                os.environ,
                {"HOME": str(root), "USERPROFILE": str(root)},
            ):
                self.assertEqual(self.helper["cursor_global_hook_paths"](), [])

            settings.write_text('{"enabledPlugins":{"review-hooks@example":true}}\n', encoding="utf-8")
            with mock.patch.object(Path, "home", return_value=root), mock.patch.dict(
                os.environ,
                {"HOME": str(root), "USERPROFILE": str(root)},
            ):
                self.assertEqual(self.helper["cursor_global_hook_paths"](), [settings])

    def test_read_text_truncates_without_scanning_tail(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "large.txt"
            path.write_bytes(b"x" * 200_000 + b"\0tail")

            text = self.helper["read_text"](path)

            self.assertIn("[truncated at 180000 characters]", text)
            self.assertNotEqual(text, "[binary file omitted]")

    def test_read_text_marks_unreadable_input_incomplete(self) -> None:
        with mock.patch.dict(
            self.helper["read_text_with_status"].__globals__,
            {"read_prefix": lambda *_args: (_ for _ in ()).throw(SystemExit("denied"))},
        ):
            text, incomplete = self.helper["read_text_with_status"](Path("blocked"))

        self.assertIn("[unreadable:", text)
        self.assertTrue(incomplete)

    def test_evidence_file_must_be_repo_relative_and_not_symlinked(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            outside = root / "outside.md"
            outside.write_text("outside\n", encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "repo-relative"):
                self.helper["validate_evidence_file"](repo, str(outside), "--prompt-file")

            target = repo / "notes.md"
            target.write_text("notes\n", encoding="utf-8")
            link = repo / "link.md"
            try:
                link.symlink_to(target)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    self.skipTest("Windows symlink privilege is not available")
                raise
            with self.assertRaisesRegex(SystemExit, "symlinked"):
                self.helper["validate_evidence_file"](repo, "link.md", "--dataset")

    def test_safe_engine_env_strips_process_injection_variables(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["GIT_DIR"] = "/tmp/unsafe-git-dir"
                os.environ["GIT_CONFIG_COUNT"] = "99"
                os.environ["DYLD_INSERT_LIBRARIES"] = "/tmp/unsafe.dylib"
                os.environ["NODE_OPTIONS"] = "--require=/tmp/unsafe.js"
                os.environ["NODE_PATH"] = "/tmp/unsafe-node"
                os.environ["LD_AUDIT"] = "/tmp/unsafe-audit.so"
                os.environ["LD_LIBRARY_PATH"] = "/tmp/unsafe-lib"
                os.environ["RUBYOPT"] = "-r/tmp/unsafe.rb"
                os.environ["PERL5OPT"] = "-Munsafe"
                os.environ["BUN_OPTIONS"] = "--preload=/tmp/unsafe.js"
                os.environ["OPENCODE_CONFIG"] = "/tmp/unsafe-opencode.json"
                os.environ["OPENCODE_PERMISSION"] = "allow"
                os.environ["OPENCODE_AUTO_SHARE"] = "1"
                os.environ["COPILOT_ALLOW_ALL"] = "1"
                os.environ["CODEX_HOME"] = "/tmp/codex-auth"
                os.environ["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=/run/user/1000/bus"
                os.environ["XDG_RUNTIME_DIR"] = "/run/user/1000"
                os.environ["CLAUDE_CONFIG_DIR"] = "/tmp/claude-auth"
                os.environ["PI_CODING_AGENT_DIR"] = "/tmp/pi-auth"
                os.environ["CLAUDE_CODE_USE_FOUNDRY"] = "1"
                os.environ["CLOUD_ML_REGION"] = "us-east5"
                os.environ["ANTHROPIC_AUTH_TOKEN"] = "test-auth-token"
                os.environ["AWS_BEARER_TOKEN_BEDROCK"] = "test-token-placeholder"
                os.environ["ANTHROPIC_BEDROCK_BASE_URL"] = (
                    "https://bedrock.example.invalid"
                )
                os.environ["ANTHROPIC_VERTEX_BASE_URL"] = (
                    "https://vertex.example.invalid"
                )
                os.environ["AWS_PROFILE"] = "review-profile"
                os.environ["AWS_CONFIG_FILE"] = "/tmp/unsafe-aws-config"
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = (
                    "/tmp/unsafe-google-credentials"
                )
                os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
                os.environ["OPENROUTER_API_KEY"] = "test-provider-key"
                os.environ["GITHUB_TOKEN"] = "test-token-placeholder"
                os.environ["HTTPS_PROXY"] = "http://proxy.example.invalid:8080"
                os.environ["HTTP_PROXY"] = "proxy.example.invalid:8080"
                os.environ["ALL_PROXY"] = "socks5://proxy.example.invalid:1080"
                os.environ["DO_NOT_TRACK"] = "1"
                os.environ["DISABLE_TELEMETRY"] = "1"
                os.environ["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"

                env = self.helper["safe_engine_env"](repo, engine="codex")
                claude_env = self.helper["safe_engine_env"](repo, engine="claude")
                pi_env = self.helper["safe_engine_env"](repo, engine="pi")

                self.assertNotEqual(env.get("GIT_DIR"), "/tmp/unsafe-git-dir")
                self.assertEqual(
                    env["GIT_CONFIG_COUNT"],
                    str(len(self.helper["ENGINE_GIT_CONFIG_OVERRIDES"])),
                )
                self.assertNotIn("DYLD_INSERT_LIBRARIES", env)
                self.assertNotIn("NODE_OPTIONS", env)
                for key in (
                    "NODE_PATH",
                    "LD_AUDIT",
                    "LD_LIBRARY_PATH",
                    "RUBYOPT",
                    "PERL5OPT",
                    "BUN_OPTIONS",
                    "OPENCODE_CONFIG",
                    "OPENCODE_PERMISSION",
                    "OPENCODE_AUTO_SHARE",
                ):
                    self.assertNotIn(key, env)
                self.assertNotIn("COPILOT_ALLOW_ALL", env)
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertEqual(env["HTTPS_PROXY"], "http://proxy.example.invalid:8080")
                self.assertEqual(env["HTTP_PROXY"], "proxy.example.invalid:8080")
                self.assertEqual(env["ALL_PROXY"], "socks5://proxy.example.invalid:1080")
                self.assertEqual(env["DO_NOT_TRACK"], "1")
                self.assertEqual(env["DISABLE_TELEMETRY"], "1")
                self.assertEqual(env["CODEX_HOME"], "/tmp/codex-auth")
                if os.name == "nt":
                    self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", env)
                else:
                    self.assertEqual(
                        env["DBUS_SESSION_BUS_ADDRESS"],
                        "unix:path=/run/user/1000/bus",
                    )
                self.assertEqual(env["XDG_RUNTIME_DIR"], "/run/user/1000")
                self.assertEqual(
                    claude_env["CLAUDE_CONFIG_DIR"],
                    "/tmp/claude-auth",
                )
                self.assertEqual(
                    claude_env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"],
                    "1",
                )
                self.assertEqual(pi_env["PI_CODING_AGENT_DIR"], "/tmp/pi-auth")
                self.assertEqual(claude_env["CLAUDE_CODE_USE_FOUNDRY"], "1")
                self.assertEqual(claude_env["CLOUD_ML_REGION"], "us-east5")
                self.assertEqual(
                    claude_env["ANTHROPIC_AUTH_TOKEN"],
                    "test-auth-token",
                )
                self.assertEqual(
                    claude_env["AWS_BEARER_TOKEN_BEDROCK"],
                    "test-token-placeholder",
                )
                self.assertEqual(
                    claude_env["ANTHROPIC_BEDROCK_BASE_URL"],
                    "https://bedrock.example.invalid",
                )
                self.assertEqual(
                    claude_env["ANTHROPIC_VERTEX_BASE_URL"],
                    "https://vertex.example.invalid",
                )
                self.assertEqual(claude_env["AWS_PROFILE"], "review-profile")
                self.assertNotIn("AWS_CONFIG_FILE", env)
                self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", env)
                self.assertNotIn(
                    "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
                    env,
                )
                self.assertNotIn("OPENROUTER_API_KEY", env)
                self.assertEqual(
                    claude_env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"],
                    "1",
                )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_parallel_tests_use_sanitized_environment_for_every_shell(self) -> None:
        observed: list[dict[str, object]] = []
        sanitized_env = {
            "PATH": "/usr/bin",
            "HOME": "/safe/home",
            "JAVA_TOOL_OPTIONS": "'-Duser.home=/safe/home'",
        }

        def fake_popen(command: object, **kwargs: object) -> mock.Mock:
            observed.append({"command": command, **kwargs})
            proc = mock.Mock()
            proc.returncode = 0
            proc.stderr = io.StringIO("")
            return proc

        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            with mock.patch.dict(
                self.helper["start_parallel_tests"].__globals__,
                {
                    "safe_test_env": lambda actual_repo, test_home: (
                        sanitized_env
                        if actual_repo == repo and not test_home.is_relative_to(repo)
                        else self.fail("parallel tests sanitized the wrong repository")
                    ),
                    "resolve_command": lambda name, actual_repo: (
                        f"/usr/bin/{name}"
                        if actual_repo == repo
                        else self.fail("parallel tests resolved a shell for the wrong repository")
                    ),
                },
            ), mock.patch("subprocess.Popen", side_effect=fake_popen):
                for shell_kind in ("default", "cmd", "powershell", "pwsh"):
                    proc, started = self.helper["start_parallel_tests"](
                        "run tests", repo, shell_kind
                    )
                    test_home = getattr(proc, "_autoreview_test_home")
                    self.assertTrue(test_home.is_dir())
                    self.helper["finish_parallel_tests"](proc, started)
                    self.assertFalse(test_home.exists())

        self.assertEqual(len(observed), 4)
        for invocation in observed:
            self.assertEqual(invocation["cwd"], repo)
            self.assertEqual(invocation["env"], sanitized_env)
            self.assertEqual(invocation["stderr"], subprocess.PIPE)
            self.assertTrue(invocation["text"])
        self.assertTrue(observed[0]["shell"])
        self.assertTrue(observed[1]["shell"])
        self.assertNotIn("shell", observed[2])
        self.assertNotIn("shell", observed[3])

    def test_parallel_test_finish_does_not_wait_for_inherited_stderr_pipe(
        self,
    ) -> None:
        release = threading.Event()
        stderr_thread = threading.Thread(target=release.wait, daemon=True)
        stderr_thread.start()
        try:
            with tempfile.TemporaryDirectory() as tempdir:
                test_home = Path(tempdir) / "test-home"
                test_home.mkdir()
                proc = mock.Mock()
                proc.returncode = 0
                proc.wait.return_value = 0
                setattr(proc, "_autoreview_test_home", test_home)
                setattr(proc, "_autoreview_stderr_thread", stderr_thread)

                started = time.time()
                before = time.monotonic()
                result = self.helper["finish_parallel_tests"](proc, started)
                elapsed = time.monotonic() - before

                self.assertEqual(result, 0)
                self.assertLess(elapsed, 1)
                self.assertFalse(test_home.exists())
        finally:
            release.set()
            stderr_thread.join(timeout=1)

    def test_source_tree_snapshot_detects_parallel_test_mutations(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            source = repo / "source.txt"
            source.write_text("before\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            git(repo, "commit", "-qm", "initial")
            before = self.helper["source_tree_snapshot"](repo)

            source.write_text("after\n", encoding="utf-8")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )
            source.write_text("before\n", encoding="utf-8")
            self.assertEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

            source.write_text("after\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            git(repo, "commit", "-qm", "mutated")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

            (repo / "generated.txt").write_text("generated\n", encoding="utf-8")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

    def test_rejects_output_paths_inside_reviewed_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            outside = root / "outside.json"

            with self.assertRaisesRegex(
                SystemExit,
                "--json-output must point outside",
            ):
                self.helper["reject_repo_output_paths"](
                    argparse.Namespace(
                        json_output=str(repo / "review.json"),
                        output=None,
                    ),
                    repo,
                )
            with self.assertRaisesRegex(
                SystemExit,
                "--output must point outside",
            ):
                self.helper["reject_repo_output_paths"](
                    argparse.Namespace(
                        json_output=None,
                        output=str(repo / "review.txt"),
                    ),
                    repo,
                )

            self.helper["reject_repo_output_paths"](
                argparse.Namespace(
                    json_output=str(outside),
                    output=None,
                ),
                repo,
            )
            alternate_repo = repo.with_name(repo.name.swapcase())
            with (
                mock.patch.object(
                    os.path,
                    "samefile",
                    side_effect=lambda left, right: (
                        str(left).casefold() == str(right).casefold()
                    ),
                ),
                self.assertRaisesRegex(
                    SystemExit,
                    "--json-output must point outside",
                ),
            ):
                self.helper["reject_repo_output_paths"](
                    argparse.Namespace(
                        json_output=str(alternate_repo / "review.json"),
                        output=None,
                    ),
                    repo,
                )

    def test_atomic_output_replaces_hard_link_without_touching_repo_file(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            tracked = repo / "tracked.txt"
            tracked.write_text("tracked\n", encoding="utf-8")
            outside = root / "review.txt"
            os.link(tracked, outside)

            self.helper["atomic_write_text"](outside, "review\n")

            self.assertEqual(
                tracked.read_text(encoding="utf-8"),
                "tracked\n",
            )
            self.assertEqual(
                outside.read_text(encoding="utf-8"),
                "review\n",
            )
            self.assertFalse(os.path.samefile(tracked, outside))

    def test_partial_panel_failure_output_is_terminal_escaped(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            reviewers = [
                argparse.Namespace(
                    engine="codex",
                    model=None,
                    fallback_model=None,
                    thinking=None,
                ),
                argparse.Namespace(
                    engine="claude",
                    model=None,
                    fallback_model=None,
                    thinking=None,
                ),
            ]
            args = argparse.Namespace(
                allow_partial_panel=True,
                require_finding=[],
            )
            report = {
                "findings": [],
                "overall_correctness": "patch is correct",
                "overall_explanation": "clean",
                "overall_confidence": 0.9,
            }

            def run_reviewer(reviewer: argparse.Namespace, *_args: object) -> object:
                if reviewer.engine == "claude":
                    raise RuntimeError(
                        "\x1b]8;;https://example.invalid\x07click"
                        "\x1b]8;;\x07"
                    )
                return report

            stdout = io.StringIO()
            with (
                mock.patch.dict(
                    self.helper["run_panel"].__globals__,
                    {"run_reviewer": run_reviewer},
                ),
                contextlib.redirect_stdout(stdout),
            ):
                self.helper["run_panel"](
                    args,
                    reviewers,
                    repo,
                    "prompt",
                    set(),
                    False,
                )

            output = stdout.getvalue()
            self.assertNotIn("\x1b", output)
            self.assertNotIn("\x07", output)
            self.assertIn("\\x1b]8;;", output)
            self.assertIn("\\x07", output)

    def test_fatal_panel_failure_output_is_terminal_escaped(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            reviewers = [
                argparse.Namespace(
                    engine="codex",
                    model=None,
                    fallback_model=None,
                    thinking=None,
                )
            ]
            args = argparse.Namespace(
                allow_partial_panel=False,
                require_finding=[],
            )

            def run_reviewer(*_args: object) -> object:
                raise RuntimeError("\x1b]8;;https://example.invalid\x07click")

            with (
                mock.patch.dict(
                    self.helper["run_panel"].__globals__,
                    {"run_reviewer": run_reviewer},
                ),
                self.assertRaises(SystemExit) as error,
            ):
                self.helper["run_panel"](
                    args,
                    reviewers,
                    repo,
                    "prompt",
                    set(),
                    False,
                )

            message = str(error.exception)
            self.assertNotIn("\x1b", message)
            self.assertNotIn("\x07", message)
            self.assertIn("\\x1b]8;;", message)
            self.assertIn("\\x07", message)

    def test_source_tree_snapshot_supports_staged_files_before_first_commit(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            source = repo / "source.txt"
            source.write_text("before\n", encoding="utf-8")
            git(repo, "add", "source.txt")

            before = self.helper["source_tree_snapshot"](repo)
            symbolic_head = git(repo, "symbolic-ref", "HEAD").strip()
            self.assertEqual(before[0], f"unborn:{symbolic_head}")

            git(repo, "symbolic-ref", "HEAD", "refs/heads/other")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )
            git(repo, "symbolic-ref", "HEAD", symbolic_head)

            source.write_text("after\n", encoding="utf-8")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

    @unittest.skipIf(os.name == "nt", "the true command is POSIX-only")
    def test_cli_parallel_tests_supports_unborn_repository(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source = repo / "source.txt"
            source.write_text("staged\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            codex_bin = self.helper["write_executable"](
                root / "codex",
                self.helper["fake_codex_script"](),
            )
            record_path = root / "record.json"
            env = os.environ.copy()
            env.update(
                {
                    "AUTOREVIEW_FAKE_RECORD": str(record_path),
                    "HOME": str(root),
                    "USERPROFILE": str(root),
                }
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--mode",
                    "local",
                    "--engine",
                    "codex",
                    "--codex-bin",
                    str(codex_bin),
                    "--parallel-tests",
                    "true",
                ],
                cwd=repo,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("autoreview clean", result.stdout)

    @unittest.skipIf(os.name == "nt", "the fake executable is POSIX-only")
    def test_cli_detects_source_mutation_without_parallel_tests(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source = repo / "source.txt"
            source.write_text("before\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            git(repo, "commit", "-qm", "initial")
            source.write_text("review me\n", encoding="utf-8")
            codex_bin = self.helper["write_executable"](
                root / "codex",
                self.helper["fake_codex_script"](),
            )
            record_path = root / "record.json"
            env = os.environ.copy()
            env.update(
                {
                    "AUTOREVIEW_FAKE_MUTATE": str(source),
                    "AUTOREVIEW_FAKE_RECORD": str(record_path),
                    "HOME": str(root),
                    "USERPROFILE": str(root),
                }
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(SCRIPT),
                    "--mode",
                    "local",
                    "--engine",
                    "codex",
                    "--codex-bin",
                    str(codex_bin),
                ],
                cwd=repo,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )

            self.assertEqual(result.returncode, 1, result.stdout)
            self.assertIn(
                "source changed after the review bundle was created",
                result.stderr,
            )
            self.assertTrue(record_path.is_file())

    def test_source_tree_snapshot_hashes_binary_and_untracked_tail_bytes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            tracked = repo / "tracked.bin"
            tracked.write_bytes(b"\0tracked-before")
            git(repo, "add", "tracked.bin")
            git(repo, "commit", "-qm", "initial")
            limit = self.helper["MAX_BUNDLE_TEXT_BYTES"]
            untracked = repo / "generated.bin"
            untracked.write_bytes(b"\0" + b"a" * (limit + 16))
            before = self.helper["source_tree_snapshot"](repo)

            tracked.write_bytes(b"\0tracked-after!")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )
            tracked.write_bytes(b"\0tracked-before")
            self.assertEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

            with untracked.open("r+b") as stream:
                stream.seek(-1, os.SEEK_END)
                stream.write(b"b")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

    def test_source_tree_snapshot_includes_index_state(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            source = repo / "source.txt"
            source.write_text("before\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            git(repo, "commit", "-qm", "initial")
            before = self.helper["source_tree_snapshot"](repo)

            source.write_text("staged\n", encoding="utf-8")
            git(repo, "add", "source.txt")
            source.write_text("before\n", encoding="utf-8")
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

    def test_source_tree_snapshot_includes_tracked_submodule_contents(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            child = root / "child"
            child.mkdir()
            git(child, "init", "-q")
            source = child / "source.txt"
            source.write_text("before\n", encoding="utf-8")
            git(child, "add", "source.txt")
            git(child, "commit", "-qm", "initial")

            repo = init_repo(root)
            git(
                repo,
                "-c",
                "protocol.file.allow=always",
                "submodule",
                "add",
                "-q",
                str(child),
                "vendor/dependency",
            )
            git(repo, "commit", "-qam", "add submodule")
            before = self.helper["source_tree_snapshot"](repo)

            (repo / "vendor/dependency/source.txt").write_text(
                "after\n",
                encoding="utf-8",
            )
            self.assertNotEqual(
                self.helper["source_tree_snapshot"](repo),
                before,
            )

    def test_trusted_maintainer_testbox_preserves_only_credentials(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            isolated_home = root / "test-home"
            host_home = root / "host-home"
            rustup_home = host_home / ".rustup"
            rustup_home.mkdir(parents=True)
            blacksmith_home = host_home / ".blacksmith"
            blacksmith_home.mkdir()
            blacksmith_credentials = blacksmith_home / "credentials"
            blacksmith_credentials.write_bytes(b"test-blacksmith-credentials")
            (blacksmith_home / "unrelated-state").write_text(
                "do not copy",
                encoding="utf-8",
            )
            local_bin = repo / ".venv" / "bin"
            local_bin.mkdir(parents=True)
            try:
                os.environ["PATH"] = f"{local_bin}{os.pathsep}/usr/bin"
                os.environ["CI"] = "1"
                os.environ["GRADLE_USER_HOME"] = "/host/gradle"
                os.environ["HOME"] = str(host_home)
                os.environ["JAVA_HOME"] = "/opt/jdk"
                os.environ["JAVA_TOOL_OPTIONS"] = "-javaagent:/host/unsafe.jar"
                os.environ["NODE_ENV"] = "test"
                os.environ["OPENCLAW_TESTBOX"] = "1"
                os.environ["PROJECT_FEATURE_MODE"] = "strict"
                os.environ["GH_CONFIG_DIR"] = "/host/gh"
                os.environ["CLOUDSDK_CONFIG"] = "/host/gcloud"
                os.environ["XDG_CONFIG_HOME"] = "/host/xdg"
                os.environ["GITHUB_TOKEN"] = "test-token-placeholder"
                os.environ["AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"] = (
                    "/host/aws-token"
                )
                os.environ["AZURE_FEDERATED_TOKEN_FILE"] = "/host/azure-token"
                os.environ["CI_JOB_JWT"] = "header.payload.signature"
                os.environ["DOCKER_AUTH_CONFIG"] = '{"auths":{"registry":{}}}'
                os.environ["PGPASSFILE"] = "/host/pgpass"
                os.environ["PGPASSWORD"] = "short-password"
                os.environ["REDISCLI_AUTH"] = "short-password"
                os.environ["BASH_FUNC_testcmd%%"] = "() { echo injected; }"
                os.environ["SHELLOPTS"] = "xtrace"
                os.environ["NODE_OPTIONS"] = "--require=/tmp/unsafe.js"
                os.environ["SERVICE_URL"] = (
                    "https://review-user:review-password@example.invalid/api"
                )
                os.environ["UNRELATED_VALUE"] = "ghp_" + "A" * 24

                env = self.helper["safe_test_env"](repo, isolated_home)

                self.assertEqual(env["PATH"], os.environ["PATH"])
                self.assertEqual(env["CI"], "1")
                self.assertEqual(
                    env["GRADLE_USER_HOME"],
                    str((isolated_home / ".gradle").resolve()),
                )
                self.assertEqual(env["JAVA_HOME"], "/opt/jdk")
                self.assertEqual(
                    env["JAVA_TOOL_OPTIONS"],
                    self.helper["quote_java_tool_option"](
                        f"-Duser.home={isolated_home.resolve()}"
                    ),
                )
                self.assertEqual(env["NODE_ENV"], "test")
                self.assertEqual(env["OPENCLAW_TESTBOX"], "1")
                isolated_blacksmith = isolated_home / ".blacksmith"
                self.assertEqual(
                    (isolated_blacksmith / "credentials").read_bytes(),
                    b"test-blacksmith-credentials",
                )
                self.assertFalse(
                    (isolated_blacksmith / "unrelated-state").exists()
                )
                if os.name != "nt":
                    self.assertEqual(
                        stat.S_IMODE(
                            (isolated_blacksmith / "credentials").stat().st_mode
                        ),
                        0o600,
                    )
                self.assertNotIn("PROJECT_FEATURE_MODE", env)
                self.assertEqual(env["HOME"], str(isolated_home.resolve()))
                self.assertNotIn("CARGO_HOME", env)
                self.assertEqual(env["RUSTUP_HOME"], str(rustup_home.resolve()))
                self.assertEqual(
                    env["XDG_CONFIG_HOME"],
                    str(isolated_home.resolve() / ".config"),
                )
                self.assertNotIn("GH_CONFIG_DIR", env)
                self.assertNotIn("CLOUDSDK_CONFIG", env)
                self.assertNotIn("GITHUB_TOKEN", env)
                self.assertNotIn("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE", env)
                self.assertNotIn("AZURE_FEDERATED_TOKEN_FILE", env)
                self.assertNotIn("CI_JOB_JWT", env)
                self.assertNotIn("DOCKER_AUTH_CONFIG", env)
                self.assertNotIn("PGPASSFILE", env)
                self.assertNotIn("PGPASSWORD", env)
                self.assertNotIn("REDISCLI_AUTH", env)
                self.assertNotIn("BASH_FUNC_testcmd%%", env)
                self.assertNotIn("SHELLOPTS", env)
                self.assertNotIn("NODE_OPTIONS", env)
                self.assertNotIn("SERVICE_URL", env)
                self.assertNotIn("UNRELATED_VALUE", env)

                os.environ.pop("HOME")
                os.environ["USERPROFILE"] = str(host_home)
                windows_env = self.helper["safe_test_env"](
                    repo,
                    root / "windows-test-home",
                )
                self.assertNotIn("CARGO_HOME", windows_env)
                self.assertEqual(
                    windows_env["RUSTUP_HOME"],
                    str(rustup_home.resolve()),
                )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_parallel_test_environment_isolates_jvm_user_home(self) -> None:
        java = shutil.which("java")
        if java is None:
            self.skipTest("java is not installed")
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            isolated_home = root / "test home"
            env = self.helper["safe_test_env"](repo, isolated_home)

            result = subprocess.run(
                [java, "-XshowSettings:properties", "-version"],
                text=True,
                encoding="utf-8",
                errors="replace",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                check=False,
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            user_home = next(
                (
                    line.split("=", 1)[1].strip()
                    for line in result.stderr.splitlines()
                    if line.strip().startswith("user.home =")
                ),
                None,
            )
            self.assertEqual(user_home, str(isolated_home.resolve()))

    def test_parallel_test_stderr_relay_hides_only_our_java_banner(self) -> None:
        option = self.helper["quote_java_tool_option"](
            "-Duser.home=/tmp/test home"
        )
        stream = io.StringIO(
            f"Picked up JAVA_TOOL_OPTIONS: {option}\n"
            "ordinary stderr\n"
            f"Picked up JAVA_TOOL_OPTIONS: {option} -Dextra=true\n"
        )
        output = io.StringIO()

        with mock.patch("sys.stderr", output):
            self.helper["relay_parallel_test_stderr"](stream, option)

        self.assertEqual(
            output.getvalue(),
            "ordinary stderr\n"
            f"Picked up JAVA_TOOL_OPTIONS: {option} -Dextra=true\n",
        )

    def test_java_tool_option_quote_round_trips_special_paths(self) -> None:
        java = shutil.which("java")
        if java is None:
            self.skipTest("java is not installed")
        names = ["space home", "apostrophe's home"]
        if os.name != "nt":
            names.append('double"quote home')
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as tempdir:
                home = Path(tempdir) / name
                home.mkdir()
                env = os.environ.copy()
                env["JAVA_TOOL_OPTIONS"] = self.helper["quote_java_tool_option"](
                    f"-Duser.home={home}"
                )
                result = subprocess.run(
                    [java, "-XshowSettings:properties", "-version"],
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(f"user.home = {home}", result.stderr)

    def test_safe_proxy_url_accepts_credential_free_formats(self) -> None:
        for value in (
            "http://proxy.example.invalid:8080",
            "proxy.example.invalid:8080",
            "socks4://proxy.example.invalid",
            "socks4a://proxy.example.invalid",
        ):
            with self.subTest(value=value):
                self.assertTrue(self.helper["safe_proxy_url"](value))

        for value in (
            "http://review-user:review-password@proxy.example.invalid:8080",
            "socks5://review-user:review-password@proxy.example.invalid:1080",
        ):
            with self.subTest(value=value):
                self.assertFalse(self.helper["safe_proxy_url"](value))

    def test_safe_engine_env_rejects_credentialed_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir, mock.patch.dict(
            os.environ,
            {
                "HTTPS_PROXY": (
                    "http://review-user:review-password@proxy.example.invalid:8080"
                )
            },
            clear=False,
        ):
            repo = init_repo(Path(tempdir))
            with self.assertRaisesRegex(SystemExit, "credentialed or malformed proxy"):
                self.helper["safe_engine_env"](repo, engine="codex")

    def test_safe_temp_root_rejects_reviewed_repo_parent(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            hostile_temp = repo / "tmp"
            hostile_temp.mkdir()

            with mock.patch.object(
                tempfile,
                "gettempdir",
                return_value=str(hostile_temp),
            ), self.assertRaisesRegex(
                SystemExit,
                "temporary directory must be outside",
            ):
                self.helper["safe_temp_root"](repo)

    @unittest.skipIf(os.name == "nt", "POSIX Testbox temp-root behavior")
    def test_testbox_parallel_test_temp_root_stays_within_socket_limit(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            long_temp = root / ("macos-temp-root-" + "x" * 96)
            long_temp.mkdir()

            with mock.patch.object(
                tempfile,
                "gettempdir",
                return_value=str(long_temp),
            ), mock.patch.dict(
                os.environ,
                {"OPENCLAW_TESTBOX": "1"},
            ):
                selected = self.helper["parallel_test_temp_root"](repo)

            self.assertEqual(selected, Path("/tmp").resolve())
            socket_path = (
                selected
                / ("autoreview-test-home-" + "x" * 8)
                / ".blacksmith"
                / "c"
                / "6d146d2f25180c1d.sock"
            )
            self.assertLess(len(os.fsencode(socket_path)), 104)

    def test_parallel_test_temp_root_keeps_configured_root_without_testbox(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            configured_temp = root / "configured-temp"
            configured_temp.mkdir()

            with mock.patch.object(
                tempfile,
                "gettempdir",
                return_value=str(configured_temp),
            ), mock.patch.dict(
                os.environ,
                {"OPENCLAW_TESTBOX": "0"},
            ):
                selected = self.helper["parallel_test_temp_root"](repo)

            self.assertEqual(selected, configured_temp.resolve())

    def test_claude_fable_alias_requires_fable_safe_mode_version(self) -> None:
        args = argparse.Namespace(
            claude_bin="claude",
            fallback_model=None,
            model="fable",
        )
        version_result = subprocess.CompletedProcess(
            ["claude", "--version"],
            0,
            "2.1.169 (Claude Code)",
            "",
        )

        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            with mock.patch.dict(
                self.helper["ensure_claude_isolation_supported"].__globals__,
                {
                    "resolve_command": lambda *_args: "/usr/bin/claude",
                    "safe_engine_env": lambda *_args, **_kwargs: {},
                    "safe_temp_root": lambda _repo: Path(tempdir),
                    "run": lambda *_args, **_kwargs: version_result,
                },
            ), self.assertRaisesRegex(
                SystemExit,
                "2.1.170",
            ):
                self.helper["ensure_claude_isolation_supported"](args, repo)

    def test_claude_runs_outside_repo_with_auto_memory_disabled(self) -> None:
        args = argparse.Namespace(
            claude_allowed_tools=None,
            claude_bin="claude",
            fallback_model=None,
            model=None,
            stream_engine_output=False,
            thinking=None,
            tools=False,
            web_search=False,
        )
        observed: dict[str, object] = {}

        def fake_run(
            _cmd: list[str],
            cwd: Path,
            **kwargs: object,
        ) -> subprocess.CompletedProcess[str]:
            observed["cwd"] = cwd
            observed["env"] = kwargs["env"]
            return subprocess.CompletedProcess([], 0, "{}", "")

        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            with mock.patch.dict(
                self.helper["run_claude"].__globals__,
                {
                    "ensure_claude_isolation_supported": lambda *_args: None,
                    "resolve_command": lambda *_args: "/usr/bin/claude",
                    "run_with_heartbeat": fake_run,
                    "safe_engine_env": lambda *_args, **_kwargs: {
                        "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"
                    },
                },
            ):
                self.helper["run_claude"](args, repo, "prompt")

            self.assertFalse(
                self.helper["is_within"](observed["cwd"], repo.resolve())
            )
            self.assertEqual(
                observed["env"]["CLAUDE_CODE_DISABLE_AUTO_MEMORY"],
                "1",
            )

    def test_build_prompt_rejects_secret_like_git_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            secret = "ghp_" + "A" * 24
            git(repo, "checkout", "-q", "-b", f"feature/{secret}")

            with self.assertRaisesRegex(SystemExit, "secret-like content"):
                self.helper["build_prompt"](repo, "local", None, "diff", "", "")

            git(repo, "checkout", "-q", "-B", "safe-branch")
            with self.assertRaisesRegex(SystemExit, "secret-like content"):
                self.helper["build_prompt"](
                    repo,
                    "branch",
                    f"origin/{secret}",
                    "diff",
                    "",
                    "",
                )

    def test_codex_env_rejects_executable_dbus_transport(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["DBUS_SESSION_BUS_ADDRESS"] = (
                    "unixexec:path=/tmp/hostile-helper"
                )
                env = self.helper["safe_engine_env"](repo, engine="codex")
                self.assertNotIn("DBUS_SESSION_BUS_ADDRESS", env)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_multi_provider_engines_preserve_provider_auth(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir).resolve()
            repo = init_repo(root)
            try:
                os.environ["DEEPSEEK_API_KEY"] = "test-token-placeholder"
                os.environ["CEREBRAS_API_KEY"] = "test-token-placeholder"
                os.environ["CLOUDFLARE_ACCOUNT_ID"] = "test-account"
                os.environ["CLOUDFLARE_API_TOKEN"] = "test-token-placeholder"
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = (
                    str(root / "provider-credentials.json")
                )
                os.environ["AWS_ROLE_ARN"] = (
                    "arn:aws:iam::123456789012:role/autoreview"
                )
                os.environ["AWS_CONTAINER_AUTHORIZATION_TOKEN"] = (
                    "test-token-placeholder"
                )
                os.environ["AWS_CONTAINER_CREDENTIALS_FULL_URI"] = (
                    "http://169.254.170.2/credentials"
                )
                os.environ["AWS_WEB_IDENTITY_TOKEN_FILE"] = str(
                    root / "web-identity",
                )
                os.environ["AWS_CONFIG_FILE"] = str(root / "aws-config")
                os.environ["AWS_SHARED_CREDENTIALS_FILE"] = str(
                    root / "aws-credentials",
                )
                os.environ["NODE_EXTRA_CA_CERTS"] = str(root / "corporate-ca.pem")
                os.environ["SSL_CERT_FILE"] = str(root / "tls-ca.pem")
                os.environ["SSL_CERT_DIR"] = str(root / "tls-ca")
                os.environ["SNOWFLAKE_ACCOUNT"] = "test-account"
                os.environ["SNOWFLAKE_CORTEX_TOKEN"] = "test-token-placeholder"
                os.environ["AZURE_RESOURCE_NAME"] = "test-resource"
                os.environ["ANTHROPIC_OAUTH_TOKEN"] = "test-token-placeholder"
                os.environ["AWS_BEDROCK_FORCE_HTTP1"] = "1"
                os.environ["AWS_BEDROCK_SKIP_AUTH"] = "1"
                os.environ["AZURE_CLIENT_ID"] = "test-client"
                os.environ["AZURE_CLIENT_SECRET"] = "test-token-placeholder"
                os.environ["AZURE_TENANT_ID"] = "test-tenant"
                os.environ["GCLOUD_PROJECT"] = "test-project"
                os.environ["GOOGLE_CLOUD_PROJECT"] = "test-project"
                os.environ["CODEX_API_KEY"] = "test-token-placeholder"
                os.environ["CODEX_CA_CERTIFICATE"] = str(root / "codex-ca.pem")
                os.environ["COPILOT_GITHUB_TOKEN"] = "test-token-placeholder"
                os.environ["PI_OFFLINE"] = "1"
                os.environ["PI_SKIP_VERSION_CHECK"] = "1"
                os.environ["PI_TELEMETRY"] = "0"
                os.environ["NPM_TOKEN"] = "test-token-placeholder"
                os.environ["SENTRY_API_KEY"] = "test-token-placeholder"
                os.environ["SENTRY_AUTH_TOKEN"] = "test-token-placeholder"
                os.environ["DIGITALOCEAN_ACCESS_TOKEN"] = "test-token-placeholder"
                os.environ["GITLAB_TOKEN"] = "test-token-placeholder"
                os.environ["NODE_OPTIONS"] = "--require=/tmp/unsafe.js"
                os.environ["GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES"] = "1"
                os.environ["XDG_DATA_HOME"] = str(root / "opencode-auth")

                for engine in ("opencode", "pi"):
                    with self.subTest(engine=engine):
                        env = self.helper["safe_engine_env"](repo, engine=engine)
                        for key in (
                            "AWS_ROLE_ARN",
                            "AWS_CONTAINER_AUTHORIZATION_TOKEN",
                            "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                            "AWS_BEDROCK_FORCE_HTTP1",
                            "AWS_BEDROCK_SKIP_AUTH",
                            "AWS_CONFIG_FILE",
                            "AWS_SHARED_CREDENTIALS_FILE",
                            "AWS_WEB_IDENTITY_TOKEN_FILE",
                            "CEREBRAS_API_KEY",
                            "CLOUDFLARE_ACCOUNT_ID",
                            "CLOUDFLARE_API_TOKEN",
                            "COPILOT_GITHUB_TOKEN",
                            "DEEPSEEK_API_KEY",
                            "GOOGLE_APPLICATION_CREDENTIALS",
                            "NODE_EXTRA_CA_CERTS",
                            "SSL_CERT_DIR",
                            "SSL_CERT_FILE",
                            "SNOWFLAKE_ACCOUNT",
                            "SNOWFLAKE_CORTEX_TOKEN",
                            "AZURE_RESOURCE_NAME",
                            "ANTHROPIC_OAUTH_TOKEN",
                        ):
                            self.assertEqual(env[key], os.environ[key])
                        self.assertNotIn("NODE_OPTIONS", env)
                        self.assertNotIn("NPM_TOKEN", env)
                        self.assertNotIn("SENTRY_API_KEY", env)
                        self.assertNotIn("SENTRY_AUTH_TOKEN", env)
                        self.assertNotIn(
                            "GOOGLE_EXTERNAL_ACCOUNT_ALLOW_EXECUTABLES",
                            env,
                        )
                        if engine == "opencode":
                            self.assertEqual(
                                env["DIGITALOCEAN_ACCESS_TOKEN"],
                                os.environ["DIGITALOCEAN_ACCESS_TOKEN"],
                            )
                            self.assertEqual(
                                env["GITLAB_TOKEN"],
                                os.environ["GITLAB_TOKEN"],
                            )
                            self.assertEqual(
                                env["XDG_DATA_HOME"],
                                str(root / "opencode-auth"),
                            )
                        else:
                            self.assertNotIn("DIGITALOCEAN_ACCESS_TOKEN", env)
                            self.assertNotIn("GITLAB_TOKEN", env)
                            self.assertEqual(env["PI_OFFLINE"], "1")
                            self.assertEqual(env["PI_SKIP_VERSION_CHECK"], "1")
                            self.assertEqual(env["PI_TELEMETRY"], "0")

                claude_env = self.helper["safe_engine_env"](repo, engine="claude")
                for key in (
                    "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_SECRET",
                    "AZURE_TENANT_ID",
                    "GCLOUD_PROJECT",
                    "GOOGLE_CLOUD_PROJECT",
                    "AWS_ROLE_ARN",
                    "AWS_CONFIG_FILE",
                    "AWS_SHARED_CREDENTIALS_FILE",
                    "AWS_WEB_IDENTITY_TOKEN_FILE",
                    "GOOGLE_APPLICATION_CREDENTIALS",
                    "NODE_EXTRA_CA_CERTS",
                    "SSL_CERT_DIR",
                    "SSL_CERT_FILE",
                ):
                    self.assertEqual(claude_env[key], os.environ[key])
                self.assertNotIn("DEEPSEEK_API_KEY", claude_env)
                self.assertNotIn("NODE_OPTIONS", claude_env)
                codex_env = self.helper["safe_engine_env"](repo, engine="codex")
                for key in (
                    "CODEX_API_KEY",
                    "CODEX_CA_CERTIFICATE",
                    "SSL_CERT_DIR",
                    "SSL_CERT_FILE",
                ):
                    self.assertEqual(codex_env[key], os.environ[key])
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_multi_provider_custom_credentials_require_explicit_safe_names(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["CORP_LLM_API_KEY"] = "test-token-placeholder"
                os.environ["CORP_AUTH_TOKEN"] = "test-token-placeholder"
                os.environ["AUTOREVIEW_PROVIDER_ENV_ALLOW"] = (
                    "CORP_LLM_API_KEY,CORP_AUTH_TOKEN"
                )

                for engine in ("opencode", "pi"):
                    env = self.helper["safe_engine_env"](repo, engine=engine)
                    self.assertEqual(
                        env["CORP_LLM_API_KEY"],
                        os.environ["CORP_LLM_API_KEY"],
                    )
                    self.assertEqual(
                        env["CORP_AUTH_TOKEN"],
                        os.environ["CORP_AUTH_TOKEN"],
                    )
                    self.assertNotIn("AUTOREVIEW_PROVIDER_ENV_ALLOW", env)

                os.environ["AUTOREVIEW_PROVIDER_ENV_ALLOW"] = "NODE_OPTIONS"
                with self.assertRaisesRegex(
                    SystemExit,
                    "invalid AUTOREVIEW_PROVIDER_ENV_ALLOW entry",
                ):
                    self.helper["safe_engine_env"](repo, engine="pi")
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_provider_credential_paths_are_forwarded_as_absolute(self) -> None:
        old_env = os.environ.copy()
        old_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            try:
                os.chdir(repo)
                os.environ["AWS_CONFIG_FILE"] = "../shared/aws-config"
                os.environ["SSL_CERT_DIR"] = os.pathsep.join(
                    ("../tls/one", "../tls/two"),
                )

                env = self.helper["safe_engine_env"](repo, engine="pi")

                self.assertEqual(
                    env["AWS_CONFIG_FILE"],
                    str((root / "shared" / "aws-config").resolve()),
                )
                self.assertEqual(
                    env["SSL_CERT_DIR"],
                    os.pathsep.join(
                        (
                            str((root / "tls" / "one").resolve()),
                            str((root / "tls" / "two").resolve()),
                        )
                    ),
                )
            finally:
                os.chdir(old_cwd)
                os.environ.clear()
                os.environ.update(old_env)

    def test_opencode_rejects_repo_local_xdg_auth_store(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["XDG_DATA_HOME"] = str(repo / ".opencode-data")
                os.environ["AWS_CONFIG_FILE"] = str(repo / ".aws-config")
                os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = str(
                    repo / "provider-credentials.json"
                )
                os.environ["NODE_EXTRA_CA_CERTS"] = str(repo / "ca.pem")
                os.environ["SSL_CERT_FILE"] = str(repo / "tls-ca.pem")
                os.environ["SSL_CERT_DIR"] = os.pathsep.join(
                    (str(repo.parent / "tls-ca"), str(repo / "tls-ca")),
                )
                env = self.helper["safe_engine_env"](repo, engine="opencode")
                self.assertNotIn("XDG_DATA_HOME", env)
                self.assertNotIn("AWS_CONFIG_FILE", env)
                self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", env)
                self.assertNotIn("NODE_EXTRA_CA_CERTS", env)
                self.assertNotIn("SSL_CERT_FILE", env)
                self.assertNotIn("SSL_CERT_DIR", env)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_engines_reject_repo_local_config_roots(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            try:
                os.environ["CLAUDE_CONFIG_DIR"] = str(repo / ".claude")
                os.environ["CODEX_HOME"] = str(repo / ".codex")
                os.environ["PI_CODING_AGENT_DIR"] = str(repo / ".pi")
                os.environ["CODEX_CA_CERTIFICATE"] = str(repo / "codex-ca.pem")
                os.environ["SSL_CERT_FILE"] = str(repo / "tls-ca.pem")
                os.environ["HOME"] = str(repo)
                os.environ["USERPROFILE"] = str(repo)
                claude_env = self.helper["safe_engine_env"](repo, engine="claude")
                codex_env = self.helper["safe_engine_env"](repo, engine="codex")
                pi_env = self.helper["safe_engine_env"](repo, engine="pi")
                self.assertNotIn("CLAUDE_CONFIG_DIR", claude_env)
                self.assertNotIn("CODEX_HOME", codex_env)
                self.assertNotIn("CODEX_CA_CERTIFICATE", codex_env)
                self.assertNotIn("SSL_CERT_FILE", codex_env)
                self.assertNotIn("PI_CODING_AGENT_DIR", pi_env)
                self.assertNotIn("HOME", claude_env)
                self.assertNotIn("USERPROFILE", claude_env)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_codex_auth_config_ignores_repo_local_home(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            config_dir = repo / ".codex"
            config_dir.mkdir()
            (config_dir / "config.toml").write_text(
                'forced_login_method = "api"\n',
                encoding="utf-8",
            )
            try:
                os.environ["CODEX_HOME"] = str(config_dir)
                self.assertEqual(self.helper["codex_auth_config_flags"](repo), [])
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_codex_runtime_home_links_only_auth_and_persists_refresh(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source_home = root / "host-home" / ".codex"
            runtime_home = root / "runtime" / "codex-home"
            source_home.mkdir(parents=True)
            source_auth = source_home / "auth.json"
            source_auth.write_text(
                '{"token":"test-token-placeholder"}',
                encoding="utf-8",
            )
            (source_home / "config.toml").write_text(
                'cli_auth_credentials_store = "file"\n',
                encoding="utf-8",
            )
            try:
                os.environ["CODEX_HOME"] = str(source_home)
                linked = self.helper["prepare_codex_runtime_auth"](repo, runtime_home)
                self.assertTrue(linked)
                self.assertTrue((runtime_home / "auth.json").is_file())
                self.assertTrue(
                    os.path.samefile(source_auth, runtime_home / "auth.json")
                )
                self.assertFalse((runtime_home / "config.toml").exists())
                self.assertIn(
                    'cli_auth_credentials_store="file"',
                    self.helper["codex_auth_config_flags"](
                        repo,
                        force_file=True,
                    ),
                )

                (runtime_home / "auth.json").write_text(
                    '{"token":"test-auth-token"}',
                    encoding="utf-8",
                )
                self.assertEqual(
                    json.loads(source_auth.read_text(encoding="utf-8"))["token"],
                    "test-auth-token",
                )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_codex_runtime_home_does_not_promote_keyring_fallback_file(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source_home = root / "host-home" / ".codex"
            source_home.mkdir(parents=True)
            (source_home / "auth.json").write_text(
                '{"token":"test-token-placeholder"}',
                encoding="utf-8",
            )
            (source_home / "config.toml").write_text(
                'cli_auth_credentials_store = "keyring"\n',
                encoding="utf-8",
            )
            try:
                os.environ["CODEX_HOME"] = str(source_home)
                self.assertFalse(
                    self.helper["prepare_codex_runtime_auth"](
                        repo,
                        root / "runtime" / "codex-home",
                    )
                )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_codex_runtime_home_fails_closed_when_linking_is_unavailable(
        self,
    ) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source_home = root / "host-home" / ".codex"
            source_home.mkdir(parents=True)
            source_auth = source_home / "auth.json"
            source_auth.write_text(
                '{"token":"test-token-placeholder"}',
                encoding="utf-8",
            )
            try:
                os.environ["CODEX_HOME"] = str(source_home)
                with (
                    mock.patch("os.link", side_effect=OSError("blocked")),
                    mock.patch.object(
                        Path,
                        "symlink_to",
                        side_effect=OSError("blocked"),
                    ),
                    self.assertRaisesRegex(
                        SystemExit,
                        "unable to isolate Codex file authentication",
                    ),
                ):
                    self.helper["prepare_codex_runtime_auth"](
                        repo,
                        root / "runtime" / "codex-home",
                    )
                self.assertEqual(
                    json.loads(source_auth.read_text(encoding="utf-8"))["token"],
                    "test-token-placeholder",
                )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_codex_runtime_home_preserves_auto_keyring_namespace(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            source_home = root / "host-home" / ".codex"
            runtime_home = root / "runtime" / "codex-home"
            source_home.mkdir(parents=True)
            (source_home / "auth.json").write_text(
                '{"token":"test-token-placeholder"}',
                encoding="utf-8",
            )
            (source_home / "config.toml").write_text(
                'cli_auth_credentials_store = "auto"\n',
                encoding="utf-8",
            )
            try:
                os.environ["CODEX_HOME"] = str(source_home)
                linked = self.helper["prepare_codex_runtime_auth"](
                    repo,
                    runtime_home,
                )
                self.assertFalse(linked)
                flags = self.helper["codex_auth_config_flags"](repo)
                self.assertIn('cli_auth_credentials_store="auto"', flags)
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_empty_codex_home_uses_external_default(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            default_home = root / "host-home" / ".codex"
            default_home.mkdir(parents=True)
            try:
                os.environ["CODEX_HOME"] = ""
                with mock.patch.object(
                    Path,
                    "home",
                    return_value=default_home.parent,
                ):
                    self.assertEqual(
                        self.helper["codex_source_home"](repo),
                        default_home.resolve(),
                    )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_empty_codex_home_ignores_missing_default(self) -> None:
        old = os.environ.copy()
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            missing_home = root / "missing-home"
            try:
                os.environ["CODEX_HOME"] = ""
                with mock.patch.object(
                    Path,
                    "home",
                    return_value=missing_home,
                ):
                    self.assertIsNone(
                        self.helper["codex_source_home"](repo)
                    )
            finally:
                os.environ.clear()
                os.environ.update(old)

    def test_opencode_web_search_preserves_explicit_exa_opt_in(self) -> None:
        old = os.environ.copy()
        try:
            os.environ["OPENCODE_ENABLE_EXA"] = "1"
            enabled = self.helper["opencode_review_env"](True)
            disabled = self.helper["opencode_review_env"](False)
            self.assertEqual(enabled["OPENCODE_ENABLE_EXA"], "1")
            self.assertNotIn("OPENCODE_ENABLE_EXA", disabled)
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_codex_isolation_restricts_tool_environment(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            runtime_root = root / "runtime"
            flags = self.helper["codex_config_isolation_flags"](
                repo,
                runtime_root,
            )

        for required in (
            f"sqlite_home={json.dumps(str((runtime_root / 'state').resolve()))}",
            f"log_dir={json.dumps(str((runtime_root / 'log').resolve()))}",
            "features.shell_snapshot=false",
            "features.hooks=false",
            "features.plugins=false",
            "skills.include_instructions=false",
            "skills.config=[]",
            'shell_environment_policy.inherit="core"',
            "shell_environment_policy.ignore_default_excludes=false",
            "shell_environment_policy.experimental_use_profile=false",
            "allow_login_shell=false",
            'default_permissions="autoreview"',
            'permissions.autoreview.filesystem={":minimal"="read",":workspace_roots"="read"}',
        ):
            self.assertIn(required, flags)
        set_flag = next(
            flag for flag in flags if flag.startswith("shell_environment_policy.set=")
        )
        for key, value in self.helper["codex_tool_git_env"]().items():
            self.assertIn(f"{key}={json.dumps(value)}", set_flag)

    def test_safe_engine_env_excludes_repo_local_path_entries(self) -> None:
        old_path = os.environ.get("PATH", "")
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            os.environ["PATH"] = f"{repo}{os.pathsep}{old_path}"
            try:
                env = self.helper["safe_engine_env"](repo, engine="codex")
            finally:
                os.environ["PATH"] = old_path

            self.assertNotIn(str(repo.resolve()), env["PATH"].split(os.pathsep))

    def test_find_command_rejects_explicit_repo_local_executables(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            (repo / "tools").mkdir()
            (root / "trusted").mkdir()
            repo_bin = self.helper["write_executable"](
                repo / "tools" / "codex",
                "#!/bin/sh\nexit 0\n",
            )
            external_bin = self.helper["write_executable"](
                root / "trusted" / "codex",
                "#!/bin/sh\nexit 0\n",
            )

            self.assertIsNone(
                self.helper["find_command"]("tools/codex", repo),
            )
            self.assertIsNone(
                self.helper["find_command"](str(repo_bin), repo),
            )
            self.assertEqual(
                self.helper["find_command"](str(external_bin), repo),
                str(Path(os.path.abspath(external_bin))),
            )
            self.assertEqual(
                self.helper["find_command"]("../trusted/codex", repo),
                str(Path(os.path.abspath(external_bin))),
            )

            external_link = root / "trusted" / "external-codex"
            repo_link = repo / "tools" / "external-codex"
            try:
                external_link.symlink_to(repo_bin)
                repo_link.symlink_to(external_bin)
            except OSError as exc:
                if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
                    return
                raise
            self.assertIsNone(
                self.helper["find_command"](str(external_link), repo),
            )
            self.assertIsNone(
                self.helper["find_command"](str(repo_link), repo),
            )

    def test_validate_report_normalizes_relative_finding_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            report = {
                "findings": [
                    {
                        "title": "Finding",
                        "body": "Body",
                        "priority": "P1",
                        "confidence": 0.9,
                        "category": "bug",
                        "code_location": {"file_path": r".\src\index.ts", "line": 1},
                    }
                ],
                "overall_correctness": "patch is incorrect",
                "overall_explanation": "Explanation",
                "overall_confidence": 0.9,
            }

            self.helper["validate_report"](report, repo, {"src/index.ts"}, [])

            self.assertEqual(report["findings"][0]["code_location"]["file_path"], "src/index.ts")

            report["findings"][0]["code_location"]["file_path"] = r"src\index.ts"
            self.helper["validate_report"](report, repo, {r"src\index.ts"}, [])
            self.assertEqual(
                report["findings"][0]["code_location"]["file_path"],
                r"src\index.ts",
            )

            report["findings"][0]["code_location"]["file_path"] = " "
            with self.assertRaisesRegex(SystemExit, "invalid location"):
                self.helper["validate_report"](report, repo, {"src/index.ts"}, [])

            for invalid_path in (123, None, True):
                with self.subTest(invalid_path=invalid_path):
                    report["findings"][0]["code_location"] = {
                        "file_path": invalid_path,
                        "line": 1,
                    }
                    with self.assertRaisesRegex(SystemExit, "invalid location"):
                        self.helper["validate_report"](
                            report,
                            repo,
                            {"src/index.ts"},
                            [],
                        )

            report["findings"][0]["code_location"] = {
                "file_path": "src/index.ts",
                "line": True,
            }
            with self.assertRaisesRegex(SystemExit, "invalid location"):
                self.helper["validate_report"](report, repo, {"src/index.ts"}, [])

            report["findings"][0]["code_location"] = {
                "file_path": "src/index.ts",
                "line": 1,
                "extra": "ignored",
            }
            with self.assertRaisesRegex(
                SystemExit,
                "invalid code_location keys",
            ):
                self.helper["validate_report"](report, repo, {"src/index.ts"}, [])

    def test_print_report_escapes_terminal_controls(self) -> None:
        report = {
            "findings": [
                {
                    "title": "clear\x1b[2Jscreen",
                    "body": "first line\nsecond\u202eline café\udc9b",
                    "priority": "P1",
                    "confidence": 0.9,
                    "category": "security",
                    "code_location": {
                        "file_path": "src/\x9b2Jfile.py",
                        "line": 1,
                    },
                }
            ],
            "overall_correctness": "patch is incorrect",
            "overall_explanation": "explanation\x07",
            "overall_confidence": 0.9,
        }
        output = io.StringIO()

        with contextlib.redirect_stdout(output):
            self.helper["print_report"](report, label="review\x00label")

        rendered = output.getvalue()
        for control in (
            "\x00",
            "\x07",
            "\x1b",
            "\x9b",
            "\u202e",
            "\udc9b",
        ):
            self.assertNotIn(control, rendered)
        for escaped in (
            r"review\x00label",
            r"clear\x1b[2Jscreen",
            r"src/\x9b2Jfile.py",
            r"second\u202eline café\udc9b",
            r"explanation\x07",
        ):
            self.assertIn(escaped, rendered)
        self.assertIn("first line\nsecond", rendered)

    def test_validate_report_escapes_controls_in_errors(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            report = {
                "findings": [
                    {
                        "title": "Finding",
                        "body": "Body",
                        "priority": "P1\x1b]52;c;VEVTVA==\x07",
                        "confidence": 0.9,
                        "category": "security",
                        "code_location": {
                            "file_path": "src/index.py",
                            "line": 1,
                        },
                    }
                ],
                "overall_correctness": "patch is incorrect",
                "overall_explanation": "Explanation",
                "overall_confidence": 0.9,
            }

            with self.assertRaises(SystemExit) as raised:
                self.helper["validate_report"](
                    report,
                    repo,
                    {"src/index.py"},
                    [],
                )

        message = str(raised.exception)
        self.assertNotIn("\x1b", message)
        self.assertNotIn("\x07", message)
        self.assertIn(r"P1\x1b]52;c;VEVTVA==\x07", message)

    def test_safe_engine_env_ignores_inaccessible_path_entries(self) -> None:
        old_path = os.environ.get("PATH", "")
        with tempfile.TemporaryDirectory() as tempdir:
            root = Path(tempdir)
            repo = init_repo(root)
            blocked = root / "blocked"
            os.environ["PATH"] = f"{blocked}{os.pathsep}{old_path}"
            original_exists = Path.exists

            def fake_exists(path: Path) -> bool:
                if str(path) == str(blocked):
                    raise PermissionError("access denied")
                return original_exists(path)

            try:
                with mock.patch.object(Path, "exists", fake_exists):
                    env = self.helper["safe_engine_env"](repo, engine="codex")
            finally:
                os.environ["PATH"] = old_path

            self.assertNotIn(str(blocked), env["PATH"].split(os.pathsep))

    def test_run_with_heartbeat_replaces_undecodable_engine_output(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            result = self.helper["run_with_heartbeat"](
                [
                    sys.executable,
                    "-c",
                    "import sys; sys.stdout.buffer.write(b'\\x90\\n')",
                ],
                Path(tempdir),
                label="decode-test",
                heartbeat_seconds=1,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("\ufffd", result.stdout)

    def test_large_repo_relative_evidence_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            evidence = repo / "evidence.txt"
            evidence.write_text("x" * 600_000, encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "file too large to scan safely"):
                self.helper["validate_evidence_file"](
                    repo,
                    "evidence.txt",
                    "--dataset",
                )

    def test_copilot_fails_closed_without_repo_only_read_sandbox(self) -> None:
        args = argparse.Namespace(
            copilot_bin="copilot",
            thinking=None,
            tools=True,
            model=None,
            web_search=False,
            stream_engine_output=False,
        )

        with tempfile.TemporaryDirectory() as tempdir:
            repo = init_repo(Path(tempdir))
            with self.assertRaisesRegex(
                SystemExit,
                r"ignored repository secrets; use codex, claude, or pi",
            ) as error:
                self.helper["run_copilot"](
                    args,
                    repo,
                    "Repository root: .\n\nprompt",
                )
            self.assertNotIn("opencode", str(error.exception))

    def test_claude_inventory_is_bundle_and_web_only(self) -> None:
        args = argparse.Namespace(
            claude_allowed_tools="WebFetch(domain:docs.example.com),WebSearch",
            web_search=True,
        )

        self.assertEqual(
            self.helper["claude_allowed_tools"](args),
            "WebFetch(domain:docs.example.com),WebSearch",
        )
        self.assertEqual(
            self.helper["claude_tool_inventory"](args),
            "WebFetch,WebSearch",
        )

        args.web_search = False
        self.assertEqual(
            self.helper["claude_allowed_tools"](args),
            "",
        )

        args.claude_allowed_tools = "Read"
        with self.assertRaisesRegex(SystemExit, "not read-only"):
            self.helper["claude_tool_inventory"](args)

        args.web_search = True
        args.claude_allowed_tools = "WebFetch"
        with self.assertRaisesRegex(SystemExit, "one explicit domain"):
            self.helper["claude_tool_inventory"](args)

    def test_uri_reference_suppression_stays_within_credential_span(
        self,
    ) -> None:
        for content in (
            "DATABASE_URL=https://" + "$TOKEN:@host",
            "DATABASE_URL=https://" + "${TOKEN}:@host",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))
                self.assertFalse(
                    self.helper["secret_text_risk"](content + "/path")
                )
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        content
                        + "/pass"
                        + "word=real-hardcoded-"
                        + "secret"
                    )
                )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "TO"
                + "KEN=https:"
                + "//$USER:@host/actual-hardcoded-"
                + "secret-123456"
            )
        )

    def test_secret_detector_keeps_chained_assignment_fallbacks(self) -> None:
        for content in (
            "pass"
            + 'word = first, second = load_pair() or ("real-hardcoded-'
            + 'secret", "x")',
            "pass"
            + 'word = first, second = ("ordinary-hardcoded-value-12345", "x")',
            "db_pass"
            + 'word = source, second = load_pair() or ("real-hardcoded-'
            + 'secret", "x")',
            "pass"
            + 'word = first, second = load(), "ordinary-hardcoded-'
            + 'value-12345"',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_stops_at_sibling_argument_fallbacks(self) -> None:
        for content in (
            "login(pass"
            + 'word=getpass.getpass(), second=load_pair() or ('
            + '"ordinary-default-value", "x"))',
            '{"pass'
            + 'word": getpass.getpass(), "second": load_pair() or ('
            + '"ordinary-default-value", "x")}',
            "config = {\npass"
            + "word: first,\n"
            + 'second: load_pair() or ("ordinary-default-value", "x")\n}',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_handles_many_sibling_assignments(self) -> None:
        content = (
            "pass"
            + "word = source, "
            + ", ".join(f"a{index}=source" for index in range(1500))
        )

        self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_precomputes_many_assignment_positions(
        self,
    ) -> None:
        content = "\n".join(
            "to" + "ken = process.env.TOKEN"
            for _index in range(2000)
        )
        scanner = mock.Mock(
            wraps=self.helper["top_level_line_assignment_positions"]
        )
        detector = self.helper["secret_text_risk"]

        with mock.patch.dict(
            detector.__globals__,
            {"top_level_line_assignment_positions": scanner},
        ):
            self.assertFalse(detector(content))

        scanner.assert_called_once()

    def test_secret_detector_bounds_separated_key_matching(self) -> None:
        content = "a_" * 20_000 + 'ordinary = "value"'
        started = time.monotonic()

        self.assertFalse(self.helper["secret_text_risk"](content))

        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_evidence_masker_is_linear_on_long_lines(self) -> None:
        content = "x" * 100_000
        started = time.monotonic()

        self.assertEqual(
            self.helper["mask_csharp_evidence_prefix"](content),
            content,
        )

        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_evidence_masker_bounds_quote_run_scanning(self) -> None:
        content = " ".join(
            '"' * width + "x"
            for width in range(1_000, 500, -1)
        )
        started = time.monotonic()

        self.helper["mask_csharp_evidence_prefix"](content)

        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_interpolation_source_scan_bounds_unterminated_quote_run(
        self,
    ) -> None:
        content = '"' * 100_000
        started = time.monotonic()

        self.helper["interpolation_source_ranges"](
            content,
            javascript_dialect="csharp",
        )

        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_string_context_scan_bounds_unterminated_quote_run(
        self,
    ) -> None:
        quote_run = '"' * 100_000
        content = quote_run + "ProdSecret123"
        position = len(quote_run)
        started = time.monotonic()

        contexts = self.helper["string_contexts_at"](
            content,
            {position},
            javascript_dialect="csharp",
        )

        self.assertIsNone(contexts[position])
        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_string_context_scan_bounds_many_raw_literals(self) -> None:
        parts: list[str] = []
        positions: set[int] = set()
        cursor = 0
        for index in range(4_000):
            if parts:
                parts.append(";")
                cursor += 1
            literal = f'"""Value{index:08d}"""'
            positions.add(cursor + 3)
            parts.append(literal)
            cursor += len(literal)
        content = "".join(parts)
        started = time.monotonic()

        contexts = self.helper["string_contexts_at"](
            content,
            positions,
            javascript_dialect="csharp",
        )

        self.assertTrue(all(contexts[position] is not None for position in positions))
        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_raw_scan_bounds_near_delimiter_quote_run(self) -> None:
        width = 20_000
        text = '"' * width + "x" + '"' * (width - 1) + "x" + '"' * width
        started = time.monotonic()

        literal = self.helper["csharp_raw_literal_span"](
            text,
            0,
            len(text),
        )

        self.assertIsNotNone(literal)
        self.assertLess(time.monotonic() - started, 5.0)

    def test_c_family_raw_scan_rejects_many_unterminated_openers_once(self) -> None:
        content = 'R"x(' * 25_000
        started = time.monotonic()

        with self.assertRaisesRegex(
            SystemExit,
            "unterminated C-family raw string",
        ):
            self.helper["quoted_literal_value_spans"](
                content,
                0,
                len(content),
                javascript_dialect="c-family",
            )

        self.assertLess(time.monotonic() - started, 5.0)

    def test_csharp_comment_fragment_scan_bounds_unterminated_quote_run(
        self,
    ) -> None:
        content = '"' * 100_000
        started = time.monotonic()

        self.helper["comment_fragment_line_spans"](
            content,
            None,
            javascript_dialect="csharp",
        )

        self.assertLess(time.monotonic() - started, 5.0)

    def test_comment_fragment_scan_skips_text_without_fragment(self) -> None:
        scanner = mock.Mock()
        helper = self.helper["comment_fragment_line_spans"]
        with mock.patch.dict(
            helper.__globals__,
            {"quoted_literal_value_spans": scanner},
        ):
            spans = helper(
                '"""${ambiguous}"""',
                re.compile("missing-fragment"),
                javascript_dialect=None,
            )

        self.assertEqual(spans, {})
        scanner.assert_not_called()

    def test_private_key_body_scan_reuses_reference_mask(self) -> None:
        content = "\n".join(
            f"Chunk{index:04d}AbcDef1234"
            for index in range(100)
        )
        masker = mock.Mock(
            wraps=self.helper["mask_reference_declaration_evidence"]
        )
        scanner = self.helper["explicit_private_key_body_spans"]

        with mock.patch.dict(
            scanner.__globals__,
            {"mask_reference_declaration_evidence": masker},
        ):
            scanner(content, in_pem=True)

        masker.assert_called_once_with(content)

    def test_csharp_context_scan_is_bounded_across_many_uris(self) -> None:
        content = "\n".join(
            f'void Run{index}() {{ dsn=$@"https://user:'
            f'{{password}}@host/{index}"; }}'
            for index in range(512)
        )
        started = time.monotonic()

        self.assertFalse(self.helper["secret_text_risk"](content))

        self.assertLess(time.monotonic() - started, 5.0)

    def test_secret_detector_allows_structured_plus_username(self) -> None:
        for content in (
            "https://FirstName.LastName+123@host/repo",
            "https://FirstName.LastName-123@host/repo",
            "https://alice+MarketingTeam2026@example.com",
            "https://user123+MarketingTeam2026@example.com",
            "https://First.Name+campaign-2026@example.com",
            "https://first_name+campaign.2026@example.com",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))
        for content in (
            "https://AbCdEfGh.IjKlMnOp"
            + "+QrStUvWxYz012345@api.example/repo",
            "https://Ab3dE5f"
            + "+Gh7Jk9Lm2Np4Qr6St8Uv0Wx2@host/repo",
            "https://service+Abcdefghijklmnop"
            + "123456@host/repo",
            "https://CorrectHorse"
            + "+BatteryStaple2026@host/repo",
            "https://FirstnameLastname"
            + "+MarketingCampaign2026@example.com",
            "https://user:correcthorse"
            + "+BatteryStaple2026@host/repo",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))

    def test_secret_detector_scans_many_ordinary_uris_in_linear_time(
        self,
    ) -> None:
        uri_expression = (
            '"x:'
            + '//u:%s@h" % p'
        )
        content = "\n".join(
            f"x{index} = {uri_expression}"
            for index in range(4000)
        )
        started = time.monotonic()

        self.assertFalse(self.helper["secret_text_risk"](content))

        self.assertLess(time.monotonic() - started, 8.0)

    def test_csharp_uri_interpolation_requires_csharp_declaration(
        self,
    ) -> None:
        for content in (
            "url=$@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host"',
            "url=@$"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host"',
            "endpoint=$@"
            + '"https:'
            + '//user:{hunter2secret}@host";',
            "dsn=$@"
            + '"postgres:'
            + '//svc:{password}@db.example/app";',
            "url=$@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@example.com";',
            "(echo $@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host")',
            "if $@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host"; then :; fi',
            "test value == $@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            "echo using $@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            "export url=$@"
            + '"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            "// namespace N { class C { void M() {\n"
            + 'connectionString=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            "/* namespace N { class C { void M() { */\n"
            + 'connectionString=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            'function Run() { dsn=$@"https:'
            + '//user:{prodPasswordSecret12345}@host"; }',
            "cat <<'EOF'\n; class C {\nEOF\n"
            + 'url=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            "cat <<EOF\n; class C {\nEOF\n"
            + 'url=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            'void Run() { // dsn=$@"label ""prod"" https:'
            + '//u:{prodPasswordSecret12345}@h"',
            '$"{Get("{ void Run() {")}"'
            + '\ndsn=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            '""""""void Run() { }"""""";\n'
            + 'connectionString=$@"https:'
            + '//user:{prodPasswordSecret12345}@host";',
            'var path = $@"C:\\'
            + '"; // https:'
            + '//user:{prodPasswordSecret12345}@host',
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))
        for content in (
            '// header\nnamespace N { class C { void M() { '
            + 'connectionString = $@"https:'
            + '//user:{password}@host"; } } }',
            '/* header */\nnamespace N { class C { void M() { '
            + 'connectionString = $@"https:'
            + '//user:{password}@host"; } } }',
            '#nullable enable\nnamespace N { class C { void M() { '
            + 'connectionString = $@"https:'
            + '//user:{password}@host"; } } }',
            '[assembly: System.CLSCompliant(true)]\n'
            + 'namespace N { class C { void M() { '
            + 'connectionString = $@"https:'
            + '//user:{password}@host"; } } }',
            '[assembly: AssemblyMetadata("Path", @"C:\\")]\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var dsn = $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'var dsn = @$"postgres:'
            + '//svc:{password}@db.example/app";',
            'var dsn = $@"postgres:'
            + '//svc:{password}@db.example/app?x=""quoted""";',
            'const string dsn = $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'FormattableString? dsn =\n$@"postgres:'
            + '//svc:{password}@db.example/app";',
            'new Config { Dsn = $@"postgres:'
            + '//svc:{password}@db.example/app" }',
            'return $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'Connect($@"postgres:'
            + '//svc:{password}@db.example/app");',
            'connect($@"postgres:'
            + '//svc:{password}@db.example/app");',
            'Connect(dsn: $@"postgres:'
            + '//svc:{password}@db.example/app");',
            'Connect(enabled ? $@"postgres:'
            + '//svc:{password}@db.example/app" : fallback);',
            'Connect(enabled ? fallback : $@"postgres:'
            + '//svc:{password}@db.example/app");',
            'Connect(enabled\n ? fallback\n : $@"postgres:'
            + '//svc:{password}@db.example/app");',
            'Connect(value ?? $@"postgres:'
            + '//svc:{password}@db.example/app");',
            'Connect(prefix + $@"postgres:'
            + '//svc:{password}@db.example/app");',
            'string Dsn => $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'var dsn = enabled ? $@"postgres:'
            + '//svc:{password}@db.example/app" : fallback;',
            'var dsn = prefix + $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'var values = new[] { enabled ? $@"postgres:'
            + '//svc:{password}@db.example/app" : fallback };',
            'var values = new[] { enabled ? fallback : $@"postgres:'
            + '//svc:{password}@db.example/app" };',
            'var values = new[] { value ?? $@"postgres:'
            + '//svc:{password}@db.example/app" };',
            'var values = new[] { prefix + $@"postgres:'
            + '//svc:{password}@db.example/app" + suffix };',
            'var values = new[] { $@"postgres:'
            + '//svc:{password}@db.example/app" };',
            'var values = new[] { $@"postgres:'
            + '//svc:{password}@db.example/app"[0] };',
            'var values = new[] { $@"postgres:'
            + '//svc:{password}@db.example/app".ToString() };',
            'var values = [$@"postgres:'
            + '//svc:{password}@db.example/app"];',
            'var text = $@"postgres:'
            + '//svc:{password}@db.example/app".ToString();',
            'var first = $@"postgres:'
            + '//svc:{password}@db.example/app"[0];',
            'var required = $@"postgres:'
            + '//svc:{password}@db.example/app"!;',
            'using System; if ($@"postgres:'
            + '//svc:{password}@db.example/app" == expected) {}',
            'using System; if (dsn == $@"postgres:'
            + '//svc:{password}@db.example/app") {}',
            'Log(); dsn = $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'Log(); dsn += $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'Log(); connect($@"postgres:'
            + '//svc:{password}@db.example/app");',
            'int retries = 3; dsn = $@"postgres:'
            + '//svc:{password}@db.example/app";',
            'void Run() { dsn = $@"https:'
            + '//user:{prodPasswordSecret12345}@host"; }',
            'var ready = true; void Run() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'class C { void Run() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'Task<string> LoadAsync() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'Task<(string User, string Password)> Load() { dsn=$@"postgres:'
            + '//svc:{dbPassword}@db.example/app"; }',
            'global::System.String Load() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'void Run() { if (ready) { Init(); } dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'string? Load() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'byte[] Read() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'customtype Load() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            '(int Code, string Message) Load() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            '(int Code, string Message)? Load() { dsn=$@"postgres:'
            + '//svc:{dbPassword}@db.example/app"; }',
            'unsafe byte* Load() { dsn=$@"postgres:'
            + '//svc:{dbPassword}@db.example/app"; }',
            'ref string Load() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'T Load<T>() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            '[Conditional("DEBUG")] void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'void Run() { dsn=$@"label ""prod"" https:'
            + '//svc:{password}@db.example/app"; }',
            'void Run() { dsn=$@"{Get("x")}https:'
            + '//svc:{prodPasswordSecret12345}@db.example/app"; }',
            'class C { void Run() { /*'
            + "x" * 9_000
            + '*/ dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'var banner = @"""";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var banner = @$"""";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var banner = """alpha " beta""";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var banner = """text"""";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var example = "cat <<\'EOF\'";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            "// example: cat <<'EOF'\n"
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'var banner = """"alpha """ beta"""";\n'
            + 'void Run() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'if (enabled) { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'record Worker { void Run() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'sealed class Worker { Worker() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'abstract class Worker { Worker() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            '[Serializable] public sealed class Worker<T, U> { '
            + 'Worker() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'record class Worker { Worker() { dsn=$@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'struct Worker { void Run() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'interface Worker { void Run() { dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
            'class C { public string Dsn { get; set; } = $@"postgres:'
            + '//svc:{password}@db.example/app"; }',
            'class C { void Run() { if (ready) { Log(); } dsn = $@"postgres:'
            + '//svc:{password}@db.example/app"; } }',
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_csharp_spaced_assignment_requires_plain_reference(self) -> None:
        secret_shaped_reference = "".join(
            ("prodPassword", "Secret", "12345")
        )
        formatted_reference = "".join(("ActualToken", "1234567890"))
        self.assertFalse(
            self.helper["secret_text_risk"](
                'url = $@"https:'
                + '//user:{password}@example.com";'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                f'url = $@"https://user:'
                f'{{{secret_shaped_reference}}}@example.com";'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                f'url = $@"https:'
                f'//user:{{{formatted_reference}:N}}@host/{{password}}";'
            )
        )

    def test_review_patch_scans_multiline_diff_metadata(self) -> None:
        patch = (
            "Subject: example\n"
            "    Author"
            + "ization: Basic\n"
            "    dXNlcjpwYXNzd29yZA==\n"
            "diff --git a/safe.txt b/safe.txt\n"
            "--- a/safe.txt\n"
            "+++ b/safe.txt\n"
            "@@ -1 +1 @@\n"
            "-old\n"
            "+new\n"
        )

        with self.assertRaisesRegex(SystemExit, "secret-like content"):
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["safe.txt"],
                patch,
            )

    def test_secret_detector_handles_additional_credential_keys(self) -> None:
        for content in (
            "cred" + "ential = real-hardcoded-" + "secret",
            "cred" + "entials = real-hardcoded-" + "secret",
            "private_" + "key = real-hardcoded-" + "secret",
            "github_to" + "ken = ordinary-hardcoded-value-12345",
            "db_pass" + "word = ordinary-hardcoded-value-12345",
            "stripe_api_" + "key = ordinary-hardcoded-value-12345",
            "githubTo" + "ken = ordinary-hardcoded-value-12345",
            "dbPass" + "word = ordinary-hardcoded-value-12345",
            "awsCred" + "entials = ordinary-hardcoded-value-12345",
            "githubAPI" + "Key = ordinary-hardcoded-value-12345",
            "myAWSSecretAccess"
            + "Key = ordinary-hardcoded-value-12345",
            "userIDTo" + "ken = ordinary-hardcoded-value-12345",
            "GITHUBTO" + "KEN = ordinary-hardcoded-value-12345",
            "DBPASS" + "WORD = ordinary-hardcoded-value-12345",
            "githubto" + "ken = ordinary-hardcoded-value-12345",
            "dbpass" + 'word = "Summer2026!"',
            "stripeapi" + "key = ordinary-hardcoded-value-12345",
            "x" * 65
            + "_pass"
            + "word = ordinary-hardcoded-value-12345",
            "pass" + "word: CorrectHorseBatteryStaple",
            "PASS" + "WORD=CorrectHorseBatteryConfig",
            "pass" + "word: CorrectHorseBatteryOptions",
            "cred" + "entials: CorrectHorseBatteryCredentials",
            "# class Fake {\ncred"
            + "entials: CorrectHorseBatteryCredentials",
            "# class Fake {\npass"
            + "word: CorrectHorseBatteryCredentials",
            "# const opts = { pass"
            + "word: actualToken1234567890",
            "echo ok # const opts = { pass"
            + "word: actualToken1234567890",
            "const opts = { cred"
            + "entials: CorrectHorseBatteryStaple };",
        ):
            with self.subTest(content=content):
                self.assertTrue(self.helper["secret_text_risk"](content))
        for content in (
            "cred" + "ential = process.env.CREDENTIAL",
            "cred" + "entials = config.credentials",
            "safe_" + "credentials = config.credentials",
            "safeCred" + "entials = config.credentials",
            "credentializer = ordinary-hardcoded-value-12345",
            "private_" + 'key = os.environ["PRIVATE_KEY"]',
            "type AuthOptions = { cred"
            + "entials: RequestCredentials };",
            'const banner = "'
            + "x" * 3_000
            + '"; type AuthOptions = { cred'
            + "entials: RequestCredentials };",
            "const cred" + "entials = options.credentials",
            "const opts = { cred"
            + "entials: requestCredentials };",
            "const quote = /'/;\nconst opts = { cred"
            + "entials: requestCredentials };",
            "const quote = /'/; const opts = { cred"
            + "entials: requestCredentials };",
            "const quote = `it's`; const opts = { cred"
            + "entials: requestCredentials };",
            "const quote = `${`it's`}`; const opts = { cred"
            + "entials: requestCredentials };",
            'const note = "unmatched `";\nconst opts = { cred'
            + "entials: requestCredentials };",
            "// unmatched `\nconst opts = { cred"
            + "entials: requestCredentials };",
            "/* unmatched ` */ const opts = { cred"
            + "entials: requestCredentials };",
            "safe_uri_cred"
            + "entials = interpolated_empty_password_uri_ranges(\n"
            + "    text,\n"
            + "    uri_authorities,\n"
            + ")",
        ):
            with self.subTest(content=content):
                self.assertFalse(self.helper["secret_text_risk"](content))

    def test_secret_detector_allows_fetch_credential_modes(self) -> None:
        for mode in ("include", "omit", "same-origin"):
            with self.subTest(mode=mode):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        "fetch(url, { cred"
                        + f'entials: "{mode}" }})'
                    )
                )

    def test_secret_detector_allows_punctuationless_password_prompt(
        self,
    ) -> None:
        for prompt in (
            "Enter password",
            "Enter the password for the database: ",
            "Enter password for GitHub: ",
            "Enter password for AWS2024",
            "Enter password for MicrosoftDynamics365",
            "Enter password for MicrosoftDynamics2024",
            "Enter password for Oracle2024",
            "Enter password for PostgreSQL: ",
            "Enter password for SpringBoot2024",
            "Enter password for Windows2024",
            "Enter your password:",
            "Password:",
        ):
            with self.subTest(prompt=prompt):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        "pass"
                        + f'word = getpass.getpass("{prompt}")'
                    )
                )
        self.assertFalse(
            self.helper["secret_text_risk"](
                'banner = """"quoted"""\n'
                + 'password = getpass.getpass("Enter password")'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "pass"
                + 'word = getpass.getpass("Enter password for ghp_'
                + 'ActualToken1234567890")'
            )
        )
        for prompt in (
            "Enter password for SummerVacation2026",
            "Password for Abcdefghijklmno12345",
        ):
            with self.subTest(prompt=prompt):
                self.assertTrue(
                    self.helper["secret_text_risk"](
                        "pass"
                        + f'word = getpass.getpass("{prompt}")'
                    )
                )

    def test_secret_detector_allows_chained_lookup_references(self) -> None:
        lookup = (
            "to"
            + 'ken = response.json().get("access_'
            + 'token")'
        )

        self.assertFalse(self.helper["secret_text_risk"](lookup))
        self.assertFalse(
            self.helper["secret_text_risk"](
                "to"
                + 'ken = client().headers.get("Authorization")'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                lookup + ' or "ordinary-hardcoded-value-12345"'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "to"
                + 'ken = client.auth().get("ghp_'
                + 'ActualToken1234567890")'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "to"
                + 'ken = response.get("ghp_'
                + 'ActualToken1234567890")'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "pass"
                + 'word = response.get("CorrectHorse'
                + 'BatteryStaple")'
            )
        )
        self.assertTrue(
            self.helper["secret_text_risk"](
                "pass"
                + 'word = response.get("CORRECTHORSE'
                + 'BATTERYSTAPLE")'
            )
        )

    def test_secret_detector_normalizes_c_family_member_operators(self) -> None:
        for content in (
            'password = headers->get("Authorization")',
            'password = headers::get("Authorization")',
            'password = ui->prompt("Enter password for Service2")',
        ):
            with self.subTest(content=content):
                self.assertFalse(
                    self.helper["secret_text_risk"](
                        content,
                        javascript_dialect="c-family",
                    )
                )

    def test_secret_detector_allows_csharp_alias_qualified_reference(self) -> None:
        self.assertFalse(
            self.helper["secret_text_risk"](
                "password = global::Credentials.Value;",
                javascript_dialect="csharp",
            )
        )

    def test_secret_detector_bounds_chained_receiver_tracking(self) -> None:
        content = "to" + "ken = f()" + ".x()" * 20_000
        started = time.monotonic()

        self.assertFalse(self.helper["secret_text_risk"](content))

        self.assertLess(time.monotonic() - started, 5.0)

    def test_review_patch_allows_safe_multiline_call_hunks(self) -> None:
        patch = (
            "diff --git a/safe.py b/safe.py\n"
            "--- a/safe.py\n"
            "+++ b/safe.py\n"
            "@@ -0,0 +1,3 @@\n"
            "+"
            + "pass"
            + "word = getpass.getpass(\n"
            '+    "Password: ",\n'
            "+)\n"
        )

        self.assertEqual(
            self.helper["validate_review_patch"](
                "local unstaged diff",
                ["safe.py"],
                patch,
            ),
            patch,
        )

    def test_review_patch_rejects_size_before_secret_scanning(self) -> None:
        scanner = mock.Mock()
        validator = self.helper["validate_review_patch"]
        with mock.patch.dict(
            validator.__globals__,
            {"require_no_secret_values": scanner},
        ):
            with self.assertRaisesRegex(SystemExit, r"20 bytes; limit 10"):
                validator(
                    "local unstaged diff",
                    ["safe.txt"],
                    "x\n" * 10,
                    10,
                )

        scanner.assert_not_called()

    def test_stream_displays_escape_terminal_controls(self) -> None:
        control = chr(27) + "]52;c;VEVTVA==" + chr(7)
        codex = self.helper["CodexStreamDisplay"]()
        claude = self.helper["ClaudeStreamDisplay"]()
        codex_message = json.dumps(
            {
                "type": "item.completed",
                "item": {
                    "type": "agent_message",
                    "text": control,
                },
            }
        )

        for displayed in (
            codex("stdout", codex_message + "\n"),
            codex("stderr", control + "\n"),
            claude("stderr", control + "\n"),
        ):
            self.assertIsNotNone(displayed)
            assert displayed is not None
            self.assertNotIn(chr(27), displayed)
            self.assertNotIn(chr(7), displayed)
            self.assertIn(r"\x1b", displayed)
            self.assertIn(r"\x07", displayed)
            self.assertTrue(displayed.endswith("\n"))

    def test_run_with_stream_escapes_terminal_output_only(self) -> None:
        control = chr(27) + "]52;c;VEVTVA==" + chr(7)
        script = (
            "import sys;"
            "value=chr(27)+']52;c;VEVTVA=='+chr(7);"
            "sys.stdout.write(value+'\\n');"
            "sys.stderr.write(value+'\\n')"
        )
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            result = self.helper["run_with_stream"](
                [sys.executable, "-c", script],
                Path.cwd(),
                input_text=None,
                label="stream-test",
                heartbeat_seconds=60,
                stream_display=None,
                resolve_root=Path.cwd(),
            )

        self.assertIn(control, result.stdout)
        self.assertIn(control, result.stderr)
        for displayed in (stdout.getvalue(), stderr.getvalue()):
            self.assertNotIn(chr(27), displayed)
            self.assertNotIn(chr(7), displayed)
            self.assertIn(r"\x1b", displayed)
            self.assertIn(r"\x07", displayed)
            self.assertTrue(displayed.endswith("\n"))

    def test_self_test_shortcut_runs_deterministic_checks(self) -> None:
        command = [str(SCRIPT), "--self-test"]
        if os.name == "nt":
            command = [sys.executable, str(SCRIPT), "--self-test"]
        result = subprocess.run(
            command,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("autoreview engine isolation self-test: ok", result.stdout)


if __name__ == "__main__":
    unittest.main()
