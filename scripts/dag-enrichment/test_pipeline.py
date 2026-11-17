"""Offline regression tests for generation coverage and repository-root updates."""

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import generate_source_summaries as summaries
import run_dag_pipeline as runner
import update_dags as updates


class PipelineTests(unittest.TestCase):
    def test_resume_requires_every_document_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mapping = root / "mapping.json"
            entries = [
                {"dag_doc_new": "L2-platform/first.md"},
                {"dag_doc_new": "L3-flows/second.md"},
            ]
            mapping.write_text(json.dumps({"mappings": entries}), encoding="utf-8")
            with patch.multiple(
                runner, MAPPING_FILE=mapping, COPILOT_DOCS=root / "final",
                INTERMEDIATE_DOCS=root / "intermediate",
            ):
                self.assertFalse(runner._done_step4())
                for entry in entries:
                    relative = entry["dag_doc_new"]
                    for folder, name in (
                        ("final", relative),
                        ("intermediate", relative.replace(".md", ".content.md")),
                    ):
                        path = root / folder / name
                        path.parent.mkdir(parents=True, exist_ok=True)
                        path.write_text("document", encoding="utf-8")
                    if relative.endswith("first.md"):
                        self.assertFalse(runner._done_step4())
                self.assertTrue(runner._done_step4())

    def test_resume_requires_all_layer_indexes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(runner, "COPILOT_DOCS", root):
                for relative in (
                    "docs-index.md", "L0-foundations/codebase-primer.md",
                    "L1-conceptual/docs-index.md", "L2-platform/docs-index.md",
                ):
                    path = root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text("index", encoding="utf-8")
                self.assertFalse(runner._done_step5())
                path = root / "L3-flows/docs-index.md"
                path.parent.mkdir()
                path.write_text("index", encoding="utf-8")
                self.assertTrue(runner._done_step5())

    def test_source_enumeration_covers_all_supported_languages(self):
        paths = ["agent/src/lib.rs", "tests/Main.cs", "ebpf/a.c", "native/a.cpp", "inc/a.h"]
        result = subprocess.CompletedProcess([], 0, "\0".join(paths + ["README.md"]).encode())
        with patch.object(summaries.subprocess, "run", return_value=result):
            self.assertEqual(summaries.source_files(), sorted(paths))

    def test_source_hash_invalidates_stale_summary(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "lib.rs").write_text("fn first() {}", encoding="utf-8")
            with patch.multiple(summaries, REPO_ROOT=root, SUMMARY_ROOT=root / "summaries"):
                output = summaries.summary_path("lib.rs")
                output.parent.mkdir()
                output.write_text(
                    f"- Source SHA256: `{summaries.source_hash('lib.rs')}`\n"
                    "## Content\nsource explanation\n## Symbols\nfirst\n",
                    encoding="utf-8",
                )
                self.assertTrue(summaries.is_current("lib.rs"))
                (root / "lib.rs").write_text("fn changed() {}", encoding="utf-8")
                self.assertFalse(summaries.is_current("lib.rs"))

    def test_empty_prefix_preserves_repository_relative_keys(self):
        paths = ["proxy_agent/src/lib.rs", "native/types.h", "tests/Main.cs"]
        result = subprocess.CompletedProcess(
            [], 0, "\n".join(f"M\t{path}" for path in paths), "",
        )
        with patch.object(updates.subprocess, "run", return_value=result) as run:
            diffs = updates.get_changed_files("old", "new", "")
        self.assertEqual([diff.compose_key for diff in diffs], [p + ".md" for p in paths])
        self.assertEqual(run.call_args_list[0].args[0][-1], "--")
        self.assertNotIn("", run.call_args_list[0].args[0])

    def test_exact_section_identity_with_repeated_basenames(self):
        content = "## agent/build.rs\nfirst\n---\n## extension/build.rs\nsecond\n---\n"
        section, _, _ = updates.extract_section(content, "extension/build.rs")
        self.assertIn("second", section)
        self.assertNotIn("first", section)
        with self.assertRaises(ValueError):
            updates.extract_section(content, "build.rs")
        with self.assertRaises(ValueError):
            updates.extract_section(content + content, "extension/build.rs")

    def test_obsolete_summary_removed_without_deleting_current(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(summaries, "SUMMARY_ROOT", root):
                current = root / "lib.rs.md"
                obsolete = root / "deleted.rs.md"
                current.write_text("current", encoding="utf-8")
                obsolete.write_text("obsolete", encoding="utf-8")
                summaries.reconcile_summaries(["lib.rs"])
                self.assertTrue(current.exists())
                self.assertFalse(obsolete.exists())

    def test_pointer_injection_always_runs_on_resume(self):
        step = next(step for step in runner.build_steps() if step.num == 8)
        self.assertFalse(step.detect())

    def test_failed_final_retains_checkpoint_and_retry_resynthesizes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            intermediate = root / "intermediate.md"
            final = root / "final.md"
            state = root / "state.json"
            intermediate.write_text("before", encoding="utf-8")
            final.write_text("before", encoding="utf-8")
            updates.save_state(state, {"last_updated_hash": "old"})
            dag = updates.AffectedDAG(
                "L2-platform/agent.md", "L2-platform",
                [updates.FileDiff("lib.rs", "lib.rs.md", "diff", "modified")],
                intermediate, final,
            )
            arguments = ["update_dags.py", "--state-file", str(state), "--mode", "patch"]

            def change_intermediate(*args):
                intermediate.write_text("after", encoding="utf-8")
                dag.intermediate_changed = True
                return True

            with (
                patch("sys.argv", arguments),
                patch.object(updates, "get_git_head", return_value="new"),
                patch.object(updates, "get_changed_files", return_value=dag.file_diffs),
                patch.object(updates, "load_mapping", return_value={}),
                patch.object(updates, "group_diffs_by_dag", return_value=({dag.dag_doc: dag}, [])),
                patch.object(updates, "update_intermediate_dag", side_effect=change_intermediate),
                patch.object(updates, "update_final_dag_patch", return_value=False),
            ):
                with self.assertRaises(RuntimeError):
                    updates.main()
            self.assertEqual(updates.load_state(state)["last_updated_hash"], "old")
            self.assertEqual(updates.load_state(state)["pending_update"], "new")
            dag.intermediate_changed = False
            with (
                patch("sys.argv", arguments),
                patch.object(updates, "LOG_DIR", root / "logs"),
                patch.object(updates, "REPO_ROOT", root),
                patch.object(updates, "DEFAULT_MAPPING", root / "mapping.json"),
                patch.object(updates, "DEFAULT_INTERMEDIATE", root / "intermediate"),
                patch.object(updates, "DEFAULT_FINAL", root / "final"),
                patch.object(updates, "DEFAULT_STATE_FILE", state),
                patch.object(updates, "get_git_head", return_value="new"),
                patch.object(updates, "get_changed_files", return_value=dag.file_diffs),
                patch.object(updates, "load_mapping", return_value={}),
                patch.object(updates, "group_diffs_by_dag", return_value=({dag.dag_doc: dag}, [])),
                patch.object(updates, "update_intermediate_dag", return_value=False),
                patch.object(updates, "update_final_dag_resync", return_value=True) as resync,
            ):
                updates.main()
                resync.assert_called_once_with(dag, False)
            self.assertEqual(updates.load_state(state)["last_updated_hash"], "new")
            self.assertNotIn("pending_update", updates.load_state(state))


if __name__ == "__main__":
    unittest.main()
