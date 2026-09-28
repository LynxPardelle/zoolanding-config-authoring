import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SourceOnlyPromotionTests(unittest.TestCase):
    def test_raw_selection_rejects_duplicates_before_last_value_can_authorize(self):
        spec=importlib.util.spec_from_file_location("source_only_duplicate",ROOT/"tools/verify_source_only_promotion.py")
        verifier=importlib.util.module_from_spec(spec);spec.loader.exec_module(verifier)
        valid={"schemaVersion":1,"mode":"thn-source-only","sourceSha":"a"*40,"sourceTree":"b"*40,"targetBaseSha":"c"*40,"mergeTree":"d"*40}
        activation={"schemaVersion":1,"mode":"thn-reviewed-activation","sha":"a"*40,"tree":"b"*40,"workflowSha256":"c"*64}
        for value in (valid,activation):
            raw=json.dumps(value);self.assertEqual(verifier.parse_selection(raw),value)
            for key in value:
                duplicate='{'+json.dumps(key)+':"wrong",'+raw[1:]
                with self.subTest(key=key),self.assertRaises(ValueError):verifier.parse_selection(duplicate)
            escaped='{"\\u0073chemaVersion":2,'+raw[1:]
            with self.assertRaises(ValueError):verifier.parse_selection(escaped)
        for bad in ("NaN",'[]','{"outer":{"x":1,"x":2}}',' '*4097):
            with self.assertRaises(ValueError):verifier.parse_selection(bad)

    def test_absent_thn_selector_preserves_only_existing_automatic_test_provenance_path(self):
        git=shutil.which("git")
        self.assertTrue(git, "Git is required for native local provenance")
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp)
            subprocess.run([git,"init","-q",str(root)],check=True,capture_output=True)
            subprocess.run([git,"-C",str(root),"-c","user.name=local-proof","-c","user.email=local-proof@example.invalid","commit","--allow-empty","-qm","local"],check=True,capture_output=True)
            sha=subprocess.run([git,"-C",str(root),"rev-parse","HEAD"],check=True,capture_output=True,text=True).stdout.strip()
            output=root/"output"
            env={**os.environ,"GITHUB_EVENT_NAME":"push","GITHUB_REF":"refs/heads/test","GITHUB_SHA":sha,
                 "GITHUB_REPOSITORY":"unit/no-network","GITHUB_OUTPUT":str(output),"PROMOTION_SELECTION_JSON":"",
                 "PATH":str(Path(git).parent)+os.pathsep+os.environ.get("SystemRoot",r"C:\Windows")+r"\System32"}
            env.pop("GH_TOKEN",None);env.pop("GITHUB_TOKEN",None)
            result=subprocess.run([sys.executable,str(ROOT/"tools/verify_source_only_promotion.py"),"--target=test"],cwd=root,env=env,capture_output=True,text=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual(output.read_text(),"source_only=false\n")
            env["GITHUB_REF"]="refs/heads/main"
            result=subprocess.run([sys.executable,str(ROOT/"tools/verify_source_only_promotion.py"),"--target=main"],cwd=root,env=env,capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)

    def test_review_digest_binds_sealed_bytes_and_native_baseline(self):
        workflow = (ROOT / ".github/workflows/deploy-test.yml").read_text()
        start_marker = "          # inline-review-digest:start\n"
        end_marker = "          # inline-review-digest:end"
        self.assertIn(start_marker, workflow)
        inline = workflow.split(start_marker)[1].split(end_marker)[0]
        script = "\n".join(line[10:] if line.startswith("          ") else line for line in inline.splitlines())
        with tempfile.TemporaryDirectory() as temp:
            paths = [Path(temp) / name for name in ("changes.json", "template.yaml", "manifest.sha256", "baseline.json")]
            paths[0].write_text(json.dumps({"Changes": [{"Type": "Resource", "ResourceChange": {
                "Action": "Modify", "LogicalResourceId": "ConfigAuthoringFunction", "ResourceType": "AWS::Lambda::Function",
                "Replacement": "False", "Scope": ["Properties"], "Details": [{"Target": {"Attribute": "Properties", "Name": "Code", "RequiresRecreation": "Never"}}]}}]}))
            paths[1].write_text("same source template")
            paths[2].write_text("same sealed package bytes")
            paths[3].write_text(json.dumps({"functionRevision": "native-reviewed-revision"}))
            def digest():
                result = subprocess.run([sys.executable, "-c", script, *(str(path) for path in paths), "a" * 40, str(paths[1])], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                return result.stdout.strip()
            approved = digest()
            self.assertRegex(approved, r"^[a-f0-9]{64}$")
            for path in paths[1:]:
                original = path.read_bytes()
                path.write_bytes(original + b" ")
                self.assertNotEqual(digest(), approved)
                path.write_bytes(original)
            changes = json.loads(paths[0].read_text())
            changes["Changes"][0]["ResourceChange"]["Scope"].append("Tags")
            paths[0].write_text(json.dumps(changes))
            self.assertNotEqual(digest(), approved)

    def test_workflow_requires_source_only_push_and_reviewed_manual_activation(self):
        for name in ("deploy-test.yml", "deploy-production.yml"):
            workflow = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
            self.assertIn("verify_source_only_promotion.py", workflow)
            self.assertIn("workflow_dispatch:", workflow)
            self.assertIn("source_only", workflow)
            self.assertIn("review_digest:", workflow)
            self.assertIn("thn-reviewed-activation", workflow)
            self.assertLess(workflow.index("thn-reviewed-activation"), workflow.index("aws-actions/configure-aws-credentials"))
            self.assertIn("review_inventory_digest", workflow)
            self.assertLess(workflow.index("review_inventory_digest"), workflow.index("aws cloudformation execute-change-set"))

    def test_exact_selector_and_reviewed_activation_are_closed(self):
        path = ROOT / "tools" / "verify_source_only_promotion.py"
        self.assertTrue(path.is_file(), "source-only promotion has no fail-closed verifier")
        spec = importlib.util.spec_from_file_location("source_only", path)
        verifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(verifier)
        selection = {"schemaVersion": 1, "mode": "thn-source-only", "sourceSha": "a" * 40,
                     "sourceTree": "b" * 40, "targetBaseSha": "c" * 40, "mergeTree": "d" * 40}
        context = {"target": "main", "eventName": "push", "ref": "refs/heads/main", "sha": "e" * 40,
                   "sourceSha": "a" * 40, "sourceTree": "b" * 40, "mergeTree": "d" * 40,
                   "nativeMergeTree": "d" * 40, "parents": ["c" * 40, "a" * 40],
                   "event": {"before": "c" * 40, "after": "e" * 40, "forced": False, "created": False, "deleted": False}}
        self.assertTrue(verifier.verify_source_only(selection, context))
        for field in selection:
            broken = copy.deepcopy(selection)
            broken[field] = "invalid"
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.verify_source_only(broken, context)
        for field in ("sourceSha", "sourceTree", "mergeTree", "nativeMergeTree", "ref", "eventName", "parents", "event"):
            broken = copy.deepcopy(context)
            broken[field] = None
            with self.subTest(field=field), self.assertRaises(ValueError):
                verifier.verify_source_only(selection, broken)
        self.assertRaises(ValueError, verifier.verify_source_only, {**selection, "extra": True}, context)
        activation = {"schemaVersion": 1, "mode": "thn-reviewed-activation", "sha": "e" * 40,
                      "tree": "d" * 40, "workflowSha256": "f" * 64}
        verifier.verify_activation(activation, "e" * 40, "d" * 40, "f" * 64)
        for field in activation:
            broken = {**activation, field: "invalid"}
            with self.subTest(activation=field), self.assertRaises(ValueError):
                verifier.verify_activation(broken, "e" * 40, "d" * 40, "f" * 64)
        self.assertRaises(ValueError, verifier.verify_activation, {**activation, "extra": True}, "e" * 40, "d" * 40, "f" * 64)


    def test_manual_test_package_accepts_sam_string_and_dict_coordinates_without_cross_bucket(self):
        from unittest.mock import patch
        workflow=(ROOT/".github/workflows/deploy-test.yml").read_text()
        start=workflow.index("          import json",workflow.index('python3 - "$packaged" "$EXPECTED_BUCKET"'))
        end=workflow.index("          PY",start)
        code="\n".join(line[10:] for line in workflow[start:end].splitlines())
        bucket="zoolanding-config-payloads-test"
        for uri in ("s3://"+bucket+"/system/deploy-artifacts/"+"a"*40+"/1/1/"+"b"*32,{"Bucket":bucket,"Key":"system/deploy-artifacts/"+"a"*40+"/1/1/"+"b"*32}):
            with tempfile.TemporaryDirectory() as temp:
                path=Path(temp)/"template.json"
                path.write_text(json.dumps({"Resources":{"ConfigAuthoringFunction":{"Properties":{"CodeUri":uri}}}}))
                with patch.object(sys,"argv",["pin",str(path),bucket]),patch.dict(os.environ,{"GITHUB_SHA":"a"*40,"GITHUB_RUN_ID":"1","GITHUB_RUN_ATTEMPT":"1"}),patch.object(subprocess,"run",return_value=type("Result",(),{"returncode":0,"stdout":json.dumps({"VersionId":"sealed"})})()):
                    exec(compile(code,"actual-inline-pin","exec"),{})
                actual=json.loads(path.read_text())["Resources"]["ConfigAuthoringFunction"]["Properties"]["CodeUri"]
                self.assertEqual(actual["Bucket"],bucket);self.assertEqual(actual["Version"],"sealed")

    def test_manual_activation_requires_current_source_and_exact_native_merge(self):
        spec=importlib.util.spec_from_file_location("source_only",ROOT/"tools/verify_source_only_promotion.py")
        op=importlib.util.module_from_spec(spec);spec.loader.exec_module(op)
        check=getattr(op,"verify_manual_merge",None)
        self.assertTrue(callable(check), "manual activation does not prove the native merged source")
        context={"parents":["a"*40,"b"*40],"sourceSha":"b"*40,"tree":"c"*40,"nativeMergeTree":"c"*40}
        check(context)
        for mutation in ({"parents":["a"*40]}, {"sourceSha":"d"*40},{"tree":"d"*40},{"nativeMergeTree":"d"*40}):
            with self.assertRaises(ValueError):check({**context,**mutation})
