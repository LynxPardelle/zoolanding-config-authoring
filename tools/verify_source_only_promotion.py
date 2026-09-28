"""Separate exact code promotion from reviewed activation before credentials."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

SHA = re.compile(r"[a-f0-9]{40}")
DIGEST = re.compile(r"[a-f0-9]{64}")


def _reject():
    raise ValueError("source_promotion_rejected")


def parse_selection(raw):
    """Reject ambiguous raw selectors before JSON can discard duplicate keys."""
    if not isinstance(raw,str) or len(raw.encode("utf-8"))>4096:_reject()
    def closed_object(pairs):
        result={}
        for key,value in pairs:
            if key in result:_reject()
            result[key]=value
        return result
    try:
        value=json.loads(raw,object_pairs_hook=closed_object,parse_constant=lambda value:_reject())
    except (TypeError,ValueError):_reject()
    if not isinstance(value,dict):_reject()
    return value


def verify_source_only(selection, c):
    keys = {"schemaVersion", "mode", "sourceSha", "sourceTree", "targetBaseSha", "mergeTree"}
    if not isinstance(selection, dict) or set(selection) != keys or type(selection["schemaVersion"]) is not int or selection["schemaVersion"] != 1 or selection["mode"] != "thn-source-only":
        _reject()
    if any(not isinstance(selection[k], str) or not SHA.fullmatch(selection[k]) for k in keys - {"schemaVersion", "mode"}):
        _reject()
    event = c.get("event")
    if (c.get("target") not in {"test", "main"} or c.get("eventName") != "push"
        or c.get("ref") != "refs/heads/" + c["target"] or not isinstance(c.get("sha"), str) or not SHA.fullmatch(c["sha"])
        or c.get("parents") != [selection["targetBaseSha"], selection["sourceSha"]]
        or c.get("sourceSha") != selection["sourceSha"] or c.get("sourceTree") != selection["sourceTree"]
        or c.get("mergeTree") != selection["mergeTree"] or c.get("nativeMergeTree") != selection["mergeTree"]
        or not isinstance(event, dict) or event.get("before") != selection["targetBaseSha"] or event.get("after") != c["sha"]
        or any(event.get(k) is not False for k in ("forced", "created", "deleted"))):
        _reject()
    return True


def verify_activation(selection, sha, tree, workflow_digest):
    if (not isinstance(selection, dict) or set(selection) != {"schemaVersion", "mode", "sha", "tree", "workflowSha256"}
        or type(selection["schemaVersion"]) is not int or selection["schemaVersion"] != 1 or selection["mode"] != "thn-reviewed-activation"
        or not SHA.fullmatch(str(sha)) or not SHA.fullmatch(str(tree)) or not DIGEST.fullmatch(str(workflow_digest))
        or selection["sha"] != sha or selection["tree"] != tree or selection["workflowSha256"] != workflow_digest):
        _reject()


def verify_manual_merge(c):
    parents=c.get("parents")
    if (not isinstance(parents,list) or len(parents)!=2 or any(not SHA.fullmatch(str(p)) for p in parents)
        or c.get("sourceSha")!=parents[1] or not SHA.fullmatch(str(c.get("tree")))
        or c.get("tree")!=c.get("nativeMergeTree")):_reject()


def _command(args):
    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode:
        _reject()
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, choices=("main", "test"))
    args = parser.parse_args()
    source = "test" if args.target == "main" else "dev"
    if os.getenv("GITHUB_REF") != "refs/heads/" + args.target:
        _reject()
    sha = os.getenv("GITHUB_SHA", "")
    if not SHA.fullmatch(sha):
        _reject()
    # Only an exact explicitly selected THN TEST promotion suppresses legacy AWS.
    # Existing generic automatic TEST provenance remains in its original workflow.
    if args.target == "test" and os.getenv("GITHUB_EVENT_NAME") == "push" and not os.getenv("PROMOTION_SELECTION_JSON"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
            stream.write("source_only=false\n")
        return
    tree = _command(["git", "rev-parse", sha + "^{tree}"])
    if os.getenv("GITHUB_EVENT_NAME") == "workflow_dispatch":
        workflow = "deploy-production.yml" if args.target == "main" else "deploy-test.yml"
        workflow_digest = hashlib.sha256(Path(".github/workflows", workflow).read_bytes().replace(b"\r\n", b"\n")).hexdigest()
        verify_activation(parse_selection(os.getenv("ACTIVATION_SELECTION_JSON", "null")), sha, tree, workflow_digest)
        repository=os.getenv("GITHUB_REPOSITORY", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+",repository):_reject()
        source_sha=json.loads(_command(["gh","api",f"repos/{repository}/git/ref/heads/{source}"]))["object"]["sha"]
        parents=_command(["git","show","-s","--format=%P",sha]).split()
        if len(parents)!=2:_reject()
        verify_manual_merge({"parents":parents,"sourceSha":source_sha,"tree":tree,
            "nativeMergeTree":_command(["git","merge-tree","--write-tree",parents[0],source_sha])})
        source_only = False
    else:
        repository = os.getenv("GITHUB_REPOSITORY", "")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            _reject()
        source_sha = json.loads(_command(["gh", "api", f"repos/{repository}/git/ref/heads/{source}"]))["object"]["sha"]
        if not SHA.fullmatch(str(source_sha)):
            _reject()
        parents = _command(["git", "show", "-s", "--format=%P", sha]).split()
        if len(parents) != 2:
            _reject()
        c = {"target": args.target, "eventName": os.getenv("GITHUB_EVENT_NAME"), "ref": os.getenv("GITHUB_REF"),
             "sha": sha, "parents": parents, "sourceSha": source_sha,
             "sourceTree": _command(["git", "rev-parse", source_sha + "^{tree}"]), "mergeTree": tree,
             "nativeMergeTree": _command(["git", "merge-tree", "--write-tree", parents[0], source_sha]),
             "event": json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))}
        verify_source_only(parse_selection(os.getenv("PROMOTION_SELECTION_JSON", "null")), c)
        source_only = True
    output = os.environ["GITHUB_OUTPUT"]
    with open(output, "a", encoding="utf-8") as stream:
        stream.write(f"source_only={str(source_only).lower()}\n")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("source_promotion_rejected") from None
