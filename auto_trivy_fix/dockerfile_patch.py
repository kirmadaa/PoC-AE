"""
Dockerfile patcher (v2):

- Detect and optionally upgrade EOL Alpine base images to a target tag (configurable).
- Separate OS package fixes from Python (pip) fixes.
- Pick highest valid version when Trivy lists multiple fixes.
- Support apt/apk/yum detection and version pinning.

Produces patched Dockerfile at <tempdir>/Dockerfile.auto_fix when changes are made.
"""
from pathlib import Path
import re
from typing import List, Dict, Tuple
from packaging.version import parse as vparse

class DockerfilePatcher:
    def __init__(self, dockerfile_path: Path, out_dir: Path, alpine_target: str = "3.20"):
        self.dockerfile_path = dockerfile_path
        self.out_dir = Path(out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.orig_text = dockerfile_path.read_text()
        self.out_path = self.out_dir / "Dockerfile.auto_fix"
        self.alpine_target = alpine_target

    @staticmethod
    def _split_fixed_versions(s: str) -> List[str]:
        # Split on commas or spaces and strip
        parts = re.split(r'[,\s]+', s.strip())
        return [p for p in parts if p]

    @staticmethod
    def _pick_highest_version(versions: List[str]) -> str:
        # Return highest by packaging.version
        if not versions:
            return ""
        try:
            return sorted(versions, key=vparse)[-1]
        except Exception:
            # Fallback: last item
            return versions[-1]

    def attempt_patch(self, vulns: List[Dict]) -> Dict:
        actions: List[Dict] = []
        text = self.orig_text

        # Detect base image FROM
        from_match = re.search(r'^(FROM\s+(\S+))', text, flags=re.MULTILINE)
        base_image = None
        base_repo = None
        base_tag = None
        if from_match:
            full = from_match.group(2)
            base_image = full
            if ":" in full:
                base_repo, base_tag = full.split(":", 1)
            else:
                base_repo = full
                base_tag = "latest"
            actions.append({"type": "info", "msg": f"Detected base image: {base_image}"})

        # Heuristic: if Alpine and tag < target, bump
        if base_repo and base_repo.startswith("alpine") and base_tag and self._alpine_needs_upgrade(base_tag):
            new_base = f"alpine:{self.alpine_target}"
            text = re.sub(r'^(FROM\s+\S+)', f"FROM {new_base}", text, count=1, flags=re.MULTILINE)
            actions.append({"type": "base-image-updated", "old": base_image, "new": new_base, "reason": "alpine_eol_or_old"})
            base_image = new_base

        # Build maps of package fixes (OS vs Python)
        os_pkg_fixes: Dict[str, str] = {}
        py_pkg_fixes: Dict[str, str] = {}
        for v in vulns:
            fixed = v.get("fixed_version") or ""
            pkg = (v.get("pkg_name") or "").strip()
            if not pkg or not fixed:
                continue
            # pick highest version if multiple listed
            chosen = self._pick_highest_version(self._split_fixed_versions(fixed))
            if not chosen:
                continue
            t = (v.get("type") or "").lower()
            # Trivy reports "python" or "python-pkg" in Type for pip packages
            if "python" in t or "pip" in t or v.get("target", "").lower().startswith("python"):
                py_pkg_fixes[pkg] = chosen
            else:
                os_pkg_fixes[pkg] = chosen

        # Detect package manager in Dockerfile
        pm = self._detect_pm(text)
        actions.append({"type": "info", "detected_pkg_manager": pm})

        # Apply OS package pins
        if os_pkg_fixes:
            before = text
            if pm == "apt":
                text = self._apply_apt_pins(text, os_pkg_fixes, actions)
            elif pm == "apk":
                text = self._apply_apk_pins(text, os_pkg_fixes, actions)
            elif pm == "yum":
                text = self._apply_yum_pins(text, os_pkg_fixes, actions)
            else:
                # Unknown: inject best-effort apt and apk lines guarded
                insert = self._inject_after_from(text, self._render_dual_os_fix_runs(os_pkg_fixes))
                text = insert
                actions.append({"type": "fallback-os-fix-insert", "pkgs": os_pkg_fixes})
            if text != before:
                actions.append({"type": "os-fixes-applied", "count": len(os_pkg_fixes)})

        # Apply Python pip upgrades (always safe to inject a dedicated RUN)
        if py_pkg_fixes:
            pip_line = "RUN pip install --no-cache-dir --upgrade " + " ".join(
                f"{name}=={ver}" for name, ver in py_pkg_fixes.items()
            )
            text = self._ensure_line_after_copy_or_from(text, pip_line)
            actions.append({"type": "python-fixes-inserted", "count": len(py_pkg_fixes), "line": pip_line})

        # Write patched Dockerfile if changed
        if text != self.orig_text:
            self.out_path.write_text(text)
            return {"patched_dockerfile": str(self.out_path), "actions": actions}
        else:
            actions.append({"type": "info", "msg": "No meaningful changes generated"})
            return {"patched_dockerfile": None, "actions": actions}

    def _alpine_needs_upgrade(self, tag: str) -> bool:
        # If tag is 'latest' -> assume okay. If numeric version < target, upgrade.
        try:
            # Keep major.minor only
            m = re.match(r'(\d+)\.(\d+)', tag)
            if not m:
                return False
            cur = (int(m.group(1)), int(m.group(2)))
            tgtm = re.match(r'(\d+)\.(\d+)', self.alpine_target)
            if not tgtm:
                return False
            tgt = (int(tgtm.group(1)), int(tgtm.group(2)))
            return cur < tgt
        except Exception:
            return False

    def _detect_pm(self, text: str) -> str:
        if re.search(r'\bapt(-get)?\b', text):
            return "apt"
        if "apk add" in text:
            return "apk"
        if re.search(r'\b(yum|dnf)\b', text):
            return "yum"
        return "unknown"

    def _apply_apt_pins(self, text: str, fixes: Dict[str, str], actions: List[Dict]) -> str:
        # Replace packages in apt-get install lines with pkg=ver
        def repl(m):
            line = m.group(0)
            new_line = line
            for pkg, ver in fixes.items():
                new_line = re.sub(rf'\b{re.escape(pkg)}\b', f"{pkg}={ver}", new_line)
            if new_line != line:
                actions.append({"type": "apt-line-pinned", "old": line.strip(), "new": new_line.strip()})
            return new_line
        new_text = re.sub(r'RUN\s+apt(-get)?\s+.*install.*', repl, text)
        if new_text == text:
            pins = " ".join(f"{p}={v}" for p, v in fixes.items())
            insert = f"\nRUN apt-get update && apt-get install -y {pins} || true\n"
            new_text = self._inject_after_from(text, insert)
            actions.append({"type": "apt-inserted", "line": insert.strip()})
        return new_text

    def _apply_apk_pins(self, text: str, fixes: Dict[str, str], actions: List[Dict]) -> str:
        def repl(m):
            line = m.group(0)
            new_line = line
            for pkg, ver in fixes.items():
                new_line = re.sub(rf'\b{re.escape(pkg)}\b', f"{pkg}={ver}", new_line)
            if new_line != line:
                actions.append({"type": "apk-line-pinned", "old": line.strip(), "new": new_line.strip()})
            return new_line
        new_text = re.sub(r'RUN\s+apk\s+add\s+.*', repl, text)
        if new_text == text:
            pins = " ".join(f"{p}={v}" for p, v in fixes.items())
            insert = f"\nRUN apk add --no-cache {pins} || true\n"
            new_text = self._inject_after_from(text, insert)
            actions.append({"type": "apk-inserted", "line": insert.strip()})
        return new_text

    def _apply_yum_pins(self, text: str, fixes: Dict[str, str], actions: List[Dict]) -> str:
        def repl(m):
            line = m.group(0)
            new_line = line
            for pkg, ver in fixes.items():
                new_line = re.sub(rf'\b{re.escape(pkg)}\b', f"{pkg}-{ver}", new_line)
            if new_line != line:
                actions.append({"type": "yum-line-pinned", "old": line.strip(), "new": new_line.strip()})
            return new_line
        new_text = re.sub(r'RUN\s+(yum|dnf)\s+install\s+.*', repl, text)
        if new_text == text:
            pins = " ".join(f"{p}-{v}" for p, v in fixes.items())
            insert = f"\nRUN yum install -y {pins} || true\n"
            new_text = self._inject_after_from(text, insert)
            actions.append({"type": "yum-inserted", "line": insert.strip()})
        return new_text

    def _render_dual_os_fix_runs(self, fixes: Dict[str, str]) -> str:
        apt = " ".join(f"{p}={v}" for p, v in fixes.items())
        apk = " ".join(f"{p}={v}" for p, v in fixes.items())
        return (
            f"\n# Best-effort OS fixes for unknown PM\n"
            f"RUN apt-get update && apt-get install -y {apt} || true\n"
            f"RUN apk add --no-cache {apk} || true\n"
        )

    def _inject_after_from(self, text: str, insert: str) -> str:
        return re.sub(r'(FROM\s+\S+\s*\n)', r'\1' + insert, text, count=1, flags=re.MULTILINE)

    def _ensure_line_after_copy_or_from(self, text: str, line: str) -> str:
        # Prefer after COPY of app (so pip sees requirements), else after FROM
        m = re.search(r'^(COPY\s+.+\n)', text, flags=re.MULTILINE)
        if m:
            idx = m.end()
            return text[:idx] + line + ("\n" if not line.endswith("\n") else "") + text[idx:]
        # Else after FROM
        return self._inject_after_from(text, "\n" + line + "\n")
