from typing import List, Dict

def generate_final_report(original_image: str, rebuilt_image: str, initial_vulns: List[Dict], post_vulns: List[Dict], actions: List[Dict]) -> Dict:
    def key(v):
        return f"{v.get('vuln_id')}|{v.get('pkg_name')}|{v.get('installed_version')}"

    initial_map = {key(v): v for v in (initial_vulns or [])}
    post_map = {key(v): v for v in (post_vulns or [])}

    removed = [v for k, v in initial_map.items() if k not in post_map]
    persisted = [v for k, v in initial_map.items() if k in post_map]
    new = [v for k, v in post_map.items() if k not in initial_map]

    return {
        "original_image": original_image,
        "rebuilt_image": rebuilt_image,
        "summary": {
            "initial_vuln_count": len(initial_map),
            "post_vuln_count": len(post_map),
            "removed_count": len(removed),
            "persisted_count": len(persisted),
            "new_count": len(new),
        },
        "removed_vulnerabilities": removed,
        "persisted_vulnerabilities": persisted,
        "new_vulnerabilities": new,
        "actions": actions
    }
