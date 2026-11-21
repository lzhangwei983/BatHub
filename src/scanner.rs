use crate::analyzer::analyze_script;
use crate::model::{ActionRef, AppData, ScriptEntry};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

const SKIP_DIRS: &[&str] = &[
    ".git",
    ".svn",
    ".hg",
    ".venv",
    "venv",
    "env",
    "node_modules",
    "__pycache__",
    "target",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".idea",
    ".vscode",
    "site-packages",
    "vendor",
    "logs",
    "cache",
    ".cache",
    "tmp",
    "temp",
    "appdata",
    "windows",
    "program files",
    "program files (x86)",
    "$recycle.bin",
    "system volume information",
    "shortcuts",
];

pub fn normalize_path_id(path: &Path) -> String {
    let s = path.to_string_lossy().to_string();
    let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
    trimmed.replace('/', "\\").to_lowercase()
}

pub fn normalize_path_str(path: &Path) -> String {
    let s = path.to_string_lossy().to_string();
    let trimmed = s.strip_prefix(r"\\?\").unwrap_or(&s);
    trimmed.replace('/', "\\")
}

fn is_bat_or_cmd(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e.to_ascii_lowercase().as_str(), "bat" | "cmd"))
        .unwrap_or(false)
}

fn should_skip_dir(dir: &Path) -> bool {
    if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
        let lower = name.to_lowercase();
        if SKIP_DIRS.contains(&lower.as_str()) {
            return true;
        }
        if lower.starts_with('.') && lower != ".github" {
            return true;
        }
    }
    false
}

fn walk_shallow(dir: &Path, depth: usize, max_depth: usize, out: &mut Vec<PathBuf>) {
    if depth > max_depth || !dir.is_dir() {
        return;
    }
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if depth < max_depth && !should_skip_dir(&path) {
                walk_shallow(&path, depth + 1, max_depth, out);
            }
        } else if is_bat_or_cmd(&path) {
            out.push(path);
        }
    }
}

pub fn detect_default_workspace_roots() -> Vec<String> {
    let mut roots = Vec::new();
    let mut seen = HashSet::new();

    let candidate_names = [
        "PythonProject",
        "Projects",
        "Project",
        "Workspace",
        "Workspaces",
        "Tools",
        "Scripts",
        "Code",
        "Dev",
    ];

    for drive in ["D:\\", "C:\\", "E:\\", "F:\\"] {
        let dp = Path::new(drive);
        if !dp.exists() {
            continue;
        }
        for name in candidate_names {
            let p = dp.join(name);
            if p.is_dir() {
                let norm = normalize_path_str(&p);
                if seen.insert(norm.to_lowercase()) {
                    roots.push(norm);
                }
            }
        }
        let cn_desktop = dp.join("\u{684c}\u{9762}");
        if cn_desktop.is_dir() {
            let norm = normalize_path_str(&cn_desktop);
            if seen.insert(norm.to_lowercase()) {
                roots.push(norm);
            }
        }
    }

    if let Ok(profile) = std::env::var("USERPROFILE") {
        let desktop = PathBuf::from(&profile).join("Desktop");
        if desktop.is_dir() {
            let norm = normalize_path_str(&desktop);
            if seen.insert(norm.to_lowercase()) {
                roots.push(norm);
            }
        }
    }

    roots
}

pub fn sync_workspaces(data: &mut AppData) -> usize {
    let max_depth = data.settings.max_scan_depth.max(1).min(4);
    let mut discovered_paths: Vec<PathBuf> = Vec::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for root in &data.settings.workspace_roots {
        let root_path = Path::new(root);
        if root_path.is_dir() {
            let mut local = Vec::new();
            walk_shallow(root_path, 0, max_depth, &mut local);
            for p in local {
                let id = normalize_path_id(&p);
                if seen_ids.insert(id) {
                    discovered_paths.push(p);
                }
            }
        }
    }

    let existing_map: HashMap<String, ScriptEntry> = data
        .entries
        .iter()
        .map(|e| (e.id.clone(), e.clone()))
        .collect();

    let mut raw_entries: Vec<ScriptEntry> = Vec::new();
    let mut processed_ids: HashSet<String> = HashSet::new();

    for path in discovered_paths {
        let id = normalize_path_id(&path);
        processed_ids.insert(id.clone());
        let entry = build_or_merge_entry(&path, "workspace", existing_map.get(&id));
        raw_entries.push(entry);
    }

    for prev in existing_map.values() {
        if prev.source == "manual" && !processed_ids.contains(&prev.id) && Path::new(&prev.path).exists() {
            processed_ids.insert(prev.id.clone());
            raw_entries.push(prev.clone());
        }
    }

    let final_entries = pair_project_scripts(raw_entries);
    let count = final_entries.len();
    data.entries = final_entries;
    count
}

pub fn add_manual_target(data: &mut AppData, target: &Path) -> Result<usize, String> {
    if !target.exists() {
        return Err("Target path does not exist".to_string());
    }

    if target.is_dir() {
        let norm = normalize_path_str(target);
        if !data
            .settings
            .workspace_roots
            .iter()
            .any(|r| r.eq_ignore_ascii_case(&norm))
        {
            data.settings.workspace_roots.push(norm);
        }
        let count = sync_workspaces(data);
        return Ok(count);
    }

    if !is_bat_or_cmd(target) {
        return Err("Only .bat and .cmd files or folders are supported".to_string());
    }

    let id = normalize_path_id(target);
    let existing = data.entries.iter().find(|e| e.id == id).cloned();
    let entry = build_or_merge_entry(target, "manual", existing.as_ref());

    data.entries.retain(|e| e.id != id);
    data.entries.push(entry);
    data.entries = pair_project_scripts(std::mem::take(&mut data.entries));
    Ok(data.entries.len())
}

fn build_or_merge_entry(
    path: &Path,
    source: &str,
    existing: Option<&ScriptEntry>,
) -> ScriptEntry {
    let analyzed = analyze_script(path);
    let norm_path = normalize_path_str(path);
    let id = normalize_path_id(path);
    let file_name = path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let project_dir = path
        .parent()
        .map(normalize_path_str)
        .unwrap_or_default();

    if let Some(prev) = existing {
        if prev.user_edited {
            return ScriptEntry {
                id,
                path: norm_path,
                file_name,
                project_dir,
                project_name: analyzed.project_name,
                display_name: prev.display_name.clone(),
                description: prev.description.clone(),
                category: prev.category.clone(),
                role: prev.role.clone(),
                ports: if prev.ports.is_empty() {
                    analyzed.ports
                } else {
                    prev.ports.clone()
                },
                keywords: prev.keywords.clone(),
                process_names: prev.process_names.clone(),
                stop_script: prev.stop_script.clone(),
                paired_actions: Vec::new(),
                requires_admin: analyzed.requires_admin,
                pinned: prev.pinned,
                hidden: prev.hidden,
                user_edited: true,
                launch_count: prev.launch_count,
                last_launched: prev.last_launched,
                source: if prev.source == "manual" {
                    "manual".to_string()
                } else {
                    source.to_string()
                },
            };
        }
    }

    ScriptEntry {
        id,
        path: norm_path,
        file_name,
        project_dir,
        project_name: analyzed.project_name,
        display_name: analyzed.display_name,
        description: analyzed.description,
        category: analyzed.category,
        role: analyzed.role,
        ports: analyzed.ports,
        keywords: analyzed.keywords,
        process_names: analyzed.process_names,
        stop_script: None,
        paired_actions: Vec::new(),
        requires_admin: analyzed.requires_admin,
        pinned: existing.map(|e| e.pinned).unwrap_or(false),
        hidden: existing.map(|e| e.hidden).unwrap_or(false),
        user_edited: false,
        launch_count: existing.map(|e| e.launch_count).unwrap_or(0),
        last_launched: existing.and_then(|e| e.last_launched),
        source: existing
            .map(|e| e.source.clone())
            .unwrap_or_else(|| source.to_string()),
    }
}

fn is_flat_collection_dir(dir_path: &str) -> bool {
    let last = Path::new(dir_path)
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    matches!(
        last.as_str(),
        "desktop"
            | "\u{684c}\u{9762}"
            | "\u{684c}\u{9762}\u{542f}\u{52a8}\u{5668}\u{5907}\u{4efd}"
            | "tools"
            | "scripts"
            | "bin"
            | "support"
    )
}

fn pair_project_scripts(entries: Vec<ScriptEntry>) -> Vec<ScriptEntry> {
    let mut by_dir: HashMap<String, Vec<ScriptEntry>> = HashMap::new();
    for mut e in entries {
        e.paired_actions.clear();
        by_dir
            .entry(e.project_dir.to_lowercase())
            .or_default()
            .push(e);
    }

    let mut result = Vec::new();

    for (dir, mut group) in by_dir {
        let has_service = group.iter().any(|e| e.role == "service");
        if !has_service || group.len() == 1 || is_flat_collection_dir(&dir) {
            result.extend(group);
            continue;
        }

        let stop_script = group
            .iter()
            .find(|e| e.role == "stop")
            .map(|e| e.path.clone());

        let mut folded_actions: Vec<ActionRef> = Vec::new();
        let mut services: Vec<ScriptEntry> = Vec::new();

        for item in group.drain(..) {
            if item.role == "service" {
                services.push(item);
            } else {
                folded_actions.push(ActionRef {
                    name: item.display_name,
                    path: item.path,
                    role: item.role,
                    requires_admin: item.requires_admin,
                });
            }
        }

        if let Some(first) = services.first_mut() {
            if first.stop_script.is_none() {
                first.stop_script = stop_script.clone();
            }
            first.paired_actions = folded_actions;
        }
        for svc in services.iter_mut().skip(1) {
            if svc.stop_script.is_none() {
                svc.stop_script = stop_script.clone();
            }
        }

        result.extend(services);
    }

    result.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then_with(|| b.launch_count.cmp(&a.launch_count))
            .then_with(|| a.display_name.to_lowercase().cmp(&b.display_name.to_lowercase()))
    });

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shortcuts::sync_shortcut_mirror;

    #[test]
    fn test_shallow_scan_pairing_and_lnk_mirror() {
        let root = std::env::temp_dir().join("bathub_scan_test");
        let _ = fs::remove_dir_all(&root);
        let proj = root.join("my_web_tool");
        let venv = proj.join(".venv").join("Scripts");
        let mirror = root.join("Shortcuts");
        fs::create_dir_all(&proj).unwrap();
        fs::create_dir_all(&venv).unwrap();

        fs::write(proj.join("package.json"), r#"{"name":"my-web-tool","dependencies":{"vite":"5.0"}}"#).unwrap();
        fs::write(proj.join("start.bat"), "@echo off\r\nnpm run dev -- --port 5173\r\n").unwrap();
        fs::write(proj.join("0_stop_all.bat"), "@echo off\r\ntaskkill /f /im node.exe\r\n").unwrap();
        fs::write(venv.join("activate.bat"), "@echo off\r\n").unwrap();

        let mut data = AppData::default();
        data.settings.workspace_roots = vec![normalize_path_str(&root)];
        let count = sync_workspaces(&mut data);

        assert_eq!(count, 1);
        assert_eq!(data.entries[0].category, "web_service");
        assert!(data.entries[0].ports.contains(&5173));
        assert!(data.entries[0].stop_script.is_some());
        assert_eq!(data.entries[0].paired_actions.len(), 1);

        let mut labels = HashMap::new();
        labels.insert("web_service".to_string(), "Web Dashboards".to_string());
        let lnk_count = sync_shortcut_mirror(&mirror, &data.entries, &labels).unwrap();
        assert_eq!(lnk_count, 1);

        let lnk_dir = mirror.join("Web Dashboards");
        let lnks: Vec<_> = fs::read_dir(&lnk_dir)
            .unwrap()
            .flatten()
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("lnk"))
            .collect();
        assert_eq!(lnks.len(), 1);

        let _ = fs::remove_dir_all(&root);
    }
}
