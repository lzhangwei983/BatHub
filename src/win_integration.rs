use crate::model::ScriptEntry;
use crate::scanner::normalize_path_id;
use serde::Deserialize;
use std::collections::HashSet;
use std::path::Path;
use winreg::enums::*;
use winreg::RegKey;

const STARTUP_REG_PATH: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const STARTUP_VALUE_NAME: &str = "BatHubLauncher";

const CONTEXT_CLASSES: &[&str] = &[
    r"Software\Classes\batfile\shell\AddToBatHub",
    r"Software\Classes\cmdfile\shell\AddToBatHub",
    r"Software\Classes\Directory\shell\AddToBatHub",
    r"Software\Classes\Directory\Background\shell\AddToBatHub",
];

pub fn set_run_on_startup(enabled: bool) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let (key, _) = hkcu
        .create_subkey(STARTUP_REG_PATH)
        .map_err(|e| e.to_string())?;

    if enabled {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let val = format!("\"{}\" --minimized", exe.to_string_lossy());
        key.set_value(STARTUP_VALUE_NAME, &val)
            .map_err(|e| e.to_string())?;
    } else {
        let _ = key.delete_value(STARTUP_VALUE_NAME);
    }
    Ok(())
}

pub fn set_context_menu(enabled: bool, label: &str) -> Result<(), String> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let exe_str = exe.to_string_lossy().to_string();

    if enabled {
        for reg_path in CONTEXT_CLASSES {
            let (key, _) = hkcu.create_subkey(reg_path).map_err(|e| e.to_string())?;
            key.set_value("", &label).map_err(|e| e.to_string())?;
            let _ = key.set_value("Icon", &exe_str);

            let (cmd_key, _) = key.create_subkey("command").map_err(|e| e.to_string())?;
            let arg_token = if reg_path.contains("Background") {
                "\"%V\""
            } else {
                "\"%1\""
            };
            let cmd_val = format!("\"{}\" --add {}", exe_str, arg_token);
            cmd_key.set_value("", &cmd_val).map_err(|e| e.to_string())?;
        }
    } else {
        for reg_path in CONTEXT_CLASSES {
            let _ = hkcu.delete_subkey_all(reg_path);
        }
    }
    Ok(())
}

#[derive(Deserialize)]
struct LegacyCategory {
    name: String,
    items: Vec<LegacyItem>,
}

#[derive(Deserialize)]
struct LegacyItem {
    name: String,
    desc: Option<String>,
    path: String,
}

fn map_legacy_category(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("ai") || lower.contains("\u{5927}\u{6a21}\u{578b}") || lower.contains("\u{8bed}\u{97f3}") {
        "ai_llm".to_string()
    } else if lower.contains("\u{91cf}\u{5316}") {
        "quant_finance".to_string()
    } else if lower.contains("web") || lower.contains("\u{77e5}\u{8bc6}\u{5e93}") {
        "web_service".to_string()
    } else if lower.contains("\u{624b}\u{673a}") || lower.contains("\u{4e92}\u{8054}") {
        "mobile_device".to_string()
    } else if lower.contains("\u{7cfb}\u{7edf}") || lower.contains("\u{684c}\u{9762}") {
        "sys_ops".to_string()
    } else {
        "general".to_string()
    }
}

pub fn import_legacy_launcherhub(
    json_path: &Path,
    entries: &mut Vec<ScriptEntry>,
) -> Result<usize, String> {
    let raw = std::fs::read_to_string(json_path).map_err(|e| e.to_string())?;
    let cats: Vec<LegacyCategory> = serde_json::from_str(&raw).map_err(|e| e.to_string())?;
    let mut existing: HashSet<String> = entries.iter().map(|e| e.id.clone()).collect();
    let mut added = 0usize;

    for cat in cats {
        let mapped_cat = map_legacy_category(&cat.name);
        for item in cat.items {
            let p = Path::new(&item.path);
            if !p.exists() {
                continue;
            }
            let id = normalize_path_id(p);
            if existing.contains(&id) {
                if let Some(found) = entries.iter_mut().find(|e| e.id == id) {
                    if !found.user_edited {
                        found.display_name = item.name;
                        if let Some(d) = item.desc {
                            found.description = d;
                        }
                        found.category = mapped_cat.clone();
                        found.user_edited = true;
                    }
                }
                continue;
            }
            existing.insert(id.clone());
            let analyzed = crate::analyzer::analyze_script(p);
            let file_name = p
                .file_name()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let project_dir = p
                .parent()
                .map(|d| d.to_string_lossy().to_string())
                .unwrap_or_default();

            entries.push(ScriptEntry {
                id,
                path: item.path,
                file_name,
                project_dir,
                project_name: analyzed.project_name,
                display_name: item.name,
                description: item.desc.unwrap_or(analyzed.description),
                category: mapped_cat.clone(),
                role: analyzed.role,
                ports: analyzed.ports,
                keywords: analyzed.keywords,
                process_names: analyzed.process_names,
                stop_script: None,
                paired_actions: Vec::new(),
                requires_admin: analyzed.requires_admin,
                pinned: false,
                hidden: false,
                user_edited: true,
                launch_count: 0,
                last_launched: None,
                source: "manual".to_string(),
            });
            added += 1;
        }
    }

    Ok(added)
}
