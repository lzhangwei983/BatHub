use crate::model::ScriptEntry;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use windows::core::{Interface, HSTRING, PCWSTR};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, IPersistFile, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows::Win32::UI::Shell::{IShellLinkW, ShellLink};

fn sanitize_filename(name: &str) -> String {
    let invalid = ['\\', '/', ':', '*', '?', '"', '<', '>', '|'];
    let cleaned: String = name
        .chars()
        .map(|c| if invalid.contains(&c) { '_' } else { c })
        .collect();
    cleaned.trim().trim_end_matches('.').to_string()
}

fn create_lnk(
    lnk_path: &Path,
    target_bat: &str,
    work_dir: &str,
    description: &str,
) -> Result<(), String> {
    unsafe {
        let link: IShellLinkW = CoCreateInstance(&ShellLink, None, CLSCTX_INPROC_SERVER)
            .map_err(|e| e.to_string())?;

        let target_h = HSTRING::from(target_bat);
        link.SetPath(PCWSTR(target_h.as_ptr()))
            .map_err(|e| e.to_string())?;

        let dir_h = HSTRING::from(work_dir);
        link.SetWorkingDirectory(PCWSTR(dir_h.as_ptr()))
            .map_err(|e| e.to_string())?;

        let desc_short: String = description.chars().take(200).collect();
        let desc_h = HSTRING::from(desc_short.as_str());
        let _ = link.SetDescription(PCWSTR(desc_h.as_ptr()));

        let icon_h = HSTRING::from(r"C:\Windows\System32\imageres.dll");
        let _ = link.SetIconLocation(PCWSTR(icon_h.as_ptr()), 63);

        let persist: IPersistFile = link.cast().map_err(|e| e.to_string())?;
        let lnk_h = HSTRING::from(lnk_path.to_string_lossy().as_ref());
        persist
            .Save(PCWSTR(lnk_h.as_ptr()), true)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

pub fn sync_shortcut_mirror(
    mirror_root: &Path,
    entries: &[ScriptEntry],
    category_labels: &HashMap<String, String>,
) -> Result<usize, String> {
    if mirror_root.as_os_str().is_empty() {
        return Ok(0);
    }
    fs::create_dir_all(mirror_root).map_err(|e| e.to_string())?;

    let mut expected_files: HashSet<PathBuf> = HashSet::new();
    let mut created_count = 0usize;

    unsafe {
        let _ = CoInitializeEx(None, COINIT_APARTMENTTHREADED);
    }

    for entry in entries {
        if entry.hidden {
            continue;
        }
        let cat_label = category_labels
            .get(&entry.category)
            .cloned()
            .unwrap_or_else(|| entry.category.clone());
        let folder_name = sanitize_filename(&cat_label);
        if folder_name.is_empty() {
            continue;
        }

        let cat_dir = mirror_root.join(&folder_name);
        if fs::create_dir_all(&cat_dir).is_err() {
            continue;
        }

        let mut base_name = sanitize_filename(&entry.display_name);
        if base_name.is_empty() {
            base_name = sanitize_filename(&entry.file_name);
        }
        let mut lnk_path = cat_dir.join(format!("{}.lnk", base_name));
        if expected_files.contains(&lnk_path) {
            lnk_path = cat_dir.join(format!("{} ({}).lnk", base_name, sanitize_filename(&entry.project_name)));
        }
        expected_files.insert(lnk_path.clone());

        if lnk_path.exists() {
            created_count += 1;
        } else if create_lnk(&lnk_path, &entry.path, &entry.project_dir, &entry.description).is_ok() {
            created_count += 1;
        }
    }

    if let Ok(cat_dirs) = fs::read_dir(mirror_root) {
        for cat_entry in cat_dirs.flatten() {
            let p = cat_entry.path();
            if p.is_dir() {
                if let Ok(files) = fs::read_dir(&p) {
                    for f in files.flatten() {
                        let fp = f.path();
                        if fp.extension().and_then(|e| e.to_str()) == Some("lnk")
                            && !expected_files.contains(&fp)
                        {
                            let _ = fs::remove_file(&fp);
                        }
                    }
                }
                if fs::read_dir(&p).map(|mut d| d.next().is_none()).unwrap_or(false) {
                    let _ = fs::remove_dir(&p);
                }
            }
        }
    }

    unsafe {
        CoUninitialize();
    }

    Ok(created_count)
}
