use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryDef {
    pub id: String,
    pub icon: String,
    pub order: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRef {
    pub name: String,
    pub path: String,
    pub role: String,
    pub requires_admin: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScriptEntry {
    pub id: String,
    pub path: String,
    pub file_name: String,
    pub project_dir: String,
    pub project_name: String,
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub role: String,
    pub ports: Vec<u16>,
    pub keywords: Vec<String>,
    pub process_names: Vec<String>,
    pub stop_script: Option<String>,
    pub paired_actions: Vec<ActionRef>,
    pub requires_admin: bool,
    pub pinned: bool,
    pub hidden: bool,
    pub user_edited: bool,
    pub launch_count: u32,
    pub last_launched: Option<u64>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub language: String,
    pub workspace_roots: Vec<String>,
    pub mirror_enabled: bool,
    pub shortcut_mirror_dir: String,
    pub hotkey: String,
    pub start_minimized: bool,
    pub run_on_startup: bool,
    pub context_menu_enabled: bool,
    pub silent_run_default: bool,
    pub max_scan_depth: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppData {
    pub version: u32,
    pub settings: AppSettings,
    pub entries: Vec<ScriptEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuntimeStatus {
    pub id: String,
    pub running: bool,
    pub matched_port: Option<u16>,
    pub pids: Vec<u32>,
    pub status_hint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExternalService {
    pub pid: u32,
    pub process_name: String,
    pub port: u16,
    pub bind_addr: String,
    pub cmdline: String,
    pub project_dir: String,
    pub suggested_bat_dir: Option<String>,
}

pub fn builtin_categories() -> Vec<CategoryDef> {
    vec![
        CategoryDef { id: "ai_llm".into(), icon: "AI".into(), order: 1 },
        CategoryDef { id: "web_service".into(), icon: "WEB".into(), order: 2 },
        CategoryDef { id: "quant_finance".into(), icon: "FIN".into(), order: 3 },
        CategoryDef { id: "automation_media".into(), icon: "AUTO".into(), order: 4 },
        CategoryDef { id: "mobile_device".into(), icon: "DEV".into(), order: 5 },
        CategoryDef { id: "embedded_hw".into(), icon: "HW".into(), order: 6 },
        CategoryDef { id: "sys_ops".into(), icon: "OPS".into(), order: 7 },
        CategoryDef { id: "general".into(), icon: "MISC".into(), order: 8 },
    ]
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            language: "zh-CN".to_string(),
            workspace_roots: Vec::new(),
            mirror_enabled: true,
            shortcut_mirror_dir: String::new(),
            hotkey: "Alt+Shift+B".to_string(),
            start_minimized: false,
            run_on_startup: false,
            context_menu_enabled: false,
            silent_run_default: false,
            max_scan_depth: 2,
        }
    }
}

impl Default for AppData {
    fn default() -> Self {
        Self {
            version: 4,
            settings: AppSettings::default(),
            entries: Vec::new(),
        }
    }
}
