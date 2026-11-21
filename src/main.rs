#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod analyzer;
mod model;
mod monitor;
mod scanner;
mod shortcuts;
mod win_integration;

use global_hotkey::hotkey::{Code, HotKey, Modifiers};
use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
use model::{builtin_categories, AppData, ExternalService, RuntimeStatus, ScriptEntry};
use monitor::{
    launch_script, open_folder_and_select, open_in_terminal, stop_pid, stop_service, SystemMonitor,
};
use scanner::{add_manual_target, detect_default_workspace_roots, normalize_path_str, sync_workspaces};
use serde::{Deserialize, Serialize};
use shortcuts::sync_shortcut_mirror;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tao::event::{Event, WindowEvent};
use tao::event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy};
use tao::window::{Icon as WindowIcon, Window, WindowBuilder};
use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{
    Icon as TrayIconImg, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent,
};
use wry::{DragDropEvent, WebView, WebViewBuilder};

const INDEX_HTML: &str = include_str!("../ui/index.html");
const LOCALE_ZH: &str = include_str!("../locales/zh-CN.json");
const LOCALE_EN: &str = include_str!("../locales/en-US.json");
const LEGACY_LAUNCHERHUB_JSON: &str = r"D:\Tools\LauncherHub\launchers_data.json";

#[derive(Debug, Clone)]
enum UserEvent {
    IpcMessage(String),
    MenuAction(String),
    TrayClick,
    HotkeyPressed,
    MonitorReady {
        statuses: HashMap<String, RuntimeStatus>,
        external_services: Vec<ExternalService>,
    },
    SyncDone {
        data: AppData,
        statuses: HashMap<String, RuntimeStatus>,
        external_services: Vec<ExternalService>,
        message: String,
        sync_epoch: u64,
    },
    RemoteShow,
    RemoteAdd(String),
    DropPaths(Vec<PathBuf>),
}

#[derive(Deserialize)]
struct UiCommand {
    action: String,
    #[serde(default)]
    payload: serde_json::Value,
}

#[derive(Serialize)]
struct UiStatePayload {
    entries: Vec<ScriptEntry>,
    statuses: HashMap<String, RuntimeStatus>,
    external_services: Vec<ExternalService>,
    categories: Vec<model::CategoryDef>,
    settings: model::AppSettings,
    i18n: HashMap<String, String>,
    legacy_available: bool,
    status_message: String,
    syncing: bool,
    last_sync_epoch: u64,
    toast_seq: u64,
    toast_message: String,
}

struct SharedState {
    data: AppData,
    statuses: HashMap<String, RuntimeStatus>,
    external_services: Vec<ExternalService>,
    window_visible: bool,
    status_message: String,
    syncing: bool,
    last_sync_epoch: u64,
    toast_seq: u64,
    toast_message: String,
    data_path: PathBuf,
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn load_locale_map(lang: &str) -> HashMap<String, String> {
    let raw = if lang == "en-US" { LOCALE_EN } else { LOCALE_ZH };
    serde_json::from_str(raw).unwrap_or_default()
}

fn build_category_labels(i18n: &HashMap<String, String>) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for cat in builtin_categories() {
        let key = format!("cat_{}", cat.id);
        let label = i18n.get(&key).cloned().unwrap_or_else(|| cat.id.clone());
        map.insert(cat.id, label);
    }
    map
}

fn generate_app_icon_rgba() -> (Vec<u8>, u32, u32) {
    let w = 32u32;
    let h = 32u32;
    let mut rgba = vec![0u8; (w * h * 4) as usize];

    for y in 0..h {
        for x in 0..w {
            let idx = ((y * w + x) * 4) as usize;
            let dx = if x < 6 {
                6 - x
            } else if x >= 26 {
                x - 25
            } else {
                0
            };
            let dy = if y < 6 {
                6 - y
            } else if y >= 26 {
                y - 25
            } else {
                0
            };
            let inside_round = (dx * dx + dy * dy) <= 36;
            if !inside_round {
                rgba[idx + 3] = 0;
                continue;
            }

            let t = (x + y) as f32 / 62.0;
            let r = (37.0 * (1.0 - t) + 16.0 * t) as u8;
            let g = (99.0 * (1.0 - t) + 185.0 * t) as u8;
            let b = (235.0 * (1.0 - t) + 129.0 * t) as u8;

            rgba[idx] = r;
            rgba[idx + 1] = g;
            rgba[idx + 2] = b;
            rgba[idx + 3] = 255;
        }
    }

    let glyph_pts: &[(u32, u32)] = &[
        (8, 10), (9, 10), (9, 11), (10, 11), (10, 12), (11, 12), (11, 13), (12, 13),
        (12, 14), (13, 14), (13, 15), (14, 15), (14, 16), (13, 16), (13, 17), (12, 17),
        (12, 18), (11, 18), (11, 19), (10, 19), (10, 20), (9, 20), (9, 21), (8, 21),
        (8, 11), (9, 12), (10, 13), (11, 14), (12, 15), (12, 16), (11, 17), (10, 18),
        (9, 19), (8, 20),
    ];
    for &(px, py) in glyph_pts {
        let idx = ((py * w + px) * 4) as usize;
        rgba[idx] = 255;
        rgba[idx + 1] = 255;
        rgba[idx + 2] = 255;
        rgba[idx + 3] = 255;
    }

    for px in 16..24 {
        for py in 19..22 {
            let idx = ((py * w + px) * 4) as usize;
            rgba[idx] = 255;
            rgba[idx + 1] = 255;
            rgba[idx + 2] = 255;
            rgba[idx + 3] = 255;
        }
    }

    (rgba, w, h)
}

fn app_base_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .unwrap_or_else(|| PathBuf::from("."))
}

fn load_or_init_data(data_path: &Path, base_dir: &Path) -> AppData {
    if data_path.exists() {
        if let Ok(raw) = fs::read_to_string(data_path) {
            if let Ok(mut parsed) = serde_json::from_str::<AppData>(&raw) {
                if parsed.settings.shortcut_mirror_dir.is_empty() {
                    parsed.settings.shortcut_mirror_dir =
                        normalize_path_str(&base_dir.join("Shortcuts"));
                }
                if parsed.version < 4 {
                    parsed.version = 4;
                    sync_workspaces(&mut parsed);
                    save_data(data_path, &parsed);
                }
                return parsed;
            }
        }
    }

    let mut data = AppData::default();
    data.settings.workspace_roots = detect_default_workspace_roots();
    data.settings.shortcut_mirror_dir = normalize_path_str(&base_dir.join("Shortcuts"));
    sync_workspaces(&mut data);
    save_data(data_path, &data);
    data
}

fn save_data(data_path: &Path, data: &AppData) {
    if let Ok(json) = serde_json::to_string_pretty(data) {
        let _ = fs::write(data_path, json);
    }
}

fn sync_mirror_if_enabled(data: &AppData) -> Option<usize> {
    if !data.settings.mirror_enabled || data.settings.shortcut_mirror_dir.trim().is_empty() {
        return None;
    }
    let i18n = load_locale_map(&data.settings.language);
    let cat_labels = build_category_labels(&i18n);
    let dir = Path::new(&data.settings.shortcut_mirror_dir);
    sync_shortcut_mirror(dir, &data.entries, &cat_labels).ok()
}

fn build_tray_menu(data: &AppData, statuses: &HashMap<String, RuntimeStatus>) -> Menu {
    let i18n = load_locale_map(&data.settings.language);
    let t = |k: &str| i18n.get(k).cloned().unwrap_or_else(|| k.to_string());

    let menu = Menu::new();
    let show_item = MenuItem::with_id("tray:show", t("tray_show"), true, None);
    let sync_item = MenuItem::with_id("tray:sync", t("tray_sync"), true, None);
    let mirror_item = MenuItem::with_id("tray:mirror", t("tray_mirror"), true, None);
    let _ = menu.append(&show_item);
    let _ = menu.append(&sync_item);
    let _ = menu.append(&mirror_item);
    let _ = menu.append(&PredefinedMenuItem::separator());

    let running_entries: Vec<&ScriptEntry> = data
        .entries
        .iter()
        .filter(|e| !e.hidden && statuses.get(&e.id).map(|s| s.running).unwrap_or(false))
        .take(8)
        .collect();
    if !running_entries.is_empty() {
        let header = MenuItem::with_id("tray:noop", format!("[{}]", t("tray_running_header")), false, None);
        let _ = menu.append(&header);
        for e in running_entries {
            let label = format!("* {}", e.display_name);
            let mi = MenuItem::with_id(format!("launch:{}", e.id), label, true, None);
            let _ = menu.append(&mi);
        }
        let _ = menu.append(&PredefinedMenuItem::separator());
    }

    for cat in builtin_categories() {
        let items_in_cat: Vec<&ScriptEntry> = data
            .entries
            .iter()
            .filter(|e| !e.hidden && e.category == cat.id)
            .take(25)
            .collect();
        if items_in_cat.is_empty() {
            continue;
        }
        let cat_label = i18n
            .get(&format!("cat_{}", cat.id))
            .cloned()
            .unwrap_or_else(|| cat.id.clone());
        let sub = Submenu::new(format!("{} ({})", cat_label, items_in_cat.len()), true);
        for e in items_in_cat {
            let mi = MenuItem::with_id(format!("launch:{}", e.id), &e.display_name, true, None);
            let _ = sub.append(&mi);
        }
        let _ = menu.append(&sub);
    }

    let _ = menu.append(&PredefinedMenuItem::separator());
    let quit_item = MenuItem::with_id("tray:quit", t("tray_quit"), true, None);
    let _ = menu.append(&quit_item);
    menu
}

fn push_ui_state(webview: &WebView, shared: &Arc<Mutex<SharedState>>) {
    let payload = {
        let guard = shared.lock().unwrap();
        let i18n = load_locale_map(&guard.data.settings.language);
        UiStatePayload {
            entries: guard.data.entries.clone(),
            statuses: guard.statuses.clone(),
            external_services: guard.external_services.clone(),
            categories: builtin_categories(),
            settings: guard.data.settings.clone(),
            i18n,
            legacy_available: Path::new(LEGACY_LAUNCHERHUB_JSON).exists(),
            status_message: guard.status_message.clone(),
            syncing: guard.syncing,
            last_sync_epoch: guard.last_sync_epoch,
            toast_seq: guard.toast_seq,
            toast_message: guard.toast_message.clone(),
        }
    };
    if let Ok(json) = serde_json::to_string(&payload) {
        let safe_json = json
            .replace('\u{2028}', "\\u2028")
            .replace('\u{2029}', "\\u2029");
        let script = format!("if(window.__bathubUpdate){{window.__bathubUpdate({});}}", safe_json);
        let _ = webview.evaluate_script(&script);
    }
}

fn evaluate_all_statuses(
    mon: &mut SystemMonitor,
    entries: &[ScriptEntry],
) -> (HashMap<String, RuntimeStatus>, Vec<ExternalService>) {
    let snap = mon.snapshot();
    let mut statuses = HashMap::new();
    for entry in entries {
        statuses.insert(entry.id.clone(), mon.evaluate_entry(&snap, entry));
    }
    let external = mon.detect_unmanaged_services(&snap, entries, &statuses);
    (statuses, external)
}

fn show_and_focus_window(
    window: &Window,
    webview: &WebView,
    shared: &Arc<Mutex<SharedState>>,
    monitor: &Arc<Mutex<SystemMonitor>>,
) {
    {
        let entries_snapshot = {
            let mut guard = shared.lock().unwrap();
            guard.window_visible = true;
            guard.data.entries.clone()
        };
        let (new_statuses, new_external) = {
            let mut mon = monitor.lock().unwrap();
            evaluate_all_statuses(&mut mon, &entries_snapshot)
        };
        let mut guard = shared.lock().unwrap();
        guard.statuses = new_statuses;
        guard.external_services = new_external;
    }
    window.set_visible(true);
    window.set_minimized(false);
    window.set_focus();
    push_ui_state(webview, shared);
    let _ = webview.evaluate_script("if(window.__bathubFocusSearch){window.__bathubFocusSearch();}");
}

fn spawn_delayed_monitor_probes(
    proxy: EventLoopProxy<UserEvent>,
    shared: Arc<Mutex<SharedState>>,
    monitor: Arc<Mutex<SystemMonitor>>,
) {
    std::thread::spawn(move || {
        for wait_ms in [450u64, 1000, 1600] {
            std::thread::sleep(Duration::from_millis(wait_ms));
            let entries_snapshot = shared.lock().unwrap().data.entries.clone();
            let (statuses, external_services) = {
                let mut mon = monitor.lock().unwrap();
                evaluate_all_statuses(&mut mon, &entries_snapshot)
            };
            let _ = proxy.send_event(UserEvent::MonitorReady {
                statuses,
                external_services,
            });
        }
    });
}

fn spawn_background_sync(
    proxy: EventLoopProxy<UserEvent>,
    shared: Arc<Mutex<SharedState>>,
    monitor: Arc<Mutex<SystemMonitor>>,
) -> bool {
    let (mut data_snapshot, before_ids, root_count) = {
        let mut guard = shared.lock().unwrap();
        if guard.syncing {
            return false;
        }
        guard.syncing = true;
        guard.status_message = "Syncing workspaces...".to_string();
        let ids: HashSet<String> = guard.data.entries.iter().map(|e| e.id.clone()).collect();
        let roots = guard.data.settings.workspace_roots.len();
        (guard.data.clone(), ids, roots)
    };

    std::thread::spawn(move || {
        let count = sync_workspaces(&mut data_snapshot);
        let after_ids: HashSet<String> = data_snapshot.entries.iter().map(|e| e.id.clone()).collect();
        let added = after_ids.difference(&before_ids).count();
        let removed = before_ids.difference(&after_ids).count();

        let lnks = sync_mirror_if_enabled(&data_snapshot).unwrap_or(0);
        let (new_st, new_ext) = {
            let mut mon = monitor.lock().unwrap();
            evaluate_all_statuses(&mut mon, &data_snapshot.entries)
        };
        let running_cnt = new_st.values().filter(|s| s.running).count();
        let sync_epoch = now_unix_secs();

        let message = if data_snapshot.settings.language == "en-US" {
            format!(
                "Synced {} roots: {} scripts (+{} / -{}), {} shortcuts, {} running",
                root_count, count, added, removed, lnks, running_cnt
            )
        } else {
            format!(
                "\u{540c}\u{6b65}\u{5b8c}\u{6210}\u{ff1a}{} \u{4e2a}\u{5de5}\u{4f5c}\u{533a} / {} \u{4e2a}\u{811a}\u{672c} (+{} / -{}) / {} \u{4e2a}\u{5feb}\u{6377}\u{65b9}\u{5f0f} / {} \u{4e2a}\u{8fd0}\u{884c}\u{4e2d}",
                root_count, count, added, removed, lnks, running_cnt
            )
        };

        let _ = proxy.send_event(UserEvent::SyncDone {
            data: data_snapshot,
            statuses: new_st,
            external_services: new_ext,
            message,
            sync_epoch,
        });
    });
    true
}

fn try_send_to_existing_instance(lock_path: &Path, args: &[String]) -> bool {
    let Ok(port_str) = fs::read_to_string(lock_path) else {
        return false;
    };
    let Ok(port) = port_str.trim().parse::<u16>() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(
        &format!("127.0.0.1:{}", port).parse().unwrap(),
        Duration::from_millis(250),
    ) else {
        return false;
    };

    let mut msg = "SHOW".to_string();
    for i in 0..args.len() {
        if args[i] == "--add" && i + 1 < args.len() {
            msg = format!("ADD|{}", args[i + 1]);
            break;
        }
    }
    let _ = stream.write_all(msg.as_bytes());
    true
}

fn start_ipc_server(lock_path: PathBuf, proxy: EventLoopProxy<UserEvent>) {
    if let Ok(listener) = TcpListener::bind("127.0.0.1:0") {
        if let Ok(addr) = listener.local_addr() {
            let _ = fs::write(&lock_path, addr.port().to_string());
        }
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut s = stream;
                let mut buf = String::new();
                if s.read_to_string(&mut buf).is_ok() {
                    let trimmed = buf.trim().to_string();
                    if let Some(target) = trimmed.strip_prefix("ADD|") {
                        let _ = proxy.send_event(UserEvent::RemoteAdd(target.to_string()));
                    } else {
                        let _ = proxy.send_event(UserEvent::RemoteShow);
                    }
                }
            }
        });
    }
}

fn handle_launch_by_id(
    id: &str,
    silent_override: Option<bool>,
    shared: &Arc<Mutex<SharedState>>,
    monitor: &Arc<Mutex<SystemMonitor>>,
) {
    let (path_opt, silent, admin, name) = {
        let mut guard = shared.lock().unwrap();
        let default_silent = guard.data.settings.silent_run_default;
        let now_ts = now_unix_secs();
        if let Some(entry) = guard.data.entries.iter_mut().find(|e| e.id == id) {
            entry.launch_count += 1;
            entry.last_launched = Some(now_ts);
            (
                Some(entry.path.clone()),
                silent_override.unwrap_or(default_silent),
                entry.requires_admin,
                entry.display_name.clone(),
            )
        } else {
            (None, false, false, String::new())
        }
    };

    if let Some(path) = path_opt {
        let res = launch_script(&path, silent, admin);
        if let Ok(Some(pid)) = res {
            monitor.lock().unwrap().register_launched_pid(id, pid);
        }
        let mut guard = shared.lock().unwrap();
        let msg = match res {
            Ok(_) => format!("Launched: {}", name),
            Err(e) => format!("Launch failed: {}", e),
        };
        guard.status_message = msg.clone();
        guard.toast_seq += 1;
        guard.toast_message = msg;
        save_data(&guard.data_path, &guard.data);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let base_dir = app_base_dir();
    let panic_log = base_dir.join("bathub_panic.log");
    std::panic::set_hook(Box::new(move |info| {
        let msg = format!("PANIC: {}\n", info);
        let _ = fs::write(&panic_log, msg);
    }));
    let lock_path = base_dir.join("bathub.lock");

    if try_send_to_existing_instance(&lock_path, &args) {
        return;
    }

    let start_minimized_arg = args.iter().any(|a| a == "--minimized");
    let mut initial_add: Option<String> = None;
    for i in 0..args.len() {
        if args[i] == "--add" && i + 1 < args.len() {
            initial_add = Some(args[i + 1].clone());
            break;
        }
    }

    let data_path = base_dir.join("bathub_data.json");
    let mut data = load_or_init_data(&data_path, &base_dir);
    if let Some(ref target) = initial_add {
        let _ = add_manual_target(&mut data, Path::new(target));
        save_data(&data_path, &data);
    }
    sync_mirror_if_enabled(&data);

    let start_visible = !start_minimized_arg && !data.settings.start_minimized;

    let monitor = Arc::new(Mutex::new(SystemMonitor::new()));
    let (initial_statuses, initial_external) = {
        let mut mon = monitor.lock().unwrap();
        evaluate_all_statuses(&mut mon, &data.entries)
    };

    let shared = Arc::new(Mutex::new(SharedState {
        data,
        statuses: initial_statuses,
        external_services: initial_external,
        window_visible: start_visible,
        status_message: "Ready".to_string(),
        syncing: false,
        last_sync_epoch: now_unix_secs(),
        toast_seq: 0,
        toast_message: String::new(),
        data_path: data_path.clone(),
    }));

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    start_ipc_server(lock_path.clone(), proxy.clone());

    let (icon_rgba, icon_w, icon_h) = generate_app_icon_rgba();
    let win_icon = WindowIcon::from_rgba(icon_rgba.clone(), icon_w, icon_h).ok();
    let tray_icon_img = TrayIconImg::from_rgba(icon_rgba, icon_w, icon_h).expect("tray icon");

    let window = WindowBuilder::new()
        .with_title("BatHub")
        .with_inner_size(tao::dpi::LogicalSize::new(1120.0, 760.0))
        .with_min_inner_size(tao::dpi::LogicalSize::new(880.0, 560.0))
        .with_visible(start_visible)
        .with_window_icon(win_icon)
        .build(&event_loop)
        .expect("Failed to create window");

    let ipc_proxy = proxy.clone();
    let drop_proxy = proxy.clone();
    let webview = WebViewBuilder::new()
        .with_html(INDEX_HTML)
        .with_ipc_handler(move |req| {
            let _ = ipc_proxy.send_event(UserEvent::IpcMessage(req.body().to_string()));
        })
        .with_drag_drop_handler(move |ev| {
            if let DragDropEvent::Drop { paths, .. } = ev {
                let _ = drop_proxy.send_event(UserEvent::DropPaths(paths));
            }
            true
        })
        .build(&window)
        .expect("Failed to build WebView");

    let mut tray_icon: Option<TrayIcon> = None;
    for _attempt in 0..5 {
        let attempt_menu = {
            let guard = shared.lock().unwrap();
            build_tray_menu(&guard.data, &guard.statuses)
        };
        if let Ok(built) = TrayIconBuilder::new()
            .with_menu(Box::new(attempt_menu))
            .with_tooltip("BatHub - Smart Batch Launcher")
            .with_icon(tray_icon_img.clone())
            .build()
        {
            tray_icon = Some(built);
            break;
        }
        std::thread::sleep(Duration::from_millis(350));
    }

    let menu_proxy = proxy.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        let _ = menu_proxy.send_event(UserEvent::MenuAction(event.id.0));
    }));

    let tray_proxy = proxy.clone();
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if let TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } = event
        {
            let _ = tray_proxy.send_event(UserEvent::TrayClick);
        }
    }));

    let hotkey_manager = GlobalHotKeyManager::new().ok();
    let toggle_hotkey = HotKey::new(Some(Modifiers::ALT | Modifiers::SHIFT), Code::KeyB);
    if let Some(ref mgr) = hotkey_manager {
        let _ = mgr.register(toggle_hotkey);
    }
    let hk_proxy = proxy.clone();
    let hk_id = toggle_hotkey.id();
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == hk_id && event.state == HotKeyState::Pressed {
            let _ = hk_proxy.send_event(UserEvent::HotkeyPressed);
        }
    }));

    let mon_proxy = proxy.clone();
    let mon_shared = Arc::clone(&shared);
    let mon_handle = Arc::clone(&monitor);
    std::thread::spawn(move || {
        let mut tick: u64 = 0;
        loop {
            std::thread::sleep(Duration::from_millis(2200));
            tick = tick.wrapping_add(1);
            let (visible, entries_snapshot) = {
                let guard = mon_shared.lock().unwrap();
                (guard.window_visible, guard.data.entries.clone())
            };
            if visible || tick % 5 == 0 {
                let (statuses, external_services) = {
                    let mut mon = mon_handle.lock().unwrap();
                    evaluate_all_statuses(&mut mon, &entries_snapshot)
                };
                let _ = mon_proxy.send_event(UserEvent::MonitorReady {
                    statuses,
                    external_services,
                });
            }
        }
    });

    let mut last_tray_toggle = Instant::now() - Duration::from_secs(5);

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                if tray_icon.is_some() {
                    window.set_visible(false);
                    shared.lock().unwrap().window_visible = false;
                } else {
                    let _ = fs::remove_file(&lock_path);
                    *control_flow = ControlFlow::Exit;
                }
            }

            Event::UserEvent(user_ev) => match user_ev {
                UserEvent::TrayClick => {
                    if last_tray_toggle.elapsed() < Duration::from_millis(350) {
                        return;
                    }
                    last_tray_toggle = Instant::now();
                    let is_vis = shared.lock().unwrap().window_visible;
                    if is_vis && !window.is_minimized() {
                        window.set_visible(false);
                        shared.lock().unwrap().window_visible = false;
                    } else {
                        show_and_focus_window(&window, &webview, &shared, &monitor);
                    }
                }

                UserEvent::HotkeyPressed => {
                    let is_vis = shared.lock().unwrap().window_visible;
                    if is_vis && !window.is_minimized() {
                        window.set_visible(false);
                        shared.lock().unwrap().window_visible = false;
                    } else {
                        show_and_focus_window(&window, &webview, &shared, &monitor);
                    }
                }

                UserEvent::RemoteShow => {
                    show_and_focus_window(&window, &webview, &shared, &monitor);
                }

                UserEvent::RemoteAdd(target) => {
                    {
                        let mut guard = shared.lock().unwrap();
                        let res = add_manual_target(&mut guard.data, Path::new(&target));
                        guard.status_message = match res {
                            Ok(n) => format!("Added from Explorer ({} total)", n),
                            Err(e) => format!("Add failed: {}", e),
                        };
                        save_data(&guard.data_path, &guard.data);
                        sync_mirror_if_enabled(&guard.data);
                    }
                    if let Some(ref ti) = tray_icon {
                        let new_menu = {
                            let guard = shared.lock().unwrap();
                            build_tray_menu(&guard.data, &guard.statuses)
                        };
                        ti.set_menu(Some(Box::new(new_menu)));
                    }
                    show_and_focus_window(&window, &webview, &shared, &monitor);
                }

                UserEvent::DropPaths(paths) => {
                    {
                        let mut guard = shared.lock().unwrap();
                        let mut added_any = false;
                        for p in &paths {
                            if add_manual_target(&mut guard.data, p).is_ok() {
                                added_any = true;
                            }
                        }
                        if added_any {
                            let synced = sync_mirror_if_enabled(&guard.data).unwrap_or(0);
                            guard.status_message = format!(
                                "Added {} dropped item(s), synced {} shortcuts",
                                paths.len(),
                                synced
                            );
                            save_data(&guard.data_path, &guard.data);
                        }
                    }
                    if let Some(ref ti) = tray_icon {
                        let new_menu = {
                            let guard = shared.lock().unwrap();
                            build_tray_menu(&guard.data, &guard.statuses)
                        };
                        ti.set_menu(Some(Box::new(new_menu)));
                    }
                    push_ui_state(&webview, &shared);
                }

                UserEvent::MonitorReady {
                    statuses: new_statuses,
                    external_services: new_external,
                } => {
                    let changed = {
                        let mut guard = shared.lock().unwrap();
                        let mut diff = new_statuses.len() != guard.statuses.len()
                            || new_external != guard.external_services;
                        if !diff {
                            for (k, st) in &new_statuses {
                                if guard
                                    .statuses
                                    .get(k)
                                    .map(|old| old != st)
                                    .unwrap_or(true)
                                {
                                    diff = true;
                                    break;
                                }
                            }
                        }
                        guard.statuses = new_statuses;
                        guard.external_services = new_external;
                        diff
                    };
                    if changed {
                        if let Some(ref ti) = tray_icon {
                            let new_menu = {
                                let guard = shared.lock().unwrap();
                                build_tray_menu(&guard.data, &guard.statuses)
                            };
                            ti.set_menu(Some(Box::new(new_menu)));
                        }
                        push_ui_state(&webview, &shared);
                    }
                }

                UserEvent::SyncDone {
                    data,
                    statuses,
                    external_services,
                    message,
                    sync_epoch,
                } => {
                    {
                        let mut guard = shared.lock().unwrap();
                        guard.data = data;
                        guard.statuses = statuses;
                        guard.external_services = external_services;
                        guard.syncing = false;
                        guard.last_sync_epoch = sync_epoch;
                        guard.status_message = message.clone();
                        guard.toast_seq += 1;
                        guard.toast_message = message;
                        save_data(&guard.data_path, &guard.data);
                    }
                    if let Some(ref ti) = tray_icon {
                        let new_menu = {
                            let guard = shared.lock().unwrap();
                            build_tray_menu(&guard.data, &guard.statuses)
                        };
                        ti.set_menu(Some(Box::new(new_menu)));
                    }
                    push_ui_state(&webview, &shared);
                }

                UserEvent::MenuAction(id) => {
                    if id == "tray:show" {
                        show_and_focus_window(&window, &webview, &shared, &monitor);
                    } else if id == "tray:sync" {
                        if spawn_background_sync(
                            proxy.clone(),
                            Arc::clone(&shared),
                            Arc::clone(&monitor),
                        ) {
                            push_ui_state(&webview, &shared);
                        }
                    } else if id == "tray:mirror" {
                        let dir = shared.lock().unwrap().data.settings.shortcut_mirror_dir.clone();
                        if !dir.is_empty() {
                            let _ = fs::create_dir_all(&dir);
                            open_folder_and_select(&dir);
                        }
                    } else if id == "tray:quit" {
                        let _ = fs::remove_file(&lock_path);
                        *control_flow = ControlFlow::Exit;
                    } else if let Some(script_id) = id.strip_prefix("launch:") {
                        handle_launch_by_id(script_id, None, &shared, &monitor);
                        push_ui_state(&webview, &shared);
                        spawn_delayed_monitor_probes(
                            proxy.clone(),
                            Arc::clone(&shared),
                            Arc::clone(&monitor),
                        );
                    }
                }

                UserEvent::IpcMessage(raw) => {
                    let Ok(cmd) = serde_json::from_str::<UiCommand>(&raw) else {
                        return;
                    };
                    match cmd.action.as_str() {
                        "ready" => {
                            push_ui_state(&webview, &shared);
                        }
                        "sync" => {
                            if spawn_background_sync(
                                proxy.clone(),
                                Arc::clone(&shared),
                                Arc::clone(&monitor),
                            ) {
                                push_ui_state(&webview, &shared);
                            }
                        }
                        "add_workspace_dir" => {
                            if let Some(dir) = cmd.payload.get("dir").and_then(|v| v.as_str()) {
                                let p = Path::new(dir);
                                if p.is_dir() {
                                    let norm = normalize_path_str(p);
                                    {
                                        let mut guard = shared.lock().unwrap();
                                        if !guard
                                            .data
                                            .settings
                                            .workspace_roots
                                            .iter()
                                            .any(|r| r.eq_ignore_ascii_case(&norm))
                                        {
                                            guard.data.settings.workspace_roots.push(norm);
                                        }
                                        save_data(&guard.data_path, &guard.data);
                                    }
                                    if spawn_background_sync(
                                        proxy.clone(),
                                        Arc::clone(&shared),
                                        Arc::clone(&monitor),
                                    ) {
                                        push_ui_state(&webview, &shared);
                                    }
                                }
                            }
                        }
                        "stop_pid" => {
                            if let Some(pid_val) = cmd.payload.get("pid").and_then(|v| v.as_u64()) {
                                let res = stop_pid(pid_val as u32);
                                {
                                    let mut guard = shared.lock().unwrap();
                                    let msg = match res {
                                        Ok(()) => format!("Stopped PID {}", pid_val),
                                        Err(e) => format!("Stop failed: {}", e),
                                    };
                                    guard.status_message = msg.clone();
                                    guard.toast_seq += 1;
                                    guard.toast_message = msg;
                                }
                                push_ui_state(&webview, &shared);
                                spawn_delayed_monitor_probes(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                );
                            }
                        }
                        "pick_add_folder" => {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                let norm = normalize_path_str(&folder);
                                {
                                    let mut guard = shared.lock().unwrap();
                                    if !guard
                                        .data
                                        .settings
                                        .workspace_roots
                                        .iter()
                                        .any(|r| r.eq_ignore_ascii_case(&norm))
                                    {
                                        guard.data.settings.workspace_roots.push(norm);
                                    }
                                    save_data(&guard.data_path, &guard.data);
                                }
                                if spawn_background_sync(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                ) {
                                    push_ui_state(&webview, &shared);
                                }
                            }
                        }
                        "pick_add_file" => {
                            if let Some(file) = rfd::FileDialog::new()
                                .add_filter("Batch Scripts", &["bat", "cmd"])
                                .pick_file()
                            {
                                {
                                    let mut guard = shared.lock().unwrap();
                                    let _ = add_manual_target(&mut guard.data, &file);
                                    let _ = sync_mirror_if_enabled(&guard.data);
                                    let msg = format!("Added {}", file.display());
                                    guard.status_message = msg.clone();
                                    guard.toast_seq += 1;
                                    guard.toast_message = msg;
                                    save_data(&guard.data_path, &guard.data);
                                }
                                if let Some(ref ti) = tray_icon {
                                    let new_menu = {
                                        let guard = shared.lock().unwrap();
                                        build_tray_menu(&guard.data, &guard.statuses)
                                    };
                                    ti.set_menu(Some(Box::new(new_menu)));
                                }
                                push_ui_state(&webview, &shared);
                                spawn_delayed_monitor_probes(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                );
                            }
                        }
                        "pick_root_for_settings" => {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                let norm = normalize_path_str(&folder);
                                if let Ok(js_arg) = serde_json::to_string(&norm) {
                                    let _ = webview.evaluate_script(&format!(
                                        "if(window.__bathubAddDraftRoot){{window.__bathubAddDraftRoot({});}}",
                                        js_arg
                                    ));
                                }
                            }
                        }
                        "pick_mirror_dir" => {
                            if let Some(folder) = rfd::FileDialog::new().pick_folder() {
                                let norm = normalize_path_str(&folder);
                                if let Ok(js_arg) = serde_json::to_string(&norm) {
                                    let _ = webview.evaluate_script(&format!(
                                        "if(window.__bathubSetMirrorDir){{window.__bathubSetMirrorDir({});}}",
                                        js_arg
                                    ));
                                }
                            }
                        }
                        "open_mirror" => {
                            let dir = shared.lock().unwrap().data.settings.shortcut_mirror_dir.clone();
                            if !dir.is_empty() {
                                let _ = fs::create_dir_all(&dir);
                                open_folder_and_select(&dir);
                            }
                        }
                        "launch" => {
                            if let Some(id) = cmd.payload.get("id").and_then(|v| v.as_str()) {
                                let silent_ov =
                                    cmd.payload.get("silent_override").and_then(|v| v.as_bool());
                                handle_launch_by_id(id, silent_ov, &shared, &monitor);
                                push_ui_state(&webview, &shared);
                                spawn_delayed_monitor_probes(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                );
                            }
                        }
                        "launch_path" => {
                            if let Some(path) = cmd.payload.get("path").and_then(|v| v.as_str()) {
                                let silent = cmd
                                    .payload
                                    .get("silent")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let admin = cmd
                                    .payload
                                    .get("requires_admin")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                let res = launch_script(path, silent, admin);
                                let mut guard = shared.lock().unwrap();
                                let msg = match res {
                                    Ok(_) => format!("Executed: {}", path),
                                    Err(e) => format!("Failed: {}", e),
                                };
                                guard.status_message = msg.clone();
                                guard.toast_seq += 1;
                                guard.toast_message = msg;
                                push_ui_state(&webview, &shared);
                                spawn_delayed_monitor_probes(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                );
                            }
                        }
                        "stop" => {
                            if let Some(id) = cmd.payload.get("id").and_then(|v| v.as_str()) {
                                let entry_opt = shared
                                    .lock()
                                    .unwrap()
                                    .data
                                    .entries
                                    .iter()
                                    .find(|e| e.id == id)
                                    .cloned();
                                if let Some(entry) = entry_opt {
                                    let (new_st, new_ext) = {
                                        let mut mon = monitor.lock().unwrap();
                                        let snap = mon.snapshot();
                                        let _ = stop_service(&entry, &snap, &mon);
                                        std::thread::sleep(Duration::from_millis(250));
                                        let entries_snapshot =
                                            shared.lock().unwrap().data.entries.clone();
                                        evaluate_all_statuses(&mut mon, &entries_snapshot)
                                    };
                                    let mut guard = shared.lock().unwrap();
                                    guard.statuses = new_st;
                                    guard.external_services = new_ext;
                                    let msg = format!("Stopped: {}", entry.display_name);
                                    guard.status_message = msg.clone();
                                    guard.toast_seq += 1;
                                    guard.toast_message = msg;
                                }
                                push_ui_state(&webview, &shared);
                                spawn_delayed_monitor_probes(
                                    proxy.clone(),
                                    Arc::clone(&shared),
                                    Arc::clone(&monitor),
                                );
                            }
                        }
                        "toggle_pin" => {
                            if let Some(id) = cmd.payload.get("id").and_then(|v| v.as_str()) {
                                let mut guard = shared.lock().unwrap();
                                if let Some(e) = guard.data.entries.iter_mut().find(|e| e.id == id) {
                                    e.pinned = !e.pinned;
                                }
                                save_data(&guard.data_path, &guard.data);
                            }
                            push_ui_state(&webview, &shared);
                        }
                        "open_terminal" => {
                            if let Some(dir) = cmd.payload.get("dir").and_then(|v| v.as_str()) {
                                let _ = open_in_terminal(dir);
                            }
                        }
                        "open_folder" => {
                            if let Some(path) = cmd.payload.get("path").and_then(|v| v.as_str()) {
                                open_folder_and_select(path);
                            }
                        }
                        "update_entry" => {
                            if let Some(id) = cmd.payload.get("id").and_then(|v| v.as_str()) {
                                {
                                    let mut guard = shared.lock().unwrap();
                                    if let Some(e) =
                                        guard.data.entries.iter_mut().find(|e| e.id == id)
                                    {
                                        if let Some(n) =
                                            cmd.payload.get("display_name").and_then(|v| v.as_str())
                                        {
                                            if !n.is_empty() {
                                                e.display_name = n.to_string();
                                            }
                                        }
                                        if let Some(d) =
                                            cmd.payload.get("description").and_then(|v| v.as_str())
                                        {
                                            e.description = d.to_string();
                                        }
                                        if let Some(c) =
                                            cmd.payload.get("category").and_then(|v| v.as_str())
                                        {
                                            e.category = c.to_string();
                                        }
                                        if let Some(arr) =
                                            cmd.payload.get("ports").and_then(|v| v.as_array())
                                        {
                                            e.ports = arr
                                                .iter()
                                                .filter_map(|v| v.as_u64().map(|n| n as u16))
                                                .collect();
                                        }
                                        if let Some(h) =
                                            cmd.payload.get("hidden").and_then(|v| v.as_bool())
                                        {
                                            e.hidden = h;
                                        }
                                        e.user_edited = true;
                                    }
                                    let _ = sync_mirror_if_enabled(&guard.data);
                                    guard.status_message = "Entry updated".to_string();
                                    save_data(&guard.data_path, &guard.data);
                                }
                                if let Some(ref ti) = tray_icon {
                                    let new_menu = {
                                        let guard = shared.lock().unwrap();
                                        build_tray_menu(&guard.data, &guard.statuses)
                                    };
                                    ti.set_menu(Some(Box::new(new_menu)));
                                }
                                push_ui_state(&webview, &shared);
                            }
                        }
                        "reset_entry" => {
                            if let Some(id) = cmd.payload.get("id").and_then(|v| v.as_str()) {
                                {
                                    let mut guard = shared.lock().unwrap();
                                    if let Some(e) =
                                        guard.data.entries.iter_mut().find(|e| e.id == id)
                                    {
                                        e.user_edited = false;
                                        e.hidden = false;
                                    }
                                    sync_workspaces(&mut guard.data);
                                    let _ = sync_mirror_if_enabled(&guard.data);
                                    guard.status_message = "Reset to auto-detected metadata".to_string();
                                    save_data(&guard.data_path, &guard.data);
                                }
                                push_ui_state(&webview, &shared);
                            }
                        }
                        "save_settings" => {
                            {
                                let mut guard = shared.lock().unwrap();
                                if let Some(arr) = cmd
                                    .payload
                                    .get("workspace_roots")
                                    .and_then(|v| v.as_array())
                                {
                                    guard.data.settings.workspace_roots = arr
                                        .iter()
                                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                                        .collect();
                                }
                                if let Some(b) =
                                    cmd.payload.get("mirror_enabled").and_then(|v| v.as_bool())
                                {
                                    guard.data.settings.mirror_enabled = b;
                                }
                                if let Some(s) = cmd
                                    .payload
                                    .get("shortcut_mirror_dir")
                                    .and_then(|v| v.as_str())
                                {
                                    guard.data.settings.shortcut_mirror_dir = s.to_string();
                                }
                                if let Some(b) = cmd
                                    .payload
                                    .get("context_menu_enabled")
                                    .and_then(|v| v.as_bool())
                                {
                                    guard.data.settings.context_menu_enabled = b;
                                    let ctx_label = if guard.data.settings.language == "zh-CN" {
                                        "\u{6536}\u{5165} BatHub \u{542f}\u{52a8}\u{4e2d}\u{5fc3}"
                                    } else {
                                        "Add to BatHub"
                                    };
                                    let _ = win_integration::set_context_menu(b, ctx_label);
                                }
                                if let Some(b) =
                                    cmd.payload.get("run_on_startup").and_then(|v| v.as_bool())
                                {
                                    guard.data.settings.run_on_startup = b;
                                    let _ = win_integration::set_run_on_startup(b);
                                }
                                if let Some(b) = cmd
                                    .payload
                                    .get("silent_run_default")
                                    .and_then(|v| v.as_bool())
                                {
                                    guard.data.settings.silent_run_default = b;
                                }
                                if let Some(lang) =
                                    cmd.payload.get("language").and_then(|v| v.as_str())
                                {
                                    guard.data.settings.language = lang.to_string();
                                }
                                save_data(&guard.data_path, &guard.data);
                            }
                            if spawn_background_sync(
                                proxy.clone(),
                                Arc::clone(&shared),
                                Arc::clone(&monitor),
                            ) {
                                push_ui_state(&webview, &shared);
                            }
                        }
                        "import_legacy" => {
                            {
                                let mut guard = shared.lock().unwrap();
                                let p = Path::new(LEGACY_LAUNCHERHUB_JSON);
                                let mut entries = std::mem::take(&mut guard.data.entries);
                                let res = win_integration::import_legacy_launcherhub(p, &mut entries);
                                guard.data.entries = entries;
                                match res {
                                    Ok(n) => {
                                        let _ = sync_mirror_if_enabled(&guard.data);
                                        guard.status_message =
                                            format!("Imported {} legacy LauncherHub items", n);
                                        save_data(&guard.data_path, &guard.data);
                                    }
                                    Err(e) => {
                                        guard.status_message = format!("Import failed: {}", e);
                                    }
                                }
                            }
                            if let Some(ref ti) = tray_icon {
                                let new_menu = {
                                    let guard = shared.lock().unwrap();
                                    build_tray_menu(&guard.data, &guard.statuses)
                                };
                                ti.set_menu(Some(Box::new(new_menu)));
                            }
                            push_ui_state(&webview, &shared);
                        }
                        _ => {}
                    }
                }
            },
            _ => {}
        }
    });
}
