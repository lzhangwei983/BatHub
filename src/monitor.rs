use crate::model::{ExternalService, RuntimeStatus, ScriptEntry};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::windows::process::CommandExt;
use std::path::Path;
use std::process::Command;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
use windows::Win32::Foundation::ERROR_INSUFFICIENT_BUFFER;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, MIB_TCP6TABLE_OWNER_PID, MIB_TCPTABLE_OWNER_PID,
    TCP_TABLE_OWNER_PID_LISTENER,
};
use windows::Win32::Networking::WinSock::{AF_INET, AF_INET6};

const CREATE_NO_WINDOW: u32 = 0x0800_0000;
const CREATE_NEW_CONSOLE: u32 = 0x0000_0010;

#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub port: u16,
    pub pid: u32,
    pub bind_addr: String,
}

#[derive(Debug, Clone)]
pub struct ProcRecord {
    pub pid: u32,
    pub parent_pid: Option<u32>,
    pub name_lower: String,
    pub cmd_lower: String,
    pub cwd_lower: String,
    pub exe_lower: String,
    pub raw_name: String,
    pub raw_cmd: String,
    pub raw_cwd: String,
    pub raw_exe: String,
}

pub struct ProcessSnapshot {
    pub listeners: Vec<ListeningPort>,
    pub port_to_pids: HashMap<u16, Vec<u32>>,
    pub procs: Vec<ProcRecord>,
    pub proc_by_pid: HashMap<u32, usize>,
}

fn query_listening_tcp_v4(out: &mut Vec<ListeningPort>) {
    let mut size: u32 = 0;
    unsafe {
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if (res != ERROR_INSUFFICIENT_BUFFER.0 && res != 0) || size == 0 {
            return;
        }
        let len_u32 = ((size as usize) + 3) / 4 + 2;
        let mut buffer = vec![0u32; len_u32];
        let res2 = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if res2 != 0 {
            return;
        }
        let table = &*(buffer.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            if port > 0 {
                let ip = Ipv4Addr::from(u32::from_be(row.dwLocalAddr));
                out.push(ListeningPort {
                    port,
                    pid: row.dwOwningPid,
                    bind_addr: ip.to_string(),
                });
            }
        }
    }
}

fn query_listening_tcp_v6(out: &mut Vec<ListeningPort>) {
    let mut size: u32 = 0;
    unsafe {
        let res = GetExtendedTcpTable(
            None,
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if (res != ERROR_INSUFFICIENT_BUFFER.0 && res != 0) || size == 0 {
            return;
        }
        let len_u32 = ((size as usize) + 3) / 4 + 2;
        let mut buffer = vec![0u32; len_u32];
        let res2 = GetExtendedTcpTable(
            Some(buffer.as_mut_ptr() as *mut _),
            &mut size,
            false,
            AF_INET6.0 as u32,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        );
        if res2 != 0 {
            return;
        }
        let table = &*(buffer.as_ptr() as *const MIB_TCP6TABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        for row in rows {
            let port = u16::from_be(row.dwLocalPort as u16);
            if port > 0 {
                let ip = Ipv6Addr::from(row.ucLocalAddr);
                out.push(ListeningPort {
                    port,
                    pid: row.dwOwningPid,
                    bind_addr: format!("[{}]", ip),
                });
            }
        }
    }
}

fn query_listening_tcp_ports() -> (Vec<ListeningPort>, HashMap<u16, Vec<u32>>) {
    let mut listeners = Vec::new();
    query_listening_tcp_v4(&mut listeners);
    query_listening_tcp_v6(&mut listeners);

    let mut map: HashMap<u16, Vec<u32>> = HashMap::new();
    for item in &listeners {
        let entry = map.entry(item.port).or_default();
        if !entry.contains(&item.pid) {
            entry.push(item.pid);
        }
    }
    (listeners, map)
}

pub struct SystemMonitor {
    sys: System,
    launched_pids: HashMap<String, Vec<u32>>,
}

fn is_ignored_port(port: u16) -> bool {
    matches!(
        port,
        22 | 80
            | 135
            | 139
            | 443
            | 445
            | 1080
            | 1081
            | 2080
            | 3306
            | 3389
            | 5040
            | 5357
            | 5432
            | 6379
            | 7680
            | 7890
            | 7891
            | 7892
            | 7897
            | 9090
            | 10808
            | 10809
            | 27017
    )
}

fn is_collection_dir_name(dir_path: &str) -> bool {
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
            | "pythonproject"
    )
}

fn is_dev_runtime_name(name_lower: &str) -> bool {
    matches!(
        name_lower,
        "python.exe"
            | "pythonw.exe"
            | "node.exe"
            | "uv.exe"
            | "uvicorn.exe"
            | "deno.exe"
            | "bun.exe"
            | "ruby.exe"
            | "java.exe"
            | "javaw.exe"
            | "go.exe"
            | "php.exe"
            | "caddy.exe"
            | "nginx.exe"
    )
}

fn is_known_local_service_proc(name_lower: &str) -> bool {
    is_dev_runtime_name(name_lower)
        || matches!(
            name_lower,
            "ollama.exe"
                | "aw-server-rust.exe"
                | "aw-server.exe"
                | "llama-server.exe"
                | "alist.exe"
                | "frpc.exe"
                | "frps.exe"
                | "cloudflared.exe"
                | "redis-server.exe"
                | "mongod.exe"
                | "freqtrade.exe"
                | "opencode-token-observatory.exe"
                | "wechatdataanalysis.exe"
                | "scrcpy.exe"
        )
}

fn is_noisy_system_or_app_proc(name_lower: &str, exe_lower: &str) -> bool {
    if name_lower.is_empty()
        || matches!(
            name_lower,
            "system"
                | "svchost.exe"
                | "lsass.exe"
                | "services.exe"
                | "wininit.exe"
                | "spoolsv.exe"
                | "bathub.exe"
                | "antigravity.exe"
                | "language_server.exe"
                | "chrome.exe"
                | "msedge.exe"
                | "msedgewebview2.exe"
                | "firefox.exe"
                | "flclash.exe"
                | "flclashcore.exe"
                | "flclashhelperservice.exe"
                | "tailscaled.exe"
                | "tailscale-ipn.exe"
                | "hipsdaemon.exe"
                | "hipstray.exe"
                | "edrservice.exe"
                | "gameviewerserver.exe"
                | "gameviewerservice.exe"
                | "gcubridge.exe"
                | "nidiscsvc.exe"
                | "qoder cn.exe"
                | "weixin.exe"
                | "wechat.exe"
                | "telegram.exe"
                | "ollama app.exe"
        )
    {
        return true;
    }
    exe_lower.starts_with(r"c:\windows\")
        || exe_lower.contains(r"\windowsapps\")
        || exe_lower.contains(r"\steamlibrary\")
        || exe_lower.contains(r"\qoder cn\")
        || exe_lower.contains(r"\flclash\")
}

fn dir_has_bat_or_cmd(dir: &Path) -> bool {
    if !dir.is_dir() {
        return false;
    }
    if let Ok(entries) = fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                    if ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd") {
                        return true;
                    }
                }
            }
        }
    }
    false
}

fn extract_project_dir_from_proc(proc_rec: &ProcRecord) -> String {
    for token in proc_rec.raw_cmd.split_whitespace() {
        let cleaned = token.trim_matches(|c| c == '"' || c == '\'');
        let lower = cleaned.to_lowercase();
        if (lower.ends_with(".py")
            || lower.ends_with(".pyw")
            || lower.ends_with(".js")
            || lower.ends_with(".mjs")
            || lower.ends_with(".cjs")
            || lower.ends_with(".ts"))
            && cleaned.len() >= 5
            && cleaned.as_bytes().get(1) == Some(&b':')
        {
            let p = Path::new(cleaned);
            if let Some(parent) = p.parent() {
                if parent.is_dir() {
                    return parent.to_string_lossy().to_string();
                }
            }
        }
    }

    if !proc_rec.raw_cwd.is_empty() {
        let lower = proc_rec.cwd_lower.as_str();
        if !lower.starts_with(r"c:\windows") {
            let p = Path::new(&proc_rec.raw_cwd);
            if p.is_dir() {
                return proc_rec.raw_cwd.clone();
            }
        }
    }

    if !proc_rec.raw_exe.is_empty() {
        let p = Path::new(&proc_rec.raw_exe);
        if let Some(parent) = p.parent() {
            return parent.to_string_lossy().to_string();
        }
    }

    String::new()
}

fn find_suggested_bat_dir(project_dir: &str) -> Option<String> {
    if project_dir.is_empty() {
        return None;
    }
    let p = Path::new(project_dir);
    if dir_has_bat_or_cmd(p) {
        return Some(project_dir.to_string());
    }
    if let Some(parent) = p.parent() {
        let parent_str = parent.to_string_lossy().to_string();
        if parent_str.len() > 3 && !is_collection_dir_name(&parent_str) && dir_has_bat_or_cmd(parent)
        {
            return Some(parent_str);
        }
    }
    None
}

impl SystemMonitor {
    pub fn new() -> Self {
        Self {
            sys: System::new(),
            launched_pids: HashMap::new(),
        }
    }

    pub fn register_launched_pid(&mut self, entry_id: &str, pid: u32) {
        if pid <= 4 {
            return;
        }
        let list = self.launched_pids.entry(entry_id.to_string()).or_default();
        if !list.contains(&pid) {
            list.push(pid);
        }
    }

    pub fn snapshot(&mut self) -> ProcessSnapshot {
        self.sys.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::new()
                .with_cmd(UpdateKind::OnlyIfNotSet)
                .with_cwd(UpdateKind::OnlyIfNotSet)
                .with_exe(UpdateKind::OnlyIfNotSet),
        );

        let (listeners, port_to_pids) = query_listening_tcp_ports();
        let mut procs = Vec::new();
        let mut proc_by_pid = HashMap::new();

        for (pid, proc_info) in self.sys.processes() {
            let pid_u32 = pid.as_u32();
            let parent_pid = proc_info.parent().map(|p| p.as_u32());
            let raw_name = proc_info.name().to_string_lossy().to_string();
            let raw_cmd = proc_info
                .cmd()
                .iter()
                .map(|s| s.to_string_lossy())
                .collect::<Vec<_>>()
                .join(" ");
            let raw_cwd = proc_info
                .cwd()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let raw_exe = proc_info
                .exe()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let idx = procs.len();
            proc_by_pid.insert(pid_u32, idx);
            procs.push(ProcRecord {
                pid: pid_u32,
                parent_pid,
                name_lower: raw_name.to_lowercase(),
                cmd_lower: raw_cmd.to_lowercase(),
                cwd_lower: raw_cwd.to_lowercase(),
                exe_lower: raw_exe.to_lowercase(),
                raw_name,
                raw_cmd,
                raw_cwd,
                raw_exe,
            });
        }

        let snap = ProcessSnapshot {
            listeners,
            port_to_pids,
            procs,
            proc_by_pid,
        };
        self.reconcile_launched_pids(&snap);
        snap
    }

    fn reconcile_launched_pids(&mut self, snap: &ProcessSnapshot) {
        for pids in self.launched_pids.values_mut() {
            let mut next = Vec::new();
            let tracked_set: HashSet<u32> = pids.iter().copied().collect();
            for &pid in pids.iter() {
                if snap.proc_by_pid.contains_key(&pid) && !next.contains(&pid) {
                    next.push(pid);
                }
            }
            for proc_rec in &snap.procs {
                if let Some(ppid) = proc_rec.parent_pid {
                    if tracked_set.contains(&ppid)
                        && proc_rec.name_lower != "conhost.exe"
                        && !next.contains(&proc_rec.pid)
                    {
                        next.push(proc_rec.pid);
                    }
                }
            }
            *pids = next;
        }
        self.launched_pids.retain(|_, v| !v.is_empty());
    }

    pub fn evaluate_entry(&self, snap: &ProcessSnapshot, entry: &ScriptEntry) -> RuntimeStatus {
        if let Some(tracked) = self.launched_pids.get(&entry.id) {
            let alive: Vec<u32> = tracked
                .iter()
                .copied()
                .filter(|pid| snap.proc_by_pid.contains_key(pid))
                .collect();
            if !alive.is_empty() {
                let mut matched_port = None;
                for &port in &entry.ports {
                    if !is_ignored_port(port) && snap.port_to_pids.contains_key(&port) {
                        matched_port = Some(port);
                        break;
                    }
                }
                let hint = if let Some(pt) = matched_port {
                    format!("port:{}", pt)
                } else {
                    format!("pid:{}", alive[0])
                };
                return RuntimeStatus {
                    id: entry.id.clone(),
                    running: true,
                    matched_port,
                    pids: alive,
                    status_hint: hint,
                };
            }
        }

        if entry.role != "service" {
            return RuntimeStatus {
                id: entry.id.clone(),
                running: false,
                matched_port: None,
                pids: Vec::new(),
                status_hint: "action".to_string(),
            };
        }

        for &port in &entry.ports {
            if is_ignored_port(port) {
                continue;
            }
            if let Some(pids) = snap.port_to_pids.get(&port) {
                if !pids.is_empty() {
                    return RuntimeStatus {
                        id: entry.id.clone(),
                        running: true,
                        matched_port: Some(port),
                        pids: pids.clone(),
                        status_hint: format!("port:{}", port),
                    };
                }
            }
        }

        for pname in &entry.process_names {
            let target = pname.to_lowercase();
            let matched: Vec<u32> = snap
                .procs
                .iter()
                .filter(|p| p.name_lower == target)
                .map(|p| p.pid)
                .collect();
            if !matched.is_empty() {
                return RuntimeStatus {
                    id: entry.id.clone(),
                    running: true,
                    matched_port: None,
                    pids: matched,
                    status_hint: format!("proc:{}", pname),
                };
            }
        }

        let bat_lower = entry.path.to_lowercase();
        let bat_slash = bat_lower.replace('\\', "/");
        let matched_bat: Vec<u32> = snap
            .procs
            .iter()
            .filter(|p| {
                p.name_lower != "bathub.exe"
                    && (p.cmd_lower.contains(&bat_lower) || p.cmd_lower.contains(&bat_slash))
            })
            .map(|p| p.pid)
            .collect();
        if !matched_bat.is_empty() {
            let hint = format!("pid:{}", matched_bat[0]);
            return RuntimeStatus {
                id: entry.id.clone(),
                running: true,
                matched_port: None,
                pids: matched_bat,
                status_hint: hint,
            };
        }

        for kw in &entry.keywords {
            let kw_lower = kw.to_lowercase();
            if !kw_lower.contains('\\') && !kw_lower.contains('/') {
                continue;
            }
            let kw_slash = kw_lower.replace('\\', "/");
            let matched: Vec<u32> = snap
                .procs
                .iter()
                .filter(|p| {
                    p.name_lower != "bathub.exe"
                        && (p.cmd_lower.contains(&kw_lower)
                            || p.cmd_lower.contains(&kw_slash)
                            || p.exe_lower.contains(&kw_lower))
                })
                .map(|p| p.pid)
                .collect();
            if !matched.is_empty() {
                let hint = format!("pid:{}", matched[0]);
                return RuntimeStatus {
                    id: entry.id.clone(),
                    running: true,
                    matched_port: None,
                    pids: matched,
                    status_hint: hint,
                };
            }
        }

        if entry.ports.is_empty()
            && entry.project_dir.len() >= 10
            && !is_collection_dir_name(&entry.project_dir)
        {
            let dir_lower = entry.project_dir.to_lowercase();
            let dir_slash = dir_lower.replace('\\', "/");
            let matched: Vec<u32> = snap
                .procs
                .iter()
                .filter(|p| {
                    is_dev_runtime_name(&p.name_lower)
                        && (p.cmd_lower.contains(&dir_lower)
                            || p.cmd_lower.contains(&dir_slash)
                            || p.cwd_lower == dir_lower
                            || p.cwd_lower.starts_with(&format!("{}\\", dir_lower))
                            || p.exe_lower.starts_with(&format!("{}\\", dir_lower)))
                })
                .map(|p| p.pid)
                .collect();
            if !matched.is_empty() {
                let hint = format!("pid:{}", matched[0]);
                return RuntimeStatus {
                    id: entry.id.clone(),
                    running: true,
                    matched_port: None,
                    pids: matched,
                    status_hint: hint,
                };
            }
        }

        RuntimeStatus {
            id: entry.id.clone(),
            running: false,
            matched_port: None,
            pids: Vec::new(),
            status_hint: "idle".to_string(),
        }
    }

    pub fn detect_unmanaged_services(
        &self,
        snap: &ProcessSnapshot,
        entries: &[ScriptEntry],
        statuses: &HashMap<String, RuntimeStatus>,
    ) -> Vec<ExternalService> {
        let mut managed_pids: HashSet<u32> = HashSet::new();
        let mut managed_ports: HashSet<u16> = HashSet::new();
        for e in entries {
            if let Some(st) = statuses.get(&e.id) {
                if st.running {
                    for &pid in &st.pids {
                        managed_pids.insert(pid);
                    }
                    if let Some(pt) = st.matched_port {
                        managed_ports.insert(pt);
                    }
                }
            }
        }

        let mut seen_key: HashSet<(u32, u16)> = HashSet::new();
        let mut out = Vec::new();

        for l in &snap.listeners {
            if l.pid <= 4 || l.port < 1024 || l.port >= 49152 || is_ignored_port(l.port) {
                continue;
            }
            if managed_pids.contains(&l.pid) || managed_ports.contains(&l.port) {
                continue;
            }
            if !seen_key.insert((l.pid, l.port)) {
                continue;
            }
            let Some(&idx) = snap.proc_by_pid.get(&l.pid) else {
                continue;
            };
            let proc_rec = &snap.procs[idx];
            if is_noisy_system_or_app_proc(&proc_rec.name_lower, &proc_rec.exe_lower) {
                continue;
            }
            let is_user_drive = proc_rec.cmd_lower.contains("d:\\")
                || proc_rec.cmd_lower.contains("e:\\")
                || proc_rec.exe_lower.starts_with("d:\\")
                || proc_rec.exe_lower.starts_with("e:\\");
            if !is_known_local_service_proc(&proc_rec.name_lower) && !is_user_drive {
                continue;
            }

            let project_dir = extract_project_dir_from_proc(proc_rec);
            let suggested_bat_dir = find_suggested_bat_dir(&project_dir);
            let cmd_display = if proc_rec.raw_cmd.is_empty() {
                proc_rec.raw_exe.clone()
            } else {
                proc_rec.raw_cmd.clone()
            };

            out.push(ExternalService {
                pid: l.pid,
                process_name: proc_rec.raw_name.clone(),
                port: l.port,
                bind_addr: l.bind_addr.clone(),
                cmdline: cmd_display,
                project_dir,
                suggested_bat_dir,
            });
        }

        out.sort_by_key(|s| (s.port, s.pid));
        out
    }
}

pub fn launch_script(
    path_str: &str,
    silent: bool,
    run_as_admin: bool,
) -> Result<Option<u32>, String> {
    let path = Path::new(path_str);
    if !path.exists() {
        return Err(format!("Script not found: {}", path_str));
    }
    let work_dir = path.parent().unwrap_or_else(|| Path::new("."));

    if run_as_admin {
        let escaped_path = path_str.replace('\'', "''");
        let escaped_dir = work_dir.to_string_lossy().replace('\'', "''");
        let ps_cmd = format!(
            "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','\"{}\"' -WorkingDirectory '{}' -Verb RunAs",
            escaped_path, escaped_dir
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &ps_cmd])
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?;
        return Ok(None);
    }

    let child = if silent {
        Command::new("cmd.exe")
            .args(["/c", path_str])
            .current_dir(work_dir)
            .creation_flags(CREATE_NO_WINDOW)
            .spawn()
            .map_err(|e| e.to_string())?
    } else {
        Command::new("cmd.exe")
            .args(["/c", path_str])
            .current_dir(work_dir)
            .creation_flags(CREATE_NEW_CONSOLE)
            .spawn()
            .map_err(|e| e.to_string())?
    };

    Ok(Some(child.id()))
}

pub fn open_in_terminal(dir_str: &str) -> Result<(), String> {
    let dir = Path::new(dir_str);
    if !dir.exists() {
        return Err(format!("Directory not found: {}", dir_str));
    }
    Command::new("cmd.exe")
        .args(["/k", "cd", "/d", dir_str])
        .current_dir(dir)
        .creation_flags(CREATE_NEW_CONSOLE)
        .spawn()
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn open_folder_and_select(path_str: &str) {
    let p = Path::new(path_str);
    if p.is_file() {
        let arg = format!("/select,\"{}\"", path_str);
        let _ = Command::new("explorer.exe").raw_arg(&arg).spawn();
    } else if p.is_dir() {
        let _ = Command::new("explorer.exe").arg(path_str).spawn();
    } else if let Some(parent) = p.parent() {
        if parent.exists() {
            let _ = Command::new("explorer.exe").arg(parent).spawn();
        }
    }
}

pub fn stop_pid(pid_val: u32) -> Result<(), String> {
    if pid_val <= 4 {
        return Err("Refusing to stop system PID".to_string());
    }
    let _ = Command::new("taskkill.exe")
        .args(["/F", "/T", "/PID", &pid_val.to_string()])
        .creation_flags(CREATE_NO_WINDOW)
        .status()
        .map_err(|e| e.to_string())?;
    Ok(())
}

pub fn stop_service(
    entry: &ScriptEntry,
    snap: &ProcessSnapshot,
    monitor: &SystemMonitor,
) -> Result<(), String> {
    if let Some(stop_path) = &entry.stop_script {
        let sp = Path::new(stop_path);
        if sp.exists() {
            let work_dir = sp.parent().unwrap_or_else(|| Path::new("."));
            let _ = Command::new("cmd.exe")
                .args(["/c", stop_path])
                .current_dir(work_dir)
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }

    let status = monitor.evaluate_entry(snap, entry);
    let mut pids_to_kill: HashSet<u32> = status.pids.into_iter().collect();

    for &port in &entry.ports {
        if let Some(pids) = snap.port_to_pids.get(&port) {
            for &pid in pids {
                pids_to_kill.insert(pid);
            }
        }
    }

    let mut sys = System::new();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    for pid_val in pids_to_kill {
        if pid_val <= 4 {
            continue;
        }
        let target_pid = Pid::from_u32(pid_val);
        if sys.process(target_pid).is_some() {
            let _ = Command::new("taskkill.exe")
                .args(["/F", "/T", "/PID", &pid_val.to_string()])
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn test_live_tcp_listener_ipv4_and_ipv6_detection() {
        let listener_v4 = TcpListener::bind("127.0.0.1:0").expect("bind v4");
        let port_v4 = listener_v4.local_addr().unwrap().port();

        let listener_v6 = TcpListener::bind("[::1]:0").ok();
        let port_v6 = listener_v6.as_ref().map(|l| l.local_addr().unwrap().port());

        let mut mon = SystemMonitor::new();
        let snap = mon.snapshot();

        let cur_pid = std::process::id();
        let pids_v4 = snap.port_to_pids.get(&port_v4).expect("v4 port should be detected");
        assert!(pids_v4.contains(&cur_pid));

        if let Some(p6) = port_v6 {
            let pids_v6 = snap.port_to_pids.get(&p6).expect("v6 port should be detected");
            assert!(pids_v6.contains(&cur_pid));
        }

        drop(listener_v4);
        drop(listener_v6);
    }

    #[test]
    fn test_live_unmanaged_services_filter_is_clean() {
        let mut mon = SystemMonitor::new();
        let snap = mon.snapshot();
        let external = mon.detect_unmanaged_services(&snap, &[], &HashMap::new());
        println!("DETECTED_EXTERNAL_COUNT={}", external.len());
        for svc in &external {
            println!(
                "  EXT: port={} pid={} proc={} dir={} bat_dir={:?} cmd={}",
                svc.port,
                svc.pid,
                svc.process_name,
                svc.project_dir,
                svc.suggested_bat_dir,
                svc.cmdline
            );
            assert!(svc.port >= 1024 && svc.port < 49152);
            assert!(!svc.process_name.eq_ignore_ascii_case("svchost.exe"));
            assert!(!svc.process_name.eq_ignore_ascii_case("bathub.exe"));
        }
    }
}
