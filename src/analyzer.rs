use encoding_rs::{GBK, UTF_8};
use regex::Regex;
use std::collections::HashSet;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

#[derive(Debug, Clone)]
pub struct AnalyzedScript {
    pub display_name: String,
    pub description: String,
    pub category: String,
    pub role: String,
    pub ports: Vec<u16>,
    pub keywords: Vec<String>,
    pub process_names: Vec<String>,
    pub requires_admin: bool,
    pub project_name: String,
}

pub fn decode_windows_text(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).to_string();
    }
    if let Ok(s) = std::str::from_utf8(bytes) {
        return s.to_string();
    }
    let (cow, _, had_errors) = GBK.decode(bytes);
    if !had_errors {
        return cow.into_owned();
    }
    let (utf8_cow, _, _) = UTF_8.decode(bytes);
    utf8_cow.into_owned()
}

pub fn read_text_lossy_limit(path: &Path, max_bytes: usize) -> Option<String> {
    let data = fs::read(path).ok()?;
    let slice = if data.len() > max_bytes {
        &data[..max_bytes]
    } else {
        &data[..]
    };
    Some(decode_windows_text(slice))
}

fn is_generic_script_stem(stem_lower: &str) -> bool {
    matches!(
        stem_lower,
        "start"
            | "run"
            | "launch"
            | "launcher"
            | "main"
            | "serve"
            | "server"
            | "dev"
            | "app"
            | "webui"
            | "go"
            | "boot"
            | "up"
            | "start-win"
            | "start_win"
            | "run_app"
            | "start_app"
            | "\u{542f}\u{52a8}"
            | "\u{4e00}\u{952e}\u{542f}\u{52a8}"
            | "\u{8fd0}\u{884c}"
    )
}

fn detect_role(stem_lower: &str, content_lower: &str) -> String {
    let stop_tokens = [
        "stop",
        "kill",
        "shutdown",
        "terminate",
        "0_stop",
        "\u{505c}\u{6b62}",
        "\u{5173}\u{95ed}",
        "\u{9000}\u{51fa}",
    ];
    if stop_tokens.iter().any(|t| stem_lower.contains(t)) {
        return "stop".to_string();
    }

    let action_tokens = [
        "install",
        "setup",
        "init",
        "check",
        "verify",
        "test",
        "dry_test",
        "dry-test",
        "fix",
        "repair",
        "clean",
        "purge",
        "build",
        "compile",
        "plot",
        "download",
        "backtest",
        "login",
        "auth",
        "autostart",
        "config",
        "backup",
        "reset",
        "status",
        "ocr",
        "flash",
        "\u{5b89}\u{88c5}",
        "\u{68c0}\u{67e5}",
        "\u{4fee}\u{590d}",
        "\u{6e05}\u{7406}",
        "\u{5f00}\u{673a}\u{81ea}\u{542f}",
        "\u{91cd}\u{7f6e}",
        "\u{72b6}\u{6001}",
        "\u{70e7}\u{5f55}",
        "\u{56de}\u{6d4b}",
        "\u{4e0b}\u{8f7d}",
    ];
    if action_tokens.iter().any(|t| stem_lower.contains(t)) {
        return "action".to_string();
    }

    if content_lower.contains("taskkill")
        && !content_lower.contains("python")
        && !content_lower.contains("node")
        && !content_lower.contains("uvicorn")
        && !content_lower.contains("start ")
    {
        return "stop".to_string();
    }

    "service".to_string()
}

fn extract_title_and_comments(content: &str) -> (Option<String>, Option<String>) {
    let mut title: Option<String> = None;
    let mut desc_lines: Vec<String> = Vec::new();

    for raw_line in content.lines().take(60) {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        let lower = line.to_lowercase();
        if lower.starts_with("@echo off") || lower == "echo off" || lower.starts_with("chcp ") {
            continue;
        }
        if lower.starts_with("title ") {
            let t = line[6..].trim().trim_matches('"').trim();
            if !t.is_empty() && !t.starts_with('%') {
                title = Some(t.to_string());
            }
            continue;
        }
        if lower.starts_with("rem ") || line.starts_with("::") {
            let cleaned = if lower.starts_with("rem ") {
                line[4..].trim()
            } else {
                line[2..].trim()
            };
            let cleaned = cleaned.trim_matches(|c: char| c == '=' || c == '-' || c == '*' || c == '#').trim();
            if cleaned.len() >= 3 && !cleaned.to_lowercase().starts_with("encoding") {
                desc_lines.push(cleaned.to_string());
            }
            continue;
        }
        if lower.starts_with("echo ") && desc_lines.is_empty() {
            let msg = line[5..].trim();
            let msg_clean = msg
                .trim_matches(|c: char| c == '=' || c == '-' || c == '*' || c == '[' || c == ']')
                .trim();
            if msg_clean.len() >= 4
                && !msg_clean.contains('%')
                && !msg_clean.to_lowercase().starts_with("error")
            {
                desc_lines.push(msg_clean.to_string());
            }
        }
    }

    let desc = if desc_lines.is_empty() {
        None
    } else {
        Some(desc_lines.into_iter().take(2).collect::<Vec<_>>().join(" | "))
    };
    (title, desc)
}

fn is_ignored_port(port: u16) -> bool {
    matches!(
        port,
        22 | 80 | 443 | 1080 | 1081 | 2080 | 3306 | 3389 | 5432 | 6379 | 7890 | 7891 | 7892 | 7897 | 9090 | 10808 | 10809 | 27017
    )
}

fn re_port_flag() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)(?:--port|-p|port\s*=|server\.port\s*=)\s*["']?(\d{2,5})"#).unwrap()
    })
}

fn re_host_port() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"(?i)(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1?\]):(\d{2,5})").unwrap()
    })
}

fn re_http_server_port() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r"(?i)http\.server\s+(\d{2,5})\b").unwrap())
}

fn re_findstr_port() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| Regex::new(r#"(?i)findstr\s+[^|\r\n]*":(\d{2,5})\b"#).unwrap())
}

fn re_abs_script_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)([a-z]:\\[^\s"'<>|]+?\.(?:py|pyw|js|ts|mjs|cjs|exe|bat|cmd))"#).unwrap()
    })
}

fn re_quoted_script_path() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r#"(?i)"([a-z]:\\[^"<>|\r\n]+?\.(?:py|pyw|js|ts|mjs|cjs|exe|bat|cmd))""#).unwrap()
    })
}

fn extract_ports(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    let mut seen = HashSet::new();
    let patterns = [
        re_port_flag(),
        re_host_port(),
        re_http_server_port(),
        re_findstr_port(),
    ];

    for raw_line in text.lines() {
        let trimmed = raw_line.trim();
        let lower = trimmed.to_lowercase();
        if trimmed.is_empty()
            || lower.starts_with("rem ")
            || trimmed.starts_with("::")
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || lower.contains("proxy")
            || lower.contains("debug_address")
        {
            continue;
        }
        for re in patterns {
            for cap in re.captures_iter(trimmed) {
                if let Some(m) = cap.get(1) {
                    if let Ok(p) = m.as_str().parse::<u16>() {
                        if p >= 80 && !is_ignored_port(p) && seen.insert(p) {
                            ports.push(p);
                        }
                    }
                }
            }
        }
    }
    ports
}

fn is_generic_runtime_exe(path_lower: &str) -> bool {
    let fname = Path::new(path_lower)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    matches!(
        fname,
        "python.exe"
            | "pythonw.exe"
            | "node.exe"
            | "cmd.exe"
            | "powershell.exe"
            | "pwsh.exe"
            | "uv.exe"
            | "git.exe"
            | "pip.exe"
            | "conda.exe"
            | "explorer.exe"
            | "taskkill.exe"
            | "netstat.exe"
            | "findstr.exe"
            | "ping.exe"
            | "conhost.exe"
            | "wt.exe"
            | "notepad.exe"
            | "code.exe"
            | "chrome.exe"
            | "msedge.exe"
            | "firefox.exe"
            | "weixin.exe"
            | "wechat.exe"
            | "qq.exe"
            | "antigravity.exe"
    )
}

fn extract_process_and_keywords(
    content_lower: &str,
) -> (Vec<String>, Vec<String>) {
    let mut process_names = Vec::new();
    let mut keywords = Vec::new();

    let known_exes = [
        "scrcpy.exe",
        "llama-server.exe",
        "llama-cli.exe",
        "cloudflared.exe",
        "ollama.exe",
        "nginx.exe",
        "caddy.exe",
        "tailscaled.exe",
        "blender.exe",
        "frida-server.exe",
        "freqtrade.exe",
    ];
    for exe in known_exes {
        if content_lower.contains(exe) || content_lower.contains(exe.trim_end_matches(".exe")) {
            process_names.push(exe.to_string());
        }
    }

    for re in [re_quoted_script_path(), re_abs_script_path()] {
        for cap in re.captures_iter(content_lower) {
            if let Some(m) = cap.get(1) {
                let tok = m.as_str().replace('/', "\\");
                if tok.contains("system32") || tok.contains("windows\\") || is_generic_runtime_exe(&tok) {
                    continue;
                }
                if !keywords.contains(&tok) {
                    keywords.push(tok.clone());
                }
                if tok.ends_with(".exe") {
                    if let Some(fname) = Path::new(&tok).file_name().and_then(|s| s.to_str()) {
                        let fname_str = fname.to_string();
                        if !process_names.contains(&fname_str) {
                            process_names.push(fname_str);
                        }
                    }
                }
            }
        }
    }

    (process_names, keywords)
}

struct ProjectMeta {
    title: Option<String>,
    summary: Option<String>,
    deps_text: String,
    extra_ports_text: String,
}

fn read_project_context(project_dir: &Path) -> ProjectMeta {
    let mut title = None;
    let mut summary = None;
    let mut deps_text = String::new();
    let mut extra_ports_text = String::new();

    let readme_candidates = ["README.md", "readme.md", "README.txt", "README_CN.md"];
    for name in readme_candidates {
        let p = project_dir.join(name);
        if let Some(txt) = read_text_lossy_limit(&p, 6144) {
            for line in txt.lines() {
                let t = line.trim();
                if t.is_empty() || t.starts_with("![") || t.starts_with("[![") || t.starts_with("---") {
                    continue;
                }
                if title.is_none() && t.starts_with('#') {
                    let clean = t.trim_start_matches('#').trim();
                    if !clean.is_empty() {
                        title = Some(clean.chars().take(60).collect());
                    }
                    continue;
                }
                if summary.is_none() && !t.starts_with('#') && !t.starts_with('<') && !t.starts_with("```") {
                    summary = Some(t.chars().take(110).collect());
                    break;
                }
            }
            break;
        }
    }

    let pkg_path = project_dir.join("package.json");
    if let Some(txt) = read_text_lossy_limit(&pkg_path, 8192) {
        if let Ok(val) = serde_json::from_str::<serde_json::Value>(&txt) {
            if summary.is_none() {
                if let Some(d) = val.get("description").and_then(|v| v.as_str()) {
                    if !d.trim().is_empty() {
                        summary = Some(d.trim().chars().take(110).collect());
                    }
                }
            }
            if title.is_none() {
                if let Some(n) = val.get("name").and_then(|v| v.as_str()) {
                    if !n.trim().is_empty() {
                        title = Some(n.trim().to_string());
                    }
                }
            }
        }
        deps_text.push_str(&txt.to_lowercase());
        extra_ports_text.push_str(&txt);
    }

    for dep_file in ["requirements.txt", "pyproject.toml", "Cargo.toml", "docker-compose.yml"] {
        let p = project_dir.join(dep_file);
        if let Some(txt) = read_text_lossy_limit(&p, 6144) {
            deps_text.push(' ');
            deps_text.push_str(&txt.to_lowercase());
            if dep_file == "docker-compose.yml" {
                extra_ports_text.push(' ');
                extra_ports_text.push_str(&txt);
            }
        }
    }

    for entry_py in ["app.py", "server.py", "main.py", "run.py", "webui.py", "start_service.py"] {
        let p = project_dir.join(entry_py);
        if let Some(txt) = read_text_lossy_limit(&p, 4096) {
            extra_ports_text.push(' ');
            extra_ports_text.push_str(&txt);
        }
    }

    ProjectMeta {
        title,
        summary,
        deps_text,
        extra_ports_text,
    }
}

fn classify_category(corpus: &str) -> String {
    let rules: &[(&str, usize, &[&str])] = &[
        (
            "quant_finance",
            2,
            &[
                "freqtrade",
                "ccxt",
                "binance",
                "okx",
                "bybit",
                "backtest",
                "trading",
                "quant",
                "kline",
                "\u{91cf}\u{5316}",
                "\u{5e01}\u{5b89}",
                "\u{5b9e}\u{76d8}",
                "\u{56de}\u{6d4b}",
            ],
        ),
        (
            "ai_llm",
            2,
            &[
                "torch",
                "transformers",
                "llama",
                "ollama",
                "whisper",
                "funasr",
                "sovits",
                "gpt-sovits",
                "comfyui",
                "stable-diffusion",
                "langchain",
                "deepseek",
                "openai",
                "anthropic",
                "gemini",
                "mirix",
                "agent",
                "llm",
                "rag",
                "mcp",
                "tts",
                "asr",
                "ocr",
                "capswriter",
                "voicetype",
                "\u{5927}\u{6a21}\u{578b}",
                "\u{8bed}\u{97f3}",
                "\u{8bb0}\u{5fc6}",
            ],
        ),
        (
            "mobile_device",
            2,
            &[
                "adb",
                "scrcpy",
                "android",
                "oneplus",
                "acepro",
                "frida",
                "apk",
                "ios",
                "airdrop",
                "lan_drop",
                "\u{624b}\u{673a}",
                "\u{6295}\u{5c4f}",
                "\u{4e00}\u{52a0}",
                "\u{9694}\u{7a7a}",
            ],
        ),
        (
            "embedded_hw",
            2,
            &[
                "stm32",
                "keil",
                "platformio",
                "arduino",
                "esp32",
                "serial",
                "com port",
                "st-link",
                "openocd",
                "firmware",
                "\u{5355}\u{7247}\u{673a}",
                "\u{4e32}\u{53e3}",
                "\u{70e7}\u{5f55}",
                "\u{56fa}\u{4ef6}",
            ],
        ),
        (
            "automation_media",
            2,
            &[
                "playwright",
                "selenium",
                "puppeteer",
                "crawler",
                "scraper",
                "douyin",
                "bilibili",
                "xiaohongshu",
                "tiktok",
                "youtube",
                "ffmpeg",
                "remotion",
                "poster",
                "wechat",
                "xwechat",
                "\u{6296}\u{97f3}",
                "\u{5fae}\u{4fe1}",
                "\u{6d77}\u{62a5}",
                "\u{81ea}\u{5a92}\u{4f53}",
                "\u{53d1}\u{5e03}",
            ],
        ),
        (
            "web_service",
            1,
            &[
                "fastapi",
                "uvicorn",
                "flask",
                "django",
                "streamlit",
                "gradio",
                "vite",
                "next",
                "react",
                "vue",
                "express",
                "dashboard",
                "webui",
                "workbench",
                "http://",
                "\u{770b}\u{677f}",
                "\u{5de5}\u{4f5c}\u{53f0}",
            ],
        ),
        (
            "sys_ops",
            1,
            &[
                "ssh",
                "tailscale",
                "cloudflared",
                "proxy",
                "netcheck",
                "disk",
                "guard",
                "monitor",
                "watchdog",
                "schtasks",
                "autostart",
                "reg ",
                "netsh",
                "patch",
                "clean",
                "backup",
                "\u{5f00}\u{673a}\u{81ea}\u{542f}",
                "\u{7f51}\u{7edc}",
                "\u{78c1}\u{76d8}",
                "\u{606f}\u{5c4f}",
                "\u{8865}\u{4e01}",
            ],
        ),
    ];

    let mut best_cat = "general";
    let mut best_score = 0usize;

    for (cat_id, weight, kws) in rules {
        let mut score = 0usize;
        for kw in *kws {
            if corpus.contains(kw) {
                score += *weight;
            }
        }
        if score > best_score {
            best_score = score;
            best_cat = cat_id;
        }
    }

    best_cat.to_string()
}

pub fn analyze_script(bat_path: &Path) -> AnalyzedScript {
    let file_name = bat_path
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "script.bat".to_string());
    let file_stem = bat_path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "script".to_string());
    let stem_lower = file_stem.to_lowercase();

    let parent_dir = bat_path.parent().unwrap_or_else(|| Path::new("."));
    let mut project_dir = parent_dir;
    let parent_name_lower = parent_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if matches!(
        parent_name_lower.as_str(),
        "scripts" | "script" | "bin" | "tools" | "bat" | "support"
    ) {
        if let Some(gp) = parent_dir.parent() {
            project_dir = gp;
        }
    }

    let project_name = project_dir
        .file_name()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "Workspace".to_string());
    let project_name_lower = project_name.to_lowercase();

    let bat_content = read_text_lossy_limit(bat_path, 32768).unwrap_or_default();
    let content_lower = bat_content.to_lowercase();

    let (bat_title, bat_desc) = extract_title_and_comments(&bat_content);
    let meta = read_project_context(project_dir);

    let role = detect_role(&stem_lower, &content_lower);

    let display_name = if let Some(t) = bat_title.as_ref() {
        if is_generic_script_stem(&stem_lower) && !t.to_lowercase().contains(&project_name_lower) {
            format!("{} - {}", project_name, t)
        } else {
            t.clone()
        }
    } else if is_generic_script_stem(&stem_lower) {
        if let Some(pt) = meta.title.as_ref() {
            if pt.to_lowercase() != project_name_lower {
                format!("{} ({})", project_name, file_stem)
            } else {
                format!("{} - {}", project_name, file_stem)
            }
        } else {
            format!("{} - {}", project_name, file_stem)
        }
    } else {
        file_stem.clone()
    };

    let description = bat_desc
        .or(meta.summary)
        .unwrap_or_else(|| format!("{} / {}", project_name, file_name));

    let mut combined_ports_text = bat_content.clone();
    combined_ports_text.push(' ');
    combined_ports_text.push_str(&meta.extra_ports_text);
    let ports = if role == "service" {
        extract_ports(&combined_ports_text)
    } else {
        Vec::new()
    };

    let (process_names, keywords) = extract_process_and_keywords(&content_lower);

    let corpus = format!(
        "{} {} {} {} {}",
        project_name_lower,
        stem_lower,
        content_lower,
        meta.deps_text,
        meta.title.unwrap_or_default().to_lowercase()
    );
    let category = classify_category(&corpus);

    let requires_admin = content_lower.contains("net session")
        || content_lower.contains("fltmc")
        || content_lower.contains("runas")
        || content_lower.contains("shell.application")
        || stem_lower.contains("admin")
        || stem_lower.contains("\u{7ba1}\u{7406}\u{5458}");

    AnalyzedScript {
        display_name,
        description,
        category,
        role,
        ports,
        keywords,
        process_names,
        requires_admin,
        project_name,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_gbk_and_utf8_bat_analysis() {
        let tmp = std::env::temp_dir().join("bathub_unit_test_proj");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();

        fs::write(
            tmp.join("README.md"),
            "# AI Voice Studio\nLocal speech synthesis server for testing.\n",
        )
        .unwrap();
        fs::write(tmp.join("requirements.txt"), "torch==2.4.0\nfastapi\nuvicorn\n").unwrap();

        let bat_path = tmp.join("start.bat");
        let gbk_bytes = GBK
            .encode("@echo off\r\ntitle \u{8bed}\u{97f3}\u{5408}\u{6210}\u{5de5}\u{4f5c}\u{53f0}\r\nrem \u{542f}\u{52a8}\u{672c}\u{5730} TTS WebUI\r\npython app.py --port 9874\r\n")
            .0;
        fs::write(&bat_path, &*gbk_bytes).unwrap();

        let res = analyze_script(&bat_path);
        assert_eq!(res.role, "service");
        assert_eq!(res.category, "ai_llm");
        assert!(res.ports.contains(&9874));
        assert!(res.display_name.contains("bathub_unit_test_proj"));
        assert!(res.display_name.contains("\u{8bed}\u{97f3}\u{5408}\u{6210}\u{5de5}\u{4f5c}\u{53f0}"));

        let stop_path = tmp.join("0_stop_all.bat");
        fs::write(&stop_path, "@echo off\r\ntaskkill /f /im python.exe\r\n").unwrap();
        let stop_res = analyze_script(&stop_path);
        assert_eq!(stop_res.role, "stop");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_port_extraction_and_quant_classification() {
        let tmp = std::env::temp_dir().join("crypto_freqtrade_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let bat_path = tmp.join("5_start_live_trading.bat");
        fs::write(
            &bat_path,
            "@echo off\r\nset HTTP_PROXY=http://127.0.0.1:7890\r\nset DEBUG_ADDRESS=127.0.0.1:13002\r\nrem Freqtrade Binance strategy on 127.0.0.1:18080\r\nC:\\Python314\\python.exe D:\\Tools\\custom_runner.py --port 18080\r\n",
        )
        .unwrap();

        let res = analyze_script(&bat_path);
        assert_eq!(res.category, "quant_finance");
        assert_eq!(res.role, "service");
        assert!(res.ports.contains(&18080));
        assert!(!res.ports.contains(&7890));
        assert!(!res.ports.contains(&13002));
        assert!(!res.keywords.iter().any(|k| k.ends_with("python.exe")));
        assert!(res.keywords.iter().any(|k| k.ends_with("custom_runner.py")));

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_quoted_exe_and_findstr_port_extraction() {
        let tmp = std::env::temp_dir().join("bathub_quoted_exe_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let bat_path = tmp.join("launch.bat");
        fs::write(
            &bat_path,
            "@echo off\r\nfor /f \"tokens=5\" %%a in ('netstat -ano ^| findstr \":8787 \"') do echo %%a\r\nstart \"\" \"C:\\Users\\demo\\AppData\\Local\\Sample App Tool\\sample-app-tool.exe\"\r\n",
        )
        .unwrap();

        let res = analyze_script(&bat_path);
        assert!(res.ports.contains(&8787));
        assert!(res.process_names.iter().any(|p| p == "sample-app-tool.exe"));
        assert!(res
            .keywords
            .iter()
            .any(|k| k.contains("sample app tool\\sample-app-tool.exe")));

        let _ = fs::remove_dir_all(&tmp);
    }
}
