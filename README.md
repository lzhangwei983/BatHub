# BatHub

Zero-config Windows batch script (`.bat` / `.cmd`) organizer, system-tray launcher, and live service monitor built in pure Rust + WebView2.

## Why BatHub?

Developers and power users often accumulate dozens of projects, each containing scripts named `start.bat`, `run.bat`, or `0_stop_all.bat`. Generic launchers either require manual JSON/shortcut curation or burn CPU/disk I/O with full-disk scanning.

BatHub solves this out of the box with zero prompts, zero external AI/memory dependencies, and zero project rule modifications:

1. **Zero-Idle-Load Shallow Discovery**: Asynchronously scans only user-selected workspace roots up to depth `<= 2` (skipping `.venv`, `node_modules`, `.git`, `target`, `dist`, `build`, `__pycache__`) in milliseconds when syncing, plus Drag & Drop and optional Windows Explorer Right-Click integration (`Add to BatHub`).
2. **Offline Static Fingerprinting**: Safely decodes GBK/CP936 and UTF-8 `.bat` files, reads `TITLE`, header comments, listening ports (`--port`, `:8080`, `PORT=`, `http.server`, `findstr`), launched executables (including quoted paths with spaces), and adjacent project metadata (`README.md`, `package.json`, `requirements.txt`, `pyproject.toml`) to automatically:
   - Disambiguate generic `start.bat` / `run.bat` names with their project context
   - Categorize scripts into 8 built-in domains (`AI & Models`, `Web & Dashboards`, `Quant & Finance`, `Automation & Media`, `Mobile & ADB`, `Embedded & Hardware`, `System & DevOps`, `General`)
   - Pair sibling `stop` / `check` / `install` scripts directly onto the main service card
3. **Live Process & Port Monitoring**:
   - **IPv4 + IPv6 Dual-Stack TCP Listener Detection** via Windows `GetExtendedTcpTable`, plus process `cmd` / `cwd` / `exe` matching and launched process-tree tracking
   - **Unmanaged Local Background Service Radar**: Surfaces other local dev services running outside your watched workspaces, with one-click `+ Track Folder`, `Folder`, and `Stop` actions
4. **Dual-Entry Delivery**:
   - **System Tray + Dashboard UI**: Categorized tray submenus, global toggle hotkey (`Alt+Shift+B`), multi-keyword search, toast sync feedback, and one-click Start / Silent Run / Stop / Open Terminal / Open Folder.
   - **Categorized `.lnk` Shortcut Mirror**: Automatically maintains a clean categorized folder of Windows `.lnk` shortcuts with `WorkingDirectory` bound to each script's original folder (keeping `%~dp0` and `.venv` paths intact).

## Build from Source

```powershell
cargo test
cargo build --release
```

The single portable binary is produced at `target/release/bathub.exe`.

## License

MIT
