# Psychopomp Packages Tools

**Psychopomp Packages Tools** is a desktop application I built to simplify the process of collecting and managing Debian package files (`.deb`) and their source code for **Debian 13 (Trixie)** and derivatives.

It provides a modern, user‑friendly interface to:
- Browse a curated catalog of packages (`packages.json`) organized by category.
- Filter and search packages by name, description, or category.
- Select one or more packages to download.
- Choose whether to download:
  - Only the `.deb` binary package
  - Only the source code
  - Or both
- Save all downloads into a structured directory tree (`packages/deb` and `packages/source`).
- Keep a persistent configuration (`config.json`) for base download path and concurrency settings.
- Log all operations and export a CSV summary of each run.

---

## 📂 Repository Structure

```
PackagesTools/
├── main.py          # Application entry point (GUI)
├── packages.json    # Package catalog with metadata, categories, and descriptions
├── config.json      # User configuration (base path, max workers)
└── README.md        # This file
```

---

## 🎯 Purpose

I created this tool to solve a recurring problem:  
When building or customizing a Debian‑based distribution, I often need to:
- Gather the latest stable `.deb` files for a specific set of packages.
- Optionally fetch their source code for inspection, patching, or offline builds.
- Keep everything organized in a predictable folder structure.
- Avoid manually running `apt-get download` or `apt-get source` dozens of times.

With **Psychopomp Packages Tools**, I can do all of that in one place, with a clear overview of what’s available and what’s been downloaded.

---

## 🛠 How It Works

1. **Load the Catalog**  
   On startup, the app reads `packages.json`, which contains:
   - A list of packages with their name, category, description, and default download type.
   - A list of categories for filtering.

2. **Configure Download Settings**  
   - Set a base download directory (the app will create `deb/` and `source/` subfolders inside it).
   - Choose the number of parallel downloads (1–8 workers).
   - Decide whether to download `.deb`, source, or both.

3. **Select Packages**  
   - Filter by category or search by keyword.
   - Select one or more packages from the list.

4. **Download**  
   - The app checks package availability in Debian 13 repositories.
   - Downloads the requested artifacts into the correct subfolders.
   - Logs all actions to a timestamped log file.
   - Generates a CSV summary of the run.

5. **Review Results**  
   - View logs directly from the app.
   - Open the download folders or logs folder from the menu.
   - Use the CSV summary for auditing or integration into build scripts.

---

## 💡 Key Features

- **Cross‑platform GUI** (built with Tkinter, tested on Debian 13).
- **Safe**: runs without root privileges; uses `apt-get download` and `apt-get source`.
- **Organized**: separates binaries and sources into dedicated folders.
- **Persistent**: remembers your settings between sessions.
- **Transparent**: detailed logs and CSV summaries for every run.
- **Flexible**: easy to extend `packages.json` with more packages or categories.

---

## 📋 Requirements

- Debian 13 (Trixie) or compatible.
- Python ≥ 3.10 with Tkinter.
- APT tools installed:
  ```bash
  sudo apt update
  sudo apt install apt-utils dpkg-dev python3-tk
  ```
- For source downloads: enable `deb-src` entries in `/etc/apt/sources.list` and run:
  ```bash
  sudo apt update
  ```

---

## 🚀 Usage

Run the application:

```bash
python3 main.py
```

1. Set your base download directory and save it.
2. Adjust max workers if needed.
3. Filter/search and select packages.
4. Tick `.deb`, source, or both.
5. Click **Download Selected** or **Download All (filtered)**.

---

## 📜 License

This project is released under the **GPLv3** license.  
See the [LICENSE](LICENSE) file for details.

---

## 🤝 Contributing

- Add new packages to `packages.json` with proper category and description.
- Report bugs or suggest features via the issue tracker.
- Pull requests are welcome.

---

## 📧 Contact

For questions or feedback, please open an issue on the repository.
