# Serverbox

Serverbox is an open-source, agentless desktop control panel for Linux servers. It connects over SSH, so there is nothing to install on the servers you manage.

Built with Rust, Tauri 2, and TypeScript, Serverbox brings common administration tasks into one cross-platform desktop workspace while keeping the terminal available for everything else.

[https://serverbox.stupidlabs.lol](https://serverbox.stupidlabs.lol)

## What it does

- Connect to multiple servers with password or private-key authentication, including SSH config import and bastion (ProxyJump-style) routes.
- Store passwords, key passphrases, and sudo credentials in an encrypted local vault protected by a master password.
- Verify SSH host keys against `known_hosts`, showing fingerprints before trusting a new or changed host key.
- View CPU, memory, disks, network interfaces, uptime, and load.
- Open persistent, tabbed SSH terminals with resizing, copy/paste, keepalives, and reconnect support.
- Manage processes, system services, logs, listening ports, and active connections.
- Browse and edit files over SFTP, including uploads, downloads, permissions, ownership, and recursive transfers.
- Explore disk usage, inode pressure, large files and directories, Docker storage, and `/var/log` usage.
- Work with Docker and Podman containers, images, volumes, networks, logs, statistics, and exec shells.
- Discover and manage Docker Compose projects and services.
- Manage user crontabs, APT packages, Linux users and groups, SSH authorized keys, and UFW or firewalld rules where supported.
- Review update and security posture, run guarded maintenance actions, save commands, keep local server notes, and create local, remote, or SOCKS5 SSH tunnels.

Serverbox detects available capabilities instead of assuming a particular distribution or init system. It supports Debian and Ubuntu, Fedora and RHEL-family systems, openSUSE and SUSE, Arch, and Alpine where the relevant tools are available. The terminal and SFTP browser require only SSH; unavailable features explain what is missing.

## Safety and privacy

Serverbox runs on your computer and communicates with managed machines over SSH. It does not require a Serverbox agent on a remote host.

Secrets are encrypted locally. Serverbox asks for explicit confirmation before potentially disruptive operations such as firewall changes, account deletion, or service actions. As with any server-administration tool, review an action carefully and maintain an independent recovery path before changing remote access or critical services.

## AI assistance

- AI-assisted tools were used during the development of Serverbox.
- This is not vibe-coded... it's AI-assisted. Over 100 individual sessions of `plan -> review -> review-review -> dev -> review -> review-review -> plan next -> review -> ...` chains were employed.
- If you don't like this, please don't use it. No need to spread [hatred](https://news.ycombinator.com/item?id=49509679).
- Bugs are expected. From humans, and AI both. Please file them under issues if you do find any.

## Install

Download a build for macOS, Windows, or Linux from the repository's releases page.

Release builds currently include:

- macOS: Intel and Apple Silicon
- Windows: x86_64 and ARM64
- Linux: x86_64 and ARM64 (`.AppImage`, `.deb`, and selected `.rpm` packages)

## ⚠️⚠️ Security warnings when installing from pre-built releases

1. Serverbox is not code-signed yet (macOS builds are ad-hoc signed), so browser and operating-system security warnings are expected. 
2. On Windows, choose **Keep** or **Download anyway** if prompted, then **More info** → **Run anyway** in SmartScreen.
3. On macOS, move Serverbox to Applications, right-click it, choose **Open**, and confirm **Open** again. You normally need to approve an installed copy only once.

## Build from source

Install a current Node.js release, Rust, and the platform prerequisites for [Tauri 2](https://v2.tauri.app/start/prerequisites/). Then run:

```sh
npm install
npm run tauri dev
```

To create a production bundle for your current operating system:

```sh
npm run tauri build
```

To run the frontend production build and Rust compile checks:

```sh
npm run check
```

## Architecture

The TypeScript frontend communicates exclusively through typed Tauri commands. Rust owns local persistence, encrypted credentials, SSH connections, terminals, SFTP transfers, and remote capability providers. Potentially blocking SSH work runs outside the window's main thread.

```text
TypeScript frontend
        |
        v
Typed Tauri commands
        |
        v
Rust backend: storage, credential vault, SSH, PTYs, SFTP, and providers
        |
        v
Linux servers over SSH (no Serverbox agent)
```

## Contributing

Issues and pull requests are welcome.

## License

Serverbox is licensed under the [MIT License](LICENSE).
