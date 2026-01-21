# elevate

`elevate` is a ruthlessly small replacement for `sudo` whose only job is to execute a single command as root on Linux. No configurable policy engine, no configuration files, no ambient environment leakage—just a safe trampoline into a target program.

### Why it’s safe

`elevate` keeps the privilege boundary tight by forcing every caller to re-enter their UNIX password, adopting full root credentials only after authentication, and then immediately replacing itself with the requested program. It never parses policy files, never keeps background helpers, and always clears the environment and search path before `execve`, drastically shrinking the attack surface compared to legacy privilege brokers.

## Design goals

- **Aggressively simple** – one binary, one command, zero configuration knobs.
- **Aggressively safe** – refuses to run without setuid root, insists the caller re‑authenticates with their own password, drops supplemental groups, resets uid/gid, sets a predictable umask, and clears the environment.
- **Predictable execution** – resolves the target command using a hard-coded, canonical root `PATH` and then `execve`s it directly so there is no long-lived privileged supervisor process.

## How it works

1. Verifies it is running with effective UID 0 (requires the binary to be owned by root and have the setuid bit).
2. Prompts the invoking user (unless they are already root) for their UNIX password and verifies it against `/etc/shadow` using `crypt(3)`, allowing three attempts with a small backoff.
3. Calls `setgroups(0, NULL)`, `setresgid(0,0,0)`, and `setresuid(0,0,0)` to fully adopt the root identity.
4. Forces the process umask to `022` to avoid permissive files created by privileged programs.
5. Resolves the requested command name against `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`. Relative or absolute paths are honored verbatim if supplied.
6. Clears the process environment and replaces it with a minimal, known-safe set (`HOME=/root`, `PATH`, `TERM`, etc.).
7. Performs an `execve`, so on success `elevate` is replaced by the requested program and inherits its exit status.

## Installation

1. Build a release binary:
   ```bash
   cargo build --release
   ```
2. Install it into a root-owned location (example uses `/usr/local/bin/elevate`):
   ```bash
   sudo install -o root -g root -m 0755 target/release/elevate /usr/local/bin/elevate
   ```
3. Enable setuid so unprivileged callers can adopt root:
   ```bash
   sudo chmod 4755 /usr/local/bin/elevate
   ```

If any of those steps are skipped, `elevate` will refuse to run and print an explicit error.

## Usage

```
elevate <command> [args...]
```

- Use `--` only if your command itself begins with `-`.
- The program inherits no user environment. To pass custom variables, wrap your command with `env`, e.g. `elevate env VAR=value /usr/bin/env`.

Example:

```bash
elevate apt-get update
```

## Security notes

- `elevate` authorizes callers by re-checking their own UNIX password via `/etc/shadow`. Limit execution rights to appropriate users (e.g., via filesystem ACLs or group ownership) and ensure their accounts have strong passwords.
- Passwords are read directly from the controlling TTY with echo disabled, never stored on disk, and zeroized in memory after verification.
- Command resolution never consults the caller's `PATH`; only the hard-coded root-safe search path is used.
- The environment is rebuilt from scratch to neutralize vectors such as `LD_PRELOAD` or `PYTHONPATH`. The only inherited piece is `TERM`, and even that is validated to simple ASCII before use.
- Because the binary immediately `execve`s the target, there is no privileged helper lingering in memory to inspect or attack.

## Optional tab completion

Shells treat `elevate` as a regular command, so to get `sudo`-style “complete the next word” behavior you can add a tiny wrapper completion:

### Bash

Save the following as `/etc/bash_completion.d/elevate` (system-wide) or `~/.local/share/bash-completion/completions/elevate`:

```bash
_elevate()
{
    _command_offset 1
}
complete -F _elevate elevate
```

### Zsh

Add to your `.zshrc`:

```zsh
_elevate() { _normal -p 1 }
compdef _elevate elevate
```

After reloading your shell, `elevate apt-g<Tab>` will expand via the wrapped command’s completion rules just like `sudo`.
