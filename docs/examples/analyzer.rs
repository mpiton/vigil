use std::collections::HashMap;

use crate::config::Config;
use crate::types::*;

/// Analyzes a system snapshot and produces alerts based on deterministic rules
pub struct RuleAnalyzer<'a> {
    config: &'a Config,
}

impl<'a> RuleAnalyzer<'a> {
    pub fn new(config: &'a Config) -> Self {
        Self { config }
    }

    /// Run all rules against a snapshot and return any triggered alerts
    pub fn analyze(&self, snapshot: &SystemSnapshot) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let ts = snapshot.timestamp;

        // --- Memory rules ---
        self.check_ram_usage(snapshot, &mut alerts, ts);
        self.check_swap_usage(snapshot, &mut alerts, ts);

        // --- CPU rules ---
        self.check_cpu_load(snapshot, &mut alerts, ts);

        // --- Process rules ---
        self.check_zombies(snapshot, &mut alerts, ts);
        self.check_duplicate_processes(snapshot, &mut alerts, ts);
        self.check_orphan_dev_processes(snapshot, &mut alerts, ts);

        // --- Disk rules ---
        self.check_disk_space(snapshot, &mut alerts, ts);

        // --- Journal rules ---
        self.check_oom_killer(snapshot, &mut alerts, ts);

        // Sort by severity (critical first)
        alerts.sort_by(|a, b| b.severity.cmp(&a.severity));
        alerts
    }

    fn check_ram_usage(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let mem = &snapshot.memory;
        let thresholds = &self.config.thresholds;

        if mem.usage_percent >= thresholds.ram_critical_percent {
            let top_procs = self.top_processes_by_ram(snapshot, 5);
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::Critical,
                rule: "ram_critical".into(),
                title: format!(
                    "RAM critique : {:.1}% utilisée ({}/{} MB)",
                    mem.usage_percent, mem.used_mb, mem.total_mb
                ),
                details: format!(
                    "Top consommateurs RAM :\n{}",
                    top_procs
                        .iter()
                        .map(|p| format!(
                            "  PID {} ({}) — {} MB, CPU {:.1}%",
                            p.pid, p.name, p.rss_mb, p.cpu_percent
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
                suggested_actions: top_procs
                    .iter()
                    .filter(|p| !self.is_protected(&p.name))
                    .map(|p| SuggestedAction {
                        description: format!("Tuer {} (PID {}, {} MB)", p.name, p.pid, p.rss_mb),
                        command: format!("kill {}", p.pid),
                        risk: ActionRisk::Moderate,
                    })
                    .collect(),
            });
        } else if mem.usage_percent >= thresholds.ram_warn_percent {
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::High,
                rule: "ram_warning".into(),
                title: format!(
                    "RAM élevée : {:.1}% utilisée ({}/{} MB)",
                    mem.usage_percent, mem.used_mb, mem.total_mb
                ),
                details: "La RAM approche du seuil critique.".into(),
                suggested_actions: vec![SuggestedAction {
                    description: "Libérer le cache système".into(),
                    command: "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches".into(),
                    risk: ActionRisk::Safe,
                }],
            });
        }
    }

    fn check_swap_usage(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let mem = &snapshot.memory;
        if mem.swap_total_mb > 0 && mem.swap_percent >= self.config.thresholds.swap_warn_percent {
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::High,
                rule: "swap_warning".into(),
                title: format!(
                    "Swap élevé : {:.1}% ({}/{} MB)",
                    mem.swap_percent, mem.swap_used_mb, mem.swap_total_mb
                ),
                details: "Le système utilise beaucoup de swap, ce qui ralentit les performances."
                    .into(),
                suggested_actions: vec![],
            });
        }
    }

    fn check_cpu_load(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let cpu = &snapshot.cpu;
        let max_load = self.config.thresholds.cpu_load_factor * cpu.core_count as f64;

        if cpu.load_avg_5m > max_load {
            let top_procs = self.top_processes_by_cpu(snapshot, 5);
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::High,
                rule: "cpu_overload".into(),
                title: format!(
                    "CPU surchargé : load {:.2}/{:.2}/{:.2} ({} cœurs, seuil: {:.1})",
                    cpu.load_avg_1m, cpu.load_avg_5m, cpu.load_avg_15m, cpu.core_count, max_load
                ),
                details: format!(
                    "Top consommateurs CPU :\n{}",
                    top_procs
                        .iter()
                        .map(|p| format!(
                            "  PID {} ({}) — CPU {:.1}%, {} MB",
                            p.pid, p.name, p.cpu_percent, p.rss_mb
                        ))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
                suggested_actions: vec![],
            });
        }
    }

    fn check_zombies(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let zombies: Vec<&ProcessInfo> = snapshot
            .processes
            .iter()
            .filter(|p| p.state == ProcessState::Zombie)
            .collect();

        if !zombies.is_empty() {
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::Medium,
                rule: "zombie_processes".into(),
                title: format!("{} processus zombie(s) détecté(s)", zombies.len()),
                details: zombies
                    .iter()
                    .map(|z| format!("  PID {} ({}) — parent PID {}", z.pid, z.name, z.ppid))
                    .collect::<Vec<_>>()
                    .join("\n"),
                suggested_actions: zombies
                    .iter()
                    .map(|z| SuggestedAction {
                        description: format!(
                            "Signaler le parent (PID {}) pour récolter le zombie",
                            z.ppid
                        ),
                        command: format!("kill -SIGCHLD {}", z.ppid),
                        risk: ActionRisk::Safe,
                    })
                    .collect(),
            });
        }
    }

    /// KEY RULE: Detect ghost/duplicate processes (the MCP Python scenario)
    fn check_duplicate_processes(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let max_dupes = self.config.thresholds.max_duplicate_processes;

        // Group processes by their executable name (normalized)
        let mut groups: HashMap<String, Vec<&ProcessInfo>> = HashMap::new();
        for proc in &snapshot.processes {
            if self.is_ignored(&proc.name) {
                continue;
            }
            // Normalize: use base command name
            let key = Self::normalize_process_name(&proc.cmdline, &proc.name);
            groups.entry(key).or_default().push(proc);
        }

        for (name, procs) in &groups {
            if procs.len() > max_dupes {
                let total_ram_mb: u64 = procs.iter().map(|p| p.rss_mb).sum();
                let total_cpu: f32 = procs.iter().map(|p| p.cpu_percent).sum();
                let pids: Vec<u32> = procs.iter().map(|p| p.pid).collect();

                // Determine if they look like orphaned dev tool processes
                let likely_dev_tool = name.contains("python")
                    || name.contains("node")
                    || name.contains("mcp")
                    || name.contains("typescript");

                let severity = if total_ram_mb > 1024 {
                    Severity::High
                } else if likely_dev_tool {
                    Severity::High
                } else {
                    Severity::Medium
                };

                let context = if likely_dev_tool {
                    "Probablement des processus MCP/dev non terminés."
                } else {
                    "Nombre inhabituel de processus identiques."
                };

                alerts.push(Alert {
                    timestamp: ts,
                    severity,
                    rule: "duplicate_processes".into(),
                    title: format!(
                        "{} instances de \"{}\" ({} MB total, CPU {:.1}%)",
                        procs.len(),
                        name,
                        total_ram_mb,
                        total_cpu
                    ),
                    details: format!(
                        "{}\nPIDs: {:?}\nRAM totale: {} MB | CPU totale: {:.1}%",
                        context, pids, total_ram_mb, total_cpu
                    ),
                    suggested_actions: vec![
                        SuggestedAction {
                            description: format!("Tuer tous les processus \"{}\"", name),
                            command: format!("pkill -f '{}'", name),
                            risk: ActionRisk::Moderate,
                        },
                        SuggestedAction {
                            description: "Tuer par liste de PIDs".into(),
                            command: format!(
                                "kill {}",
                                pids.iter()
                                    .map(|p| p.to_string())
                                    .collect::<Vec<_>>()
                                    .join(" ")
                            ),
                            risk: ActionRisk::Moderate,
                        },
                    ],
                });
            }
        }
    }

    /// Detect orphaned development tool processes
    fn check_orphan_dev_processes(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let dev_patterns = [
            "mcp",
            "claude",
            "copilot",
            "lsp-server",
            "typescript-language-server",
        ];

        let orphans: Vec<&ProcessInfo> = snapshot
            .processes
            .iter()
            .filter(|p| {
                // Parent is init (orphaned) AND matches dev tool pattern
                (p.ppid == 1 || p.ppid == 0)
                    && dev_patterns
                        .iter()
                        .any(|pat| p.cmdline.to_lowercase().contains(pat))
                    && p.cpu_percent > 0.0
            })
            .collect();

        if !orphans.is_empty() {
            let total_ram: u64 = orphans.iter().map(|p| p.rss_mb).sum();
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::High,
                rule: "orphan_dev_processes".into(),
                title: format!(
                    "{} processus dev orphelin(s) détecté(s) ({} MB)",
                    orphans.len(),
                    total_ram
                ),
                details: orphans
                    .iter()
                    .map(|p| {
                        format!(
                            "  PID {} ({}) — {} MB, CPU {:.1}%, cmdline: {}",
                            p.pid,
                            p.name,
                            p.rss_mb,
                            p.cpu_percent,
                            &p.cmdline[..p.cmdline.len().min(100)]
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n"),
                suggested_actions: orphans
                    .iter()
                    .map(|p| SuggestedAction {
                        description: format!("Tuer {} (PID {})", p.name, p.pid),
                        command: format!("kill {}", p.pid),
                        risk: ActionRisk::Safe,
                    })
                    .collect(),
            });
        }
    }

    fn check_disk_space(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        for disk in &snapshot.disks {
            let free_percent = 100.0 - disk.usage_percent;
            if free_percent < self.config.thresholds.disk_min_free_percent {
                let severity = if free_percent < 3.0 {
                    Severity::Critical
                } else {
                    Severity::High
                };

                alerts.push(Alert {
                    timestamp: ts,
                    severity,
                    rule: "disk_space_low".into(),
                    title: format!(
                        "Disque {} presque plein : {:.1}% utilisé ({:.1} GB libre)",
                        disk.mount_point, disk.usage_percent, disk.available_gb
                    ),
                    details: format!(
                        "Point de montage: {}\nSystème de fichiers: {}\nTotal: {:.1} GB",
                        disk.mount_point, disk.filesystem, disk.total_gb
                    ),
                    suggested_actions: vec![
                        SuggestedAction {
                            description: "Nettoyer les journaux système".into(),
                            command: "sudo journalctl --vacuum-size=500M".into(),
                            risk: ActionRisk::Safe,
                        },
                        SuggestedAction {
                            description: "Trouver les gros fichiers".into(),
                            command: format!(
                                "du -sh {}/* 2>/dev/null | sort -rh | head -20",
                                disk.mount_point
                            ),
                            risk: ActionRisk::Safe,
                        },
                    ],
                });
            }
        }
    }

    fn check_oom_killer(
        &self,
        snapshot: &SystemSnapshot,
        alerts: &mut Vec<Alert>,
        ts: chrono::DateTime<chrono::Utc>,
    ) {
        let oom_entries: Vec<&JournalEntry> = snapshot
            .journal_entries
            .iter()
            .filter(|e| {
                let msg = e.message.to_lowercase();
                msg.contains("oom")
                    || msg.contains("out of memory")
                    || msg.contains("killed process")
            })
            .collect();

        if !oom_entries.is_empty() {
            alerts.push(Alert {
                timestamp: ts,
                severity: Severity::Critical,
                rule: "oom_killer".into(),
                title: format!(
                    "OOM Killer actif — {} événement(s) récent(s)",
                    oom_entries.len()
                ),
                details: oom_entries
                    .iter()
                    .take(5)
                    .map(|e| format!("  [{}] {}", e.unit, e.message))
                    .collect::<Vec<_>>()
                    .join("\n"),
                suggested_actions: vec![SuggestedAction {
                    description: "Identifier le processus le plus gourmand".into(),
                    command: "ps aux --sort=-%mem | head -10".into(),
                    risk: ActionRisk::Safe,
                }],
            });
        }
    }

    // --- Helpers ---

    fn top_processes_by_ram<'s>(
        &self,
        snapshot: &'s SystemSnapshot,
        n: usize,
    ) -> Vec<&'s ProcessInfo> {
        let mut procs: Vec<&ProcessInfo> = snapshot.processes.iter().collect();
        procs.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
        procs.into_iter().take(n).collect()
    }

    fn top_processes_by_cpu<'s>(
        &self,
        snapshot: &'s SystemSnapshot,
        n: usize,
    ) -> Vec<&'s ProcessInfo> {
        let mut procs: Vec<&ProcessInfo> = snapshot.processes.iter().collect();
        procs.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        procs.into_iter().take(n).collect()
    }

    fn is_ignored(&self, name: &str) -> bool {
        self.config
            .allowlist
            .ignore_commands
            .iter()
            .any(|cmd| name.contains(cmd))
    }

    fn is_protected(&self, name: &str) -> bool {
        self.config.allowlist.protected_commands.iter().any(|cmd| {
            if cmd.ends_with('*') {
                name.starts_with(&cmd[..cmd.len() - 1])
            } else {
                name == cmd
            }
        })
    }

    /// Normalize a process name for grouping duplicates
    fn normalize_process_name(cmdline: &str, name: &str) -> String {
        // For python/node scripts, use the script name as key
        let parts: Vec<&str> = cmdline.split_whitespace().collect();
        if parts.len() >= 2 {
            let exec = parts[0];
            if exec.contains("python") || exec.contains("node") || exec.contains("ruby") {
                // Use "python:script_name" as key
                let script = parts[1].rsplit('/').next().unwrap_or(parts[1]);
                return format!("{}:{}", exec.rsplit('/').next().unwrap_or(exec), script);
            }
        }
        name.to_string()
    }
}
