use anyhow::{Context, Result};
use serde_json::json;
use std::time::Instant;

use crate::config::AiConfig;
use crate::types::*;

pub struct AiAnalyzer {
    client: reqwest::Client,
    config: AiConfig,
    last_call: Option<Instant>,
}

impl AiAnalyzer {
    pub fn new(config: AiConfig) -> Self {
        Self {
            client: reqwest::Client::new(),
            config,
            last_call: None,
        }
    }

    /// Check if we can make an API call (respecting cooldown)
    fn can_call(&self) -> bool {
        match self.last_call {
            Some(last) => last.elapsed().as_secs() >= self.config.cooldown_secs,
            None => true,
        }
    }

    /// Analyze alerts with AI context for better diagnostics
    pub async fn analyze(
        &mut self,
        snapshot: &SystemSnapshot,
        alerts: &[Alert],
    ) -> Result<Option<AiDiagnostic>> {
        if !self.config.enabled || alerts.is_empty() || !self.can_call() {
            return Ok(None);
        }

        let api_key = std::env::var(&self.config.api_key_env)
            .context(format!("Missing env var: {}", self.config.api_key_env))?;

        let prompt = self.build_prompt(snapshot, alerts);

        let body = json!({
            "model": self.config.model,
            "max_tokens": self.config.max_tokens,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "system": "Tu es un expert Linux sysadmin. Tu analyses des situations système et proposes des actions correctives. Réponds UNIQUEMENT en JSON valide, sans markdown ni backticks. Le JSON doit suivre ce schéma : {\"diagnostic\": \"string\", \"severity\": \"critical|high|medium|low\", \"actions\": [{\"type\": \"string\", \"target\": \"string\", \"command\": \"string\", \"risk\": \"safe|moderate|dangerous\", \"explanation\": \"string\"}], \"prevention\": \"string\"}"
        });

        let response = self
            .client
            .post("https://api.anthropic.com/v1/messages")
            .header("x-api-key", &api_key)
            .header("anthropic-version", "2023-06-01")
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .await
            .context("Failed to call Claude API")?;

        self.last_call = Some(Instant::now());

        if !response.status().is_success() {
            let status = response.status();
            let text = response
                .text()
                .await
                .unwrap_or_else(|_| "unknown".into());
            anyhow::bail!("Claude API error {}: {}", status, text);
        }

        let resp_json: serde_json::Value = response
            .json()
            .await
            .context("Failed to parse Claude API response")?;

        // Extract text from Claude's response
        let text = resp_json["content"]
            .as_array()
            .and_then(|arr| arr.first())
            .and_then(|block| block["text"].as_str())
            .unwrap_or("");

        // Parse the JSON response from Claude
        let clean_text = text
            .trim()
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim();

        match serde_json::from_str::<AiDiagnostic>(clean_text) {
            Ok(diagnostic) => Ok(Some(diagnostic)),
            Err(e) => {
                tracing::warn!(
                    "Failed to parse AI response as JSON: {}. Raw: {}",
                    e,
                    &clean_text[..clean_text.len().min(200)]
                );
                Ok(None)
            }
        }
    }

    fn build_prompt(&self, snapshot: &SystemSnapshot, alerts: &[Alert]) -> String {
        let mem = &snapshot.memory;
        let cpu = &snapshot.cpu;

        // Top 10 processes by RAM
        let mut procs_by_ram = snapshot.processes.clone();
        procs_by_ram.sort_by(|a, b| b.rss_mb.cmp(&a.rss_mb));
        let top_ram: String = procs_by_ram
            .iter()
            .take(10)
            .map(|p| {
                format!(
                    "  PID={} name={} cmd=\"{}\" RAM={}MB CPU={:.1}% state={} ppid={}",
                    p.pid,
                    p.name,
                    &p.cmdline[..p.cmdline.len().min(80)],
                    p.rss_mb,
                    p.cpu_percent,
                    p.state,
                    p.ppid
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Top 10 by CPU
        let mut procs_by_cpu = snapshot.processes.clone();
        procs_by_cpu.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let top_cpu: String = procs_by_cpu
            .iter()
            .take(10)
            .map(|p| {
                format!(
                    "  PID={} name={} CPU={:.1}% RAM={}MB",
                    p.pid, p.name, p.cpu_percent, p.rss_mb
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        // Alerts summary
        let alerts_summary: String = alerts
            .iter()
            .map(|a| format!("  [{:?}] {}: {}", a.severity, a.rule, a.title))
            .collect::<Vec<_>>()
            .join("\n");

        // Journal entries
        let journal: String = snapshot
            .journal_entries
            .iter()
            .take(10)
            .map(|e| format!("  [prio={}] [{}] {}", e.priority, e.unit, e.message))
            .collect::<Vec<_>>()
            .join("\n");

        format!(
            r#"Analyse cette situation système Linux et propose des actions correctives.

## État système
- RAM: {used_mb}/{total_mb} MB ({usage_pct:.1}%), disponible: {avail_mb} MB
- Swap: {swap_used}/{swap_total} MB ({swap_pct:.1}%)
- CPU: load {load1:.2}/{load5:.2}/{load15:.2} ({cores} cœurs), usage global: {cpu_usage:.1}%
- Processus totaux: {proc_count}

## Top processus par RAM
{top_ram}

## Top processus par CPU
{top_cpu}

## Alertes détectées par les règles
{alerts_summary}

## Derniers journaux système (warning+)
{journal}

Analyse la situation, identifie la cause racine, et propose des actions concrètes."#,
            used_mb = mem.used_mb,
            total_mb = mem.total_mb,
            usage_pct = mem.usage_percent,
            avail_mb = mem.available_mb,
            swap_used = mem.swap_used_mb,
            swap_total = mem.swap_total_mb,
            swap_pct = mem.swap_percent,
            load1 = cpu.load_avg_1m,
            load5 = cpu.load_avg_5m,
            load15 = cpu.load_avg_15m,
            cores = cpu.core_count,
            cpu_usage = cpu.global_usage_percent,
            proc_count = snapshot.processes.len(),
            top_ram = top_ram,
            top_cpu = top_cpu,
            alerts_summary = alerts_summary,
            journal = if journal.is_empty() {
                "  (aucune entrée récente)".into()
            } else {
                journal
            },
        )
    }
}
