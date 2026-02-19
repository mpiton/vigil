use std::time::Duration;

use crate::application::services::monitor::MonitorService;

/// Run the monitoring daemon loop at the configured interval.
///
/// # Errors
///
/// Returns an error if the initial monitoring cycle fails catastrophically.
pub async fn run_daemon(service: &MonitorService<'_>, interval_secs: u64) -> anyhow::Result<()> {
    println!("Démarrage du daemon vigil (intervalle : {interval_secs}s)...");
    let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        interval.tick().await;
        match service.run_once().await {
            Ok(result) => {
                tracing::info!(
                    "Cycle terminé : {} alerte(s), snapshot {}",
                    result.alerts_count,
                    if result.snapshot_saved {
                        "sauvegardé"
                    } else {
                        "échoué"
                    }
                );
            }
            Err(e) => {
                tracing::error!("Erreur cycle monitoring : {e}");
            }
        }
    }
}
