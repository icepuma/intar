use crate::metrics::{fetch_metrics_text, labels_match, parse_prometheus_text};
use indexmap::IndexMap;
use intar_scenario::models::{Comparator, ProbeSpec, Scenario};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;

const FILE_CONTENT_METRIC: &str = "intar_agent_file_content";

fn eval_comparator(op: Comparator, observed: f64, expected: f64) -> bool {
    match op {
        Comparator::Eq => (observed - expected).abs() < f64::EPSILON,
        Comparator::Ne => (observed - expected).abs() >= f64::EPSILON,
        Comparator::Gt => observed > expected,
        Comparator::Ge => observed >= expected,
        Comparator::Lt => observed < expected,
        Comparator::Le => observed <= expected,
    }
}

fn find_sample<'a>(
    samples: &'a [crate::metrics::Sample],
    metric: &str,
    labels: &IndexMap<String, String>,
) -> Option<&'a crate::metrics::Sample> {
    samples
        .iter()
        .find(|s| s.name == metric && labels_match(&s.labels, labels))
}
#[derive(Clone, Debug)]
pub enum ProbeState {
    Waiting,
    MetricNotFound,
    Pending { value: f64 },
    Pass { value: f64 },
    Error(String),
}

#[derive(Clone)]
pub struct ProbeEntry {
    pub name: String,
    pub spec: ProbeSpec,
    pub state: ProbeState,
}

#[derive(Clone)]
pub struct VmProbes {
    pub vm_name: String,
    pub probes: Vec<ProbeEntry>,
}

#[derive(Clone)]
pub struct ProbesState {
    pub vms: Vec<VmProbes>,
}

fn build_vms_model(
    scenario: &Scenario,
    vm_names: &[String],
    default_interval_ms: u64,
) -> Vec<(String, String, Duration, Vec<ProbeEntry>)> {
    let sid = intar_local_backend::cloud_init::calculate_scenario_id(&scenario.name);
    let mut vms_model: Vec<(String, String, Duration, Vec<ProbeEntry>)> = Vec::new();
    for (idx, vm_name) in vm_names.iter().enumerate() {
        let Some(vm_cfg) = scenario.vm.get(vm_name) else {
            continue;
        };
        if vm_cfg.problems.is_empty() {
            continue;
        }
        let mut probes: Vec<ProbeEntry> = Vec::new();
        for prob_label in &vm_cfg.problems {
            if let Some(prob) = scenario.problems.get(prob_label) {
                for (probe_name, spec) in &prob.probes {
                    probes.push(ProbeEntry {
                        name: probe_name.clone(),
                        spec: spec.clone(),
                        state: ProbeState::Waiting,
                    });
                }
            }
        }
        if probes.is_empty() {
            continue;
        }
        let idx_u8 = u8::try_from(idx).unwrap_or(u8::MAX);
        let mport = intar_local_backend::constants::metrics_port(sid, idx_u8);
        let url = format!("http://127.0.0.1:{mport}/metrics");
        let interval_ms = probes
            .iter()
            .filter_map(|p| p.spec.interval_ms)
            .min()
            .unwrap_or(default_interval_ms);
        vms_model.push((
            vm_name.clone(),
            url,
            Duration::from_millis(interval_ms),
            probes,
        ));
    }
    vms_model
}

fn next_sleep_duration(
    vms: &[(String, String, Duration, Vec<ProbeEntry>)],
    default_interval_ms: u64,
) -> Duration {
    let mut next = Duration::from_millis(default_interval_ms);
    for (_, _, interval, probes) in vms {
        if probes
            .iter()
            .any(|p| !matches!(p.state, ProbeState::Pass { .. }))
            && *interval < next
        {
            next = *interval;
        }
    }
    next
}

pub fn spawn_probes_engine(
    scenario: &Scenario,
    vm_names: &[String],
) -> (JoinHandle<()>, Arc<Mutex<ProbesState>>) {
    let default_interval_ms: u64 = std::env::var("INTAR_PROBES_DEFAULT_INTERVAL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(1_000);
    let vms_model = build_vms_model(scenario, vm_names, default_interval_ms);

    let shared = Arc::new(Mutex::new(ProbesState {
        vms: vms_model
            .iter()
            .map(|(name, _, _, probes)| VmProbes {
                vm_name: name.clone(),
                probes: probes.clone(),
            })
            .collect(),
    }));

    let shared_clone = shared.clone();
    let handle = tokio::spawn(async move {
        let mut vms = vms_model;
        loop {
            // Scrape all VMs concurrently for faster updates
            let futs = vms
                .iter()
                .enumerate()
                .map(|(i, (_name, url, _interval, probes))| {
                    let url = url.clone();
                    let probes_snapshot = probes.clone();
                    async move {
                        match fetch_metrics_text(&url).await {
                            Ok(text) => {
                                let samples = parse_prometheus_text(&text);
                                let mut updated = probes_snapshot;
                                for p in &mut updated {
                                    match find_sample(&samples, &p.spec.metric, &p.spec.labels) {
                                        Some(s) => {
                                            if eval_comparator(p.spec.op, s.value, p.spec.value) {
                                                p.state = ProbeState::Pass { value: s.value };
                                            } else {
                                                p.state = ProbeState::Pending { value: s.value };
                                            }
                                        }
                                        None => {
                                            // If the metric encodes state via labels (like file content),
                                            // treat missing sample for the expected label as a failure so
                                            // regressions flip back immediately when content changes.
                                            if p.spec.metric == FILE_CONTENT_METRIC {
                                                p.state = ProbeState::MetricNotFound;
                                            } else {
                                                // Otherwise keep previous state to avoid flicker on brief gaps
                                            }
                                        }
                                    }
                                }
                                (i, updated)
                            }
                            Err(e) => {
                                let msg = format!("🚫 scrape error: {e}");
                                let mut updated = probes_snapshot;
                                for p in &mut updated {
                                    if !matches!(p.state, ProbeState::Pass { .. }) {
                                        p.state = ProbeState::Error(msg.clone());
                                    }
                                }
                                (i, updated)
                            }
                        }
                    }
                });

            let results = futures_util::future::join_all(futs).await;
            for (i, updated) in results {
                if let Some((_n, _u, _itv, dest)) = vms.get_mut(i) {
                    *dest = updated;
                }
            }

            // push state snapshot to shared
            {
                let mut guard = shared_clone.lock().await;
                guard.vms.clear();
                guard
                    .vms
                    .extend(vms.iter().map(|(name, _, _, probes)| VmProbes {
                        vm_name: name.clone(),
                        probes: probes.clone(),
                    }));
            }

            // sleep until next poll based on smallest interval among pending VMs
            let next = next_sleep_duration(&vms, default_interval_ms);
            tokio::time::sleep(next).await;
        }
    });

    (handle, shared)
}
