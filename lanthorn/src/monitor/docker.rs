use bollard::{
    Docker,
    query_parameters::{EventsOptions, ListContainersOptions},
    secret::ContainerSummary,
};
use futures::StreamExt;
use log::{debug, error, info, warn};
use std::{collections::HashMap, os::unix::fs::MetadataExt, sync::Arc};
use tokio::sync::RwLock;

pub type DockerCache = Arc<RwLock<HashMap<u64, MonitoredContainer>>>;

#[derive(Debug, Clone)]
pub struct MonitoredContainer {
    pub id: String,
    pub names: Option<Vec<String>>,
    pub image: Option<String>,
    pub pid: i64,
    pub cgroup_id: u64,
}

pub async fn run_docker_monitor(cache: DockerCache) -> Result<(), anyhow::Error> {
    info!("Starting Docker monitor...");
    let docker = Docker::connect_with_socket_defaults()?;

    // Load initial state of running containers
    load_running_containers(&docker, &cache).await?;

    // Subscribe to Docker events and watch for container start/stop
    watch_container_events(&docker, &cache).await
}

/// Load all currently running containers into the cache
async fn load_running_containers(docker: &Docker, cache: &DockerCache) -> Result<(), anyhow::Error> {
    let options = Some(ListContainersOptions {
        all: true,
        limit: None,
        size: true,
        filters: Some(HashMap::from([("status".into(), vec!["running".into()])])),
    });
    let running_containers = docker.list_containers(options).await?;

    for container in running_containers {
        if let Some(item) = get_monitored_container(docker, &container).await {
            let mut state = cache.write().await;
            info!("Adding container {} to cache", item.id);
            state.insert(item.cgroup_id, item);
        } else {
            error!(
                "Failed to insert container with ID {:?} to cache",
                &container.id,
            )
        }
    }

    let state = cache.read().await;
    info!("Loaded {} existing containers into cache", state.len());
    debug!("Existing Containers:\n{:#?}", *state);
    Ok(())
}

/// Watch for Docker container events and update the cache accordingly
async fn watch_container_events(docker: &Docker, cache: &DockerCache) -> Result<(), anyhow::Error> {
    info!("Subscribing to Docker container events...");

    // Filter for container events only
    let options = EventsOptions {
        filters: Some(HashMap::from([("type".into(), vec!["container".into()])])),
        ..Default::default()
    };

    let mut events_stream = docker.events(Some(options));

    while let Some(event_result) = events_stream.next().await {
        match event_result {
            Ok(event) => {
                let action = event.action.as_deref().unwrap_or("");
                let actor = event.actor.as_ref();
                let container_id = actor.and_then(|a| a.id.as_deref());

                debug!("Docker event: action={}, container_id={:?}", action, container_id);

                match action {
                    "start" => {
                        if let Some(id) = container_id {
                            handle_container_start(docker, cache, id).await;
                        }
                    }
                    "stop" | "die" | "kill" => {
                        if let Some(id) = container_id {
                            handle_container_stop(cache, id).await;
                        }
                    }
                    _ => {
                        // Ignore other events (create, pause, unpause, etc.)
                    }
                }
            }
            Err(e) => {
                error!("Error receiving Docker event: {}", e);
                // Continue listening for events even after an error
            }
        }
    }

    warn!("Docker events stream ended unexpectedly");
    Ok(())
}

/// Handle a container start event by adding it to the cache
async fn handle_container_start(docker: &Docker, cache: &DockerCache, container_id: &str) {
    info!("Container started: {}", container_id);

    // Get container details via inspect
    match docker
        .inspect_container(
            container_id,
            None::<bollard::query_parameters::InspectContainerOptions>,
        )
        .await
    {
        Ok(info) => {
            let pid = match info.state.and_then(|s| s.pid) {
                Some(p) => p,
                None => {
                    error!("Could not get PID for started container {}", container_id);
                    return;
                }
            };

            match get_cgroup_id(pid) {
                Some(cgroup_id) => {
                    let monitored = MonitoredContainer {
                        id: container_id.to_string(),
                        names: info.name.map(|n| vec![n]),
                        image: info.config.and_then(|c| c.image),
                        pid,
                        cgroup_id,
                    };

                    let mut state = cache.write().await;
                    info!(
                        "Adding started container {} (cgroup_id={}) to cache",
                        container_id, cgroup_id
                    );
                    state.insert(cgroup_id, monitored);
                }
                None => {
                    error!(
                        "Could not get cgroup ID for started container {}",
                        container_id
                    );
                }
            }
        }
        Err(e) => {
            error!("Failed to inspect started container {}: {}", container_id, e);
        }
    }
}

/// Handle a container stop event by removing it from the cache
async fn handle_container_stop(cache: &DockerCache, container_id: &str) {
    info!("Container stopped: {}", container_id);

    let mut state = cache.write().await;

    // Find and remove the container by ID
    let cgroup_id_to_remove = state
        .iter()
        .find(|(_, c)| c.id == container_id)
        .map(|(cgroup_id, _)| *cgroup_id);

    if let Some(cgroup_id) = cgroup_id_to_remove {
        state.remove(&cgroup_id);
        info!(
            "Removed stopped container {} (cgroup_id={}) from cache",
            container_id, cgroup_id
        );
    } else {
        debug!(
            "Container {} not found in cache (may have already been removed)",
            container_id
        );
    }
}

/// Get the cgroup ID (inode number) for a given PID
fn get_cgroup_id(pid: i64) -> Option<u64> {
    let cgroup_path = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .inspect_err(|e| error!("Failed to read /proc/{}/cgroup: {}", pid, e))
        .ok()?;

    let cgroup_path = cgroup_path
        .lines()
        .next()
        .and_then(|line| line.split("::").nth(1))
        .or_else(|| {
            error!("Failed to parse cgroup path from /proc/{}/cgroup", pid);
            None
        })?;

    let full_path = format!("/sys/fs/cgroup/{}", cgroup_path);
    let cgroup_id = std::fs::metadata(&full_path)
        .inspect_err(|e| error!("Failed to get metadata for {}: {}", full_path, e))
        .ok()?
        .ino();

    Some(cgroup_id)
}

async fn get_monitored_container(
    docker: &Docker,
    container: &ContainerSummary,
) -> Option<MonitoredContainer> {
    let Some(id) = container.id.clone() else {
        error!("ID missing from container {:?}. Skipping...", &container);
        return None;
    };

    let info = docker
        .inspect_container(
            &id,
            None::<bollard::query_parameters::InspectContainerOptions>,
        )
        .await
        .inspect_err(|e| error!("Failed to inspect container {}: {}", id, e))
        .ok()?;

    let pid = info.state.and_then(|v| v.pid).or_else(|| {
        error!("Couldn't get pid for container with id: {}", &id);
        None
    })?;

    let cgroup_path = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))
        .inspect_err(|e| {
            error!(
                "Failed to get cgroup path for container with ID {}: {}",
                &id, e
            )
        })
        .ok()?;

    let cgroup_path = cgroup_path
        .lines()
        .next()
        .and_then(|line| line.split("::").nth(1))
        .or_else(|| {
            error!("Failed to parse cgroup path from /proc/{}/cgroup", pid);
            None
        })?;
    let cgroup_path = format!("/sys/fs/cgroup/{}", cgroup_path);
    let cgroup_id = std::fs::metadata(&cgroup_path)
        .inspect_err(|e| {
            error!(
                "Failed to fetch metadata for container with ID {}: {}",
                &id, e
            )
        })
        .ok()?
        .ino();

    Some(MonitoredContainer {
        id,
        names: container.names.clone(),
        image: container.image.clone(),
        pid,
        cgroup_id,
    })
}
