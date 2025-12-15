use bollard::{Docker, query_parameters::ListContainersOptions, secret::ContainerSummary};
use log::{error, info};
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
    let options = Some(ListContainersOptions {
        all: true,
        limit: None,
        size: true,
        filters: Some(HashMap::from([("status".into(), vec!["running".into()])])),
    });
    let running_containers = docker.list_containers(options).await?;

    for container in running_containers {
        if let Some(item) = get_monitored_container(&docker, &container).await {
            let mut state = cache.write().await;
            state.insert(item.cgroup_id, item);
        } else {
            error!(
                "Failed to insert container with ID {:?} to cache",
                &container.id,
            )
        }
    }

    let state = cache.read().await;
    println!("Existing Containers:\n{:#?}", state);
    Ok(())
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
