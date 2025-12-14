use bollard::{Docker, query_parameters::ListContainersOptions};
use log::info;
use std::{collections::HashMap, os::unix::fs::MetadataExt};

#[derive(Debug)]
struct MonitoredContainer {
    id: String,
    names: Vec<String>,
    image: String,
    pid: i64,
    cgroup_id: u64,
}

pub async fn run_docker_monitor() -> Result<(), anyhow::Error> {
    info!("Starting Docker monitor...");
    let docker = Docker::connect_with_socket_defaults()?;
    let options = Some(ListContainersOptions {
        all: true,
        limit: None,
        size: true,
        filters: Some(HashMap::from([("status".into(), vec!["running".into()])])),
    });
    let running_containers = docker.list_containers(options).await?;

    let mut docker_state: HashMap<String, MonitoredContainer> = HashMap::new();

    for container in running_containers {
        let pid = docker
            .inspect_container(
                container.id.clone().unwrap().as_str(),
                None::<bollard::query_parameters::InspectContainerOptions>,
            )
            .await
            .unwrap()
            .state
            .and_then(|v| v.pid)
            .unwrap();

        let cgroup_path = std::fs::read_to_string(format!("/proc/{}/cgroup", pid))?;
        let cgroup_path = cgroup_path
            .lines()
            .next()
            .and_then(|line| line.split("::").nth(1))
            .unwrap();
        let cgroup_path = format!("/sys/fs/cgroup/{}", cgroup_path);
        let cgroup_id = std::fs::metadata(&cgroup_path)?.ino();

        let item = MonitoredContainer {
            id: container.id.clone().unwrap(),
            names: container.names.unwrap(),
            image: container.image.unwrap(),
            pid,
            cgroup_id,
        };
        docker_state.insert(container.id.unwrap(), item);
    }

    println!("Existing Containers:\n{:#?}", docker_state);

    Ok(())
}
