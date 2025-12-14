use bollard::{Docker, query_parameters::ListContainersOptions};
use log::info;
use std::collections::HashMap;

pub async fn run_docker_monitor() -> Result<(), anyhow::Error> {
    info!("Starting Docker monitor...");
    let docker = Docker::connect_with_socket_defaults()?;
    let options = Some(ListContainersOptions {
        all: true,
        limit: None,
        size: true,
        filters: Some(HashMap::from([("status".into(), vec!["running".into()])])),
    });
    let containers = docker.list_containers(options).await?;
    println!("{:?}", containers);

    Ok(())
}
