use lanthorn_common::ConnectEvent;

use crate::utils::ip_to_string;
use log::info;

pub async fn handle_event(event: ConnectEvent) {
    info!(
        "Connection: PID={}, Port={}, Family={}, CGroup={}",
        event.pid, event.port, event.family, event.cgroup_id
    );

    if let Some(ip_string) = ip_to_string(event.family, event.ip) {
        info!("{}", ip_string);
    }
}
