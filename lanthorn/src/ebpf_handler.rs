use lanthorn_common::ConnectEvent;

use log::info;

pub async fn handle_event(event: ConnectEvent) {
    info!(
        "Connection: PID={}, Port={}, Family={}, CGroup={}",
        event.pid, event.port, event.family, event.cgroup_id
    );

    // Pretty print IP address
    match event.family {
        2 => {
            // AF_INET
            info!(
                "  IPv4: {}.{}.{}.{}",
                event.ip[0], event.ip[1], event.ip[2], event.ip[3]
            );
        }
        10 => {
            // AF_INET6
            info!(
                "  IPv6: {:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
                event.ip[0],
                event.ip[1],
                event.ip[2],
                event.ip[3],
                event.ip[4],
                event.ip[5],
                event.ip[6],
                event.ip[7],
                event.ip[8],
                event.ip[9],
                event.ip[10],
                event.ip[11],
                event.ip[12],
                event.ip[13],
                event.ip[14],
                event.ip[15]
            );
        }
        _ => {}
    }
}
