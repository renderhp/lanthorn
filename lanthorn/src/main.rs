use clap::Parser;
use log::info;

mod monitor;
mod utils;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let _args = Args::parse();
    env_logger::init();

    info!("Starting TCP connection monitor...");
    monitor::run_monitor().await?;

    info!("Monitor running. Press Ctrl+C to exit.");

    // Wait for Ctrl+C signal
    tokio::signal::ctrl_c().await?;
    info!("Shutting down...");

    Ok(())
}
