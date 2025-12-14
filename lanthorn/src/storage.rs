use anyhow::Ok;
use log::info;

pub async fn init() -> Result<(), anyhow::Error> {
    info!("Initialising storage...");
    Ok(())
}
