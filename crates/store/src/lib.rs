pub mod ipfs;
pub mod localdb;
mod schema;

pub use schema::*;



#[cfg(test)]
mod tests {
    use crate::localdb::LocalDB;

    #[tokio::test(flavor = "multi_thread")]
    async fn save_proof() -> Result<(), Box<dyn std::error::Error>> {
        let db_path = "/tmp/.bitvm2-node.db".to_string();
        let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let mut storage_process = local_db.acquire().await?;
        storage_process.create_proof(
            11111,
            "proof.test".to_string()
        ).await?;
        Ok(())
    }
}
