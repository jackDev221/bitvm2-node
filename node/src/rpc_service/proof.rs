use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofsQueryParams {
    pub block_number: Option<i64>,
    #[serde(default = "default_block_range")]
    pub block_range: i64,
    pub graph_id: Option<String>,
}

// impl ProofsOverview{
//     // pub fn to_url_params() -> String{
//     //     let mut param = vec![];
//     //     if b
//     // }
// }

fn default_block_range() -> i64 {
    6
}

#[derive(Debug, Deserialize, Serialize)]
pub struct BlockProofs {
    pub block_number: i64,
    pub block_proof: Option<ProofItem>,
    pub aggregation_proof: Option<ProofItem>,
    pub groth16_proof: Option<ProofItem>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofItem {
    pub state: String,
    pub proving_time: i64,
    pub total_time_to_proof: i64,
    pub proof_size: f64,
    pub zkm_version: String,
    pub started_at: i64,
    pub updated_at: i64,
}

impl ProofItem {
    pub fn create_mock_data(&self, time_cast: i64) -> ProofItem {
        Self {
            state: self.state.clone(),
            started_at: self.updated_at + 500,
            updated_at: self.updated_at + 500 + time_cast,
            total_time_to_proof: time_cast,
            proof_size: self.proof_size,
            proving_time: time_cast,
            zkm_version: self.zkm_version.clone(),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Proofs {
    pub block_proofs: Vec<BlockProofs>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ProofsOverview {
    pub total_blocks: i64,
    pub avg_block_proof: f64,
    pub avg_aggregation_proof: f64,
    pub avg_groth16_proof: f64,
}
