use crate::client::chain::chain_adaptor::*;
use alloy::primitives::TxHash;
use async_trait::async_trait;
use uuid::Uuid;

pub struct MockAdaptorConfig {}

pub struct MockAdaptor {
    _config: Option<MockAdaptorConfig>,
}

#[async_trait]
impl ChainAdaptor for MockAdaptor {
    async fn get_finalized_block_number(&self) -> anyhow::Result<i64> {
        todo!()
    }

    async fn pegin_tx_used(&self, _tx_id: &[u8; 32]) -> anyhow::Result<bool> {
        todo!()
    }

    async fn get_pegin_data(&self, _instance_id: &Uuid) -> anyhow::Result<PeginData> {
        todo!()
    }

    async fn is_operator_withdraw(&self, _graph_id: &Uuid) -> anyhow::Result<bool> {
        todo!()
    }

    async fn get_withdraw_data(&self, _graph_id: &Uuid) -> anyhow::Result<WithdrawData> {
        todo!()
    }

    async fn get_operator_data(&self, _graph_id: &Uuid) -> anyhow::Result<OperatorData> {
        todo!()
    }

    async fn post_pegin_data(
        &self,
        _instance_id: &Uuid,
        _raw_pgin_tx: &BitcoinTx,
        _raw_header: &[u8],
        _height: u64,
        _proof: &[[u8; 32]],
        _index: u64,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn post_operator_data(
        &self,
        _instance_id: &Uuid,
        _graph_id: &Uuid,
        _operator_data: &OperatorData,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn post_operator_data_batch(
        &self,
        _instance_id: &Uuid,
        _graph_ids: &[Uuid],
        _operator_datas: &[OperatorData],
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn get_btc_block_hash(&self, _height: u64) -> anyhow::Result<[u8; 32]> {
        todo!()
    }

    async fn parse_btc_block_header(
        &self,
        _raw_header: &[u8],
    ) -> anyhow::Result<([u8; 32], [u8; 32])> {
        todo!()
    }

    async fn get_initialized_ids(&self) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        todo!()
    }

    async fn get_instanceids_by_pubkey(
        &self,
        _operator_pubkey: &[u8; 32],
    ) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
        todo!()
    }

    async fn init_withdraw(&self, _instance_id: &Uuid, _graph_id: &Uuid) -> anyhow::Result<String> {
        todo!()
    }

    async fn cancel_withdraw(&self, _graph_id: &Uuid) -> anyhow::Result<String> {
        todo!()
    }

    async fn process_withdraw(
        &self,
        _graph_id: &Uuid,
        _raw_kickoff_tx: &BitcoinTx,
        _raw_header: &[u8],
        _height: u64,
        _proof: &[[u8; 32]],
        _index: u64,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn finish_withdraw_happy_path(
        &self,
        _graph_id: &Uuid,
        _raw_take1_tx: &BitcoinTx,
        _raw_header: &[u8],
        _height: u64,
        _proof: &[[u8; 32]],
        _index: u64,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn finish_withdraw_unhappy_path(
        &self,
        _graph_id: &Uuid,
        _raw_take2_tx: &BitcoinTx,
        _raw_header: &[u8],
        _height: u64,
        _proof: &[[u8; 32]],
        _index: u64,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn finish_withdraw_disproved(
        &self,
        _graph_id: &Uuid,
        _raw_disproved_tx: &BitcoinTx,
        _raw_header: &[u8],
        _height: u64,
        _proof: &[[u8; 32]],
        _index: u64,
    ) -> anyhow::Result<String> {
        todo!()
    }

    async fn verify_merkle_proof(
        &self,
        _root: &[u8; 32],
        _proof: &[[u8; 32]],
        _pleaf: &[u8; 32],
        _pindex: u64,
    ) -> anyhow::Result<bool> {
        Ok(true)
    }

    async fn is_tx_execute_success(&self, _tx_hash: TxHash) -> anyhow::Result<bool> {
        todo!()
    }
}

impl MockAdaptor {
    pub fn new(_config: Option<MockAdaptorConfig>) -> Self {
        Self { _config }
    }
}
