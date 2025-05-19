pub mod chain;
pub mod client;
pub mod esplora;

#[cfg(test)]
mod tests {
    use crate::chain::chain_adaptor::GoatNetwork;
    use crate::chain::goat_adaptor::GoatInitConfig;
    use crate::client::BitVM2Client;
    use bitcoin::hashes::Hash;
    use bitcoin::{Network, Transaction, Txid};
    use std::str::FromStr;

    #[tokio::test]
    async fn test_spv_check() {
        let global_init_config = GoatInitConfig::from_env_for_test();
        //  let local_db = LocalDB::new(&format!("sqlite:{db_path}"), true).await;
        let tmp_db = tempfile::NamedTempFile::new().unwrap();
        let client = BitVM2Client::new(
            tmp_db.path().as_os_str().to_str().unwrap(),
            None,
            Network::Testnet,
            GoatNetwork::Test,
            global_init_config,
            "http://localhost:5001",
        )
        .await;
        let tx_id =
            Txid::from_str("cd557f6656051531ab53d08a43524330b39344bb98b710461450feda4ff4b231")
                .expect("decode txid");

        let (root, proof_info, _) =
            client.get_bitc_merkle_proof(&tx_id).await.expect("call merkle proof");
        let root = root.to_byte_array().map(|v| v);
        let proof: Vec<[u8; 32]> =
            proof_info.merkle.iter().map(|v| v.to_byte_array().map(|v| v)).collect();
        let res = client
            .verify_merkle_proof(&root, &proof, &tx_id.to_byte_array(), proof_info.pos as u64)
            .await
            .expect("get result");
        assert!(res);
    }

    #[test]
    fn check_transaction() {
        let hex_str = "02000000000101e5de4c304096aa9d5db86b9c18625e633b666caf5be6be73e99fc1554abd46a90100000000ffffffff01ae93040000000000220020325342861a5a027fc0449ced265c6cdc6b3ebd9b16ec5857519ed4aa50f40c080341e6d4ed2de0a15c243fd6e108012538865ea0811090b8c3070b52587ada02933f1175c349fe210f5856deb3228eee67fca189bf9646f9d5b0c9ff435a82eb9384832220484db4a2950d63da8455a1b705b39715e4075dd33511d0c7e3ce308c93449debac41c1f4f0ec162f6d1ce98bfe0b27ea1ebb579b9a95131ac7efeb40c7b27726da671addda6aa7663c9206e3d6c33c443bf253619feff8fc4f816cbe3745c7c97297f800000000";
        let structed_tx: Transaction =
            bitcoin::consensus::encode::deserialize_hex(hex_str).expect("");
        let tx_id = structed_tx.compute_txid().to_string();
        println!("dddd");
        for input in structed_tx.input {
            println!("{:?}", input.previous_output)
        }

        println!("{}", tx_id)
    }
}
