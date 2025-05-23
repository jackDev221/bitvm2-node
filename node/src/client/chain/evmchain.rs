use crate::client::chain::chain_adaptor::ChainAdaptor;
use crate::client::chain::mock_adaptor::MockAdaptor;

pub struct EvmChain {
    pub adaptor: Box<dyn ChainAdaptor + Send + Sync>,
}
impl Default for EvmChain {
    fn default() -> Self {
        Self::new(Box::new(MockAdaptor::new(None)))
    }
}
impl EvmChain {
    pub fn new(adaptor: Box<dyn ChainAdaptor>) -> Self {
        Self { adaptor }
    }
}
