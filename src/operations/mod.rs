// ZK mode operations
pub mod zk_transfer;

// Bridge operations (TEE ↔ ZK)
pub mod shield;
pub mod unshield;

pub use zk_transfer::{execute_zk_transfer, ZkTransferMsg};
pub use shield::{execute_shield, ShieldMsg};
pub use unshield::{execute_unshield, UnshieldMsg};
