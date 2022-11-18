use std::cell::RefCell;

use cosmrs::rpc::{self, Client as RpcClient};

use crate::{
    account::Account,
    crypto::{self, Decrypter, Nonce},
    CodeHash, Error, Result,
};

// the client query impl
mod query;
// the client tx impl
pub mod types;

pub struct Client {
    rpc: rpc::HttpClient,
    enclave_pubk: RefCell<Option<crypto::Key>>,
}

impl Client {
    pub(crate) fn init(
        rpc_host: &str,
        rpc_port: u16,
        enclave_key: Option<crypto::Key>,
    ) -> Result<Client> {
        let rpc_url = format!("{}:{}", rpc_host, rpc_port);
        let rpc = rpc::HttpClient::new(rpc_url.as_str())?;
        let enclave_pubk = RefCell::new(enclave_key);

        Ok(Client {
            rpc,
            enclave_pubk,
        })
    }

    async fn enclave_public_key(&self) -> Result<crypto::Key> {
        if let Some(pubk) = self.enclave_pubk.borrow().as_ref() {
            return Ok(*pubk);
        }

        let key = self.query_tx_key().await?;

        let pubk = crypto::cert::consenus_io_pubk(&key)?;

        self.enclave_pubk.replace(Some(pubk));

        Ok(pubk)
    }

    async fn encrypt_msg<M: serde::Serialize>(
        &self,
        msg: &M,
        code_hash: &CodeHash,
        account: &Account,
    ) -> Result<(Nonce, Vec<u8>)> {
        let msg = serde_json::to_vec(msg).expect("msg cannot be serialized as JSON");
        let plaintext = [code_hash.to_hex_string().as_bytes(), msg.as_slice()].concat();
        self.encrypt_msg_raw(&plaintext, account).await
    }

    async fn encrypt_msg_raw(&self, msg: &[u8], account: &Account) -> Result<(Nonce, Vec<u8>)> {
        let (prvk, pubk) = account.prv_pub_bytes();
        let io_key = self.enclave_public_key().await?;
        let nonce_ciphertext = crypto::encrypt(&prvk, &pubk, &io_key, msg)?;
        Ok(nonce_ciphertext)
    }

    async fn decrypter(&self, nonce: &Nonce, account: &Account) -> Result<Decrypter> {
        let (secret, _) = account.prv_pub_bytes();
        let io_key = self.enclave_public_key().await?;
        Ok(Decrypter::new(secret, io_key, *nonce))
    }

}

async fn wait_for_first_block(client: &rpc::HttpClient) -> Result<()> {
    const HEALTHY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);
    const BLOCK_ATTEMPT_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
    const BLOCK_ATTEMPTS: usize = 20;

    client
        .wait_until_healthy(HEALTHY_TIMEOUT)
        .await
        .map_err(|_| Error::FirstBlockTimeout(HEALTHY_TIMEOUT.as_secs() as _))?;

    for _ in 0..BLOCK_ATTEMPTS {
        if (client.latest_block().await).is_ok() {
            return Ok(());
        }
        tokio::time::sleep(BLOCK_ATTEMPT_INTERVAL).await;
    }

    Err(Error::FirstBlockTimeout(
        (HEALTHY_TIMEOUT.as_millis()
            + (BLOCK_ATTEMPTS as u128 * BLOCK_ATTEMPT_INTERVAL.as_millis()))
            / 1000,
    ))
}
