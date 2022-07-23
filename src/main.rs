use anyhow::{Ok, Result};
use std::{env, str::FromStr};
use web3::types::Address;

mod eth_wallet;
mod utils;

fn create_new_wallet(wallet_file_path: &str) -> Result<eth_wallet::Wallet> {
    let (secret_key, public_key) = eth_wallet::generate_keypair();

    let pub_address = eth_wallet::public_key_address(&public_key);
    println!("public address: {:?}", pub_address);

    let crypto_wallet = eth_wallet::Wallet::new(&secret_key, &public_key);

    crypto_wallet.save_to_file(wallet_file_path)?;

    Ok(crypto_wallet)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv::dotenv().ok();
    let wallet_file_path = "crypto_wallet.json";

    // let crypto_wallet = create_new_wallet(wallet_file_path)?;
    // crypto_wallet.save_to_file(wallet_file_path)?;

    let crypto_wallet = eth_wallet::Wallet::from_file(wallet_file_path)?;
    println!("crypto_wallet: {:?}", crypto_wallet);

    let ws_endpoint = env::var("INFURA_RINKEBY_WS")?;
    let web3_conn = eth_wallet::establish_web3_connection(&ws_endpoint).await?;

    let block_number = web3_conn.eth().block_number().await?;
    println!("block number: {}", &block_number);

    let balance = crypto_wallet.get_wallet_balance_in_eth(&web3_conn).await?;
    println!("wallet balance: {}", &balance);

    println!("sending 0.001 ETH");
    let transaction = eth_wallet::create_eth_transaction(
        Address::from_str("0xb0559F21745dD59150530785bBBd4e1F694D9d92")?,
        0.001,
    );
    let transaction_hash =
        eth_wallet::sign_and_send(&web3_conn, transaction, &crypto_wallet.get_secret_key()?)
            .await?;
    println!("transaction hash: {:?}", transaction_hash);

    let balance = crypto_wallet.get_wallet_balance_in_eth(&web3_conn).await?;
    println!("wallet balance: {}", &balance);

    Ok(())
}
