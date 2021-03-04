use bitcoin_hashes::{sha256d::Hash as Sha256dHash, Hash};
use bitcoin_hashes::hex::FromHex;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::{BlockHash, Txid};

use rusoto_core::Region;
use rusoto_dynamodb::{DynamoDb, DynamoDbClient, ScanInput};
use rusoto_sqs::{ReceiveMessageRequest, Sqs, SqsClient, DeleteMessageRequest, GetQueueUrlRequest, GetQueueUrlResult, SendMessageRequest};

use std::default::Default;
use std::env;
use std::format;
use std::sync::{Arc};
use std::sync::mpsc::{SyncSender};
use std::collections::{HashMap, HashSet};
use serde_json::Value;
use std::time::Instant;

use crate::errors::*;
use crate::index::compute_script_hash;
use crate::query::{Query};
use crate::util::{spawn_thread, SyncChannel, HeaderEntry, FullHash};
use std::sync::atomic::{AtomicBool, Ordering};

fn get_output_scripthash(txn: &Transaction, n: Option<usize>) -> Vec<FullHash> {
    if let Some(out) = n {
        vec![compute_script_hash(&txn.output[out].script_pubkey[..])]
    } else {
        txn.output
            .iter()
            .map(|o| compute_script_hash(&o.script_pubkey[..]))
            .collect()
    }
}

#[derive(Debug)]
pub enum ScriptHashCompareMessage {
    Start
}

pub struct ScriptHashComparer {
    query: Arc<Query>,
    pub chan: SyncChannel<ScriptHashCompareMessage>,
    notifications_sender: SyncSender<SubscriptionMessage>,
    in_progress: Arc<AtomicBool>
}

impl ScriptHashComparer {
    pub fn new(query: Arc<Query>, notifications_sender: SyncSender<SubscriptionMessage>, in_progress: Arc<AtomicBool>) -> ScriptHashComparer {
        ScriptHashComparer {
            query,
            chan: SyncChannel::new(3),
            notifications_sender,
            in_progress
        }
    }

    fn compare_status_hashes(&mut self) {
        info!("compare_status_hashes begin");
        self.in_progress.store(true, Ordering::Relaxed);
        let script_hashes_res = SubscriptionsManager::get_script_hashes();
        if script_hashes_res.is_err() {
            return ()
        }
        let script_hashes = script_hashes_res.unwrap();
        info!("compare_status_hashes: script_hashes.len() = {}, starting", script_hashes.len());
        let now = Instant::now();
        for (i, (scripthash, old_statushash)) in script_hashes.iter().enumerate() {
            if i % 1000 == 0 {
                info!("Comparing scripthash #{}", i);
            }

            let scripthash_buffer = scripthash.into_inner();
            let status_result = self.query.status(&scripthash_buffer);
            if status_result.is_err() {
                warn!("compare_status_hashes error - {}", status_result.err().unwrap());
                continue;
            }
            let status = status_result.unwrap();
            let new_statushash = status.hash().map_or(Value::Null, |h| json!(hex::encode(h)));
            if new_statushash == *old_statushash {
                continue;
            }

            info!("compare_status_hashes: found diff. scripthash = {}, old_statushash = {}, new_statushash = {}", scripthash, old_statushash, new_statushash);
            if let Err(_) = self.notifications_sender.send(SubscriptionMessage::ScriptHashChange(scripthash_buffer, None)) {
                warn!("compare_status_hashes: send failed because the channel is closed, shutting down")
            }
        }

        info!("compare_status_hashes: script_hashes.len() = {}, took {} seconds", script_hashes.len(), now.elapsed().as_secs());
        self.in_progress.store(false, Ordering::Relaxed);
    }

    pub fn handle_request(&mut self) -> Result<()> {
        debug!("compare_status_hashes listener started");
        loop {
            let msg = self.chan.receiver().recv().chain_err(|| "channel closed")?;
            match msg {
                ScriptHashCompareMessage::Start => self.compare_status_hashes(),
            }
        }
    }
}

#[derive(Debug)]
pub enum SubscriptionMessage {
    NewScriptHash(String),
    ScriptHashChange(FullHash, Option<FullHash>),
    Done,
}

struct SubscriptionsHandler {
    query: Arc<Query>,
    script_hashes: HashMap<Sha256dHash, Value>, // ScriptHash -> StatusHash
    chan: SyncChannel<SubscriptionMessage>,
    tx_notification_url: String,
}

impl SubscriptionsHandler {
    pub fn new(
        query: Arc<Query>,
        script_hashes: HashMap<Sha256dHash, Value>,
        env: String
    ) -> SubscriptionsHandler {
        let tx_notification_url = SubscriptionsHandler::get_sqs_queue_for_txs_notifications(env);

        SubscriptionsHandler {
            query,
            script_hashes,
            chan: SyncChannel::new(100),
            tx_notification_url
        }
    }

    fn get_sqs_queue_for_txs_notifications(env: String) -> String {
        let sqs = SqsClient::new(Region::UsWest2);

        let queue_name = format!("Bitcoin_Tx_Event_{}.fifo", env);

        let get_queue_by_name_request = GetQueueUrlRequest {
            queue_name: queue_name.clone(),
            ..Default::default()
        };

        let response: GetQueueUrlResult = sqs
            .get_queue_url(get_queue_by_name_request)
            .sync()
            .expect("Get queue by URL request failed");

        response.queue_url
            .expect("Queue url should be available from list queues")
    }

    fn subscribe_script_hash(&mut self, script_hash: String) -> Result<()> {
        let script_hash = Sha256dHash::from_hex(script_hash.as_str()).chain_err(|| "bad script_hash")?;

        let status = self.query.status(&script_hash[..])?;
        let result = status.hash().map_or(Value::Null, |h| json!(hex::encode(h)));
        self.script_hashes.insert(script_hash, result.clone());
        debug!("Subscribed script_hash: {}", script_hash);
        Ok(())
    }

    fn notify_scripthash_subscriptions(&mut self, scripthash: FullHash, txid_opt: Option<FullHash>) -> Result<()> {
        let scripthash = Sha256dHash::from_slice(&scripthash[..]).expect("invalid scripthash");
        let txid_opt = txid_opt.map(|txid| Sha256dHash::from_slice(&txid[..]).expect("invalid txid"));

        let old_statushash;
        match self.script_hashes.get(&scripthash) {
            Some(statushash) => {
                debug!("notify_scripthash_subscriptions: scripthash = {}, statushash = {}{}",
                       scripthash,
                       statushash,
                       txid_opt.map_or("".to_string(), |txid| format!(", txid = {}", txid))
                );
                old_statushash = statushash;
            }
            None => {
                return Ok(());
            }
        };

        let status_result = self.query.status(&scripthash[..]);
        if status_result.is_err() {
            warn!("notify_scripthash_subscriptions error - {}", status_result.err().unwrap());
            return Ok(());
        }
        let status = status_result.unwrap();
        let new_statushash = status.hash().map_or(Value::Null, |h| json!(hex::encode(h)));
        if new_statushash == *old_statushash {
            return Ok(());
        }

        debug!("notify_scripthash_subscriptions: scripthash = {}, old_statushash = {}, new_statushash = {}{}",
               scripthash,
               old_statushash,
               new_statushash,
               txid_opt.map_or("".to_string(), |txid| format!(", txid = {}", txid))
        );

        let msg_str = json!({
            "script_hash": scripthash,
            "status_hash": new_statushash
        }).to_string();

        let send_msg_request = SendMessageRequest {
            message_body: msg_str.clone(),
            message_group_id: Option::from(String::from(new_statushash.clone().as_str().unwrap())),
            queue_url: self.tx_notification_url.clone(),
            ..Default::default()
        };

        let sqs = SqsClient::new(Region::UsWest2);

        let response = sqs.send_message(send_msg_request).sync();

        match response {
            Ok(res) => debug!("Sent message with body '{}' and created message_id {}", msg_str, res.message_id.unwrap()),
            Err(error) => debug!("SendMessageError: {:?}", error),
        }

        self.script_hashes.insert(scripthash, new_statushash);
        Ok(())
    }

    pub fn handle_replies(&mut self) -> Result<()> {
        loop {
            let msg = self.chan.receiver().recv().chain_err(|| "channel closed")?;
            match msg {
                SubscriptionMessage::NewScriptHash(script_hash) => self.subscribe_script_hash(script_hash)?,
                SubscriptionMessage::ScriptHashChange(hash, txid) => self.notify_scripthash_subscriptions(hash, txid)?,
                SubscriptionMessage::Done => return Ok(()),
            }
        }
    }
}

#[derive(Debug)]
pub enum ComparisonStatus {
    NotStarted,
    InProgress,
    Done
}

#[derive(Serialize, Deserialize, Debug)]
#[allow(non_snake_case)]
struct SNSMessage {
    Type: String,
    MessageId: String,
    TopicArn: String,
    Message: String,
    Timestamp: String,
    SignatureVersion: String,
    Signature: String,
    SigningCertURL: String,
    UnsubscribeURL: String,
}

pub struct SubscriptionsManager {
    query: Arc<Query>,
    pub notifications_sender: SyncSender<SubscriptionMessage>,
    pub comparison_sender: SyncSender<ScriptHashCompareMessage>,
}

impl SubscriptionsManager {
    fn get_az() -> String {
        let res = reqwest::blocking::get("http://instance-data/latest/meta-data/placement/availability-zone");
        if res.is_ok() {
            return res.unwrap().text().unwrap();
        } else {
            return String::from("us-west-2c");
        }
    }

    pub fn get_script_hashes() -> Result<HashMap<Sha256dHash, Value>> {
        let client = DynamoDbClient::new(Region::UsWest2);

        let mut script_hashes = HashMap::new();
        let mut last_evaluated_key = None;
        // we need an alias for "status" because that happens to be a saved word
        let mut expression_attribute_names = HashMap::new();
        expression_attribute_names.insert(String::from("#statusHash"), String::from("status"));

        loop {
            // loop until no more pages (1MB limit)
            let scan_input = ScanInput {
                table_name: format!("{}_AddressInfo", env::var("ENV").unwrap_or(String::from("dev"))),
                projection_expression: Some(String::from("electrumHash, #statusHash")),
                expression_attribute_names: Some(expression_attribute_names.clone()),
                exclusive_start_key: last_evaluated_key.clone(),
                ..Default::default()
            };

            match client.scan(scan_input).sync() {
                Ok(output) => {
                    match output.items {
                        Some(items) => {
                            for item in items {
                                let script_hash_attribute_value = item.get("electrumHash").unwrap();
                                let script_hash_str = script_hash_attribute_value.s.as_ref().unwrap();
                                let script_hash_res = Sha256dHash::from_hex(&script_hash_str);
                                if script_hash_res.is_ok() {
                                    let script_hash = script_hash_res.unwrap();

                                    let status_hash_attribute_value_option = item.get("status");
                                    let status_hash_str_option =
                                        match status_hash_attribute_value_option {
                                            Some(attr_value) => &attr_value.s,
                                            None => &None,
                                        };
                                    let status_hash = match status_hash_str_option {
                                        Some(s) => json!(s),
                                        None => Value::Null,
                                    };

                                    debug!("subscribing script_hash = {:?}, status_hash = {:?}", script_hash, status_hash);
                                    script_hashes.insert(script_hash, status_hash);
                                }
                            }
                        },
                        None => {
                            bail!(ErrorKind::DynamoDB("Failed fetching script hashes from DB".to_string()))
                        }
                    };
                    last_evaluated_key = output.last_evaluated_key;
                    if last_evaluated_key.is_none() {
                        break;
                    }
                },
                Err(error) => {
                    bail!(ErrorKind::DynamoDB(error.to_string()))
                }
            }
        }

        Ok(script_hashes)
    }

    fn get_scripthashes_effected_by_tx(
        &self,
        txid: &Txid,
        blockhash: Option<BlockHash>,
    ) -> Result<Vec<FullHash>> {
        let txn = self.query.load_txn_with_blockhashlookup(txid, blockhash)?;
        let mut scripthashes = get_output_scripthash(&txn, None);

        for txin in txn.input {
            if txin.previous_output.is_null() {
                continue;
            }
            let id: &Txid = &txin.previous_output.txid;
            let n = txin.previous_output.vout as usize;

            let txn = self.query.load_txn_with_blockhashlookup(&id, None)?;
            scripthashes.extend(get_output_scripthash(&txn, Some(n)));
        }
        Ok(scripthashes)
    }

    pub fn start(query: Arc<Query>, script_hash_comparison_status: Arc<AtomicBool>) -> SubscriptionsManager {
        let now = Instant::now();
        let script_hashes = SubscriptionsManager::get_script_hashes()
            .unwrap_or(HashMap::new());
        debug!("script_hashes.len() = {}, took {} milliseconds", script_hashes.len(), now.elapsed().as_millis());

        let env = env::var("ENV").unwrap_or(String::from("dev"));

        let mut res = SubscriptionsManager::get_az();
        let az = res.split_off(res.len() - 2).to_uppercase();

        debug!("Create SubscriptionsHandler");
        let mut subs_handler = SubscriptionsHandler::new(query.clone(), script_hashes.clone(), env.clone());

        let subscribe_sender = subs_handler.chan.sender();
        SubscriptionsManager::start_subscribe_scripthash_sqs_poller(subscribe_sender, env, az);
        debug!("Started sqs poller for subscribes");

        let notifications_sender = subs_handler.chan.sender();

        let mut comparison_handler = ScriptHashComparer::new(query.clone(),subs_handler.chan.sender(), script_hash_comparison_status.clone());
        let comparison_sender = comparison_handler.chan.sender();

        spawn_thread("comparison_handler", move || comparison_handler.handle_request());
        debug!("comparison_handler created");

        spawn_thread("subs_handler", move || subs_handler.handle_replies());
        debug!("Started SubscriptionsHandler handle_replies");

        SubscriptionsManager {
            query: query.clone(),
            notifications_sender,
            comparison_sender
        }
    }

    pub fn on_scripthash_change(
        &self,
        headers_changed: &Vec<HeaderEntry>,
        txs_changed: HashSet<Txid>,
    ) {
        let mut txn_done: HashSet<Txid> = HashSet::new();
        let mut scripthashes: HashMap<FullHash, Txid> = HashMap::new();

        let mut insert_for_tx = |txid, blockhash| {
            if !txn_done.insert(txid) {
                return;
            }
            if let Ok(hashes) = self.get_scripthashes_effected_by_tx(&txid, blockhash) {
                for h in hashes {
                    scripthashes.insert(h, txid);
                }
            } else {
                warn!("failed to get effected scripthashes for tx {}", txid);
            }
        };

        for header in headers_changed {
            let blockhash = header.hash();
            let txids = match self.query.get_block_txids(&blockhash) {
                Ok(txids) => txids,
                Err(e) => {
                    warn!("Failed to get blocktxids for {}: {}", blockhash, e);
                    continue;
                }
            };
            for txid in txids {
                insert_for_tx(txid, Some(*blockhash));
            }
        }
        for txid in txs_changed {
            insert_for_tx(txid, None);
        }

        for (scripthash, txid) in scripthashes.drain() {
            self.notifications_sender.send(SubscriptionMessage::ScriptHashChange(scripthash, Some(txid.into_inner())));
        }
    }

    pub fn start_subscribe_scripthash_sqs_poller(sender: SyncSender<SubscriptionMessage>, env: String, az: String) {
        let sqs = SqsClient::new(Region::UsWest2);

        let queue_name = format!("Electrum_address_subscription_{}_AZ-{}", env, az);

        let get_queue_by_name_request = GetQueueUrlRequest {
            queue_name: queue_name.clone(),
            ..Default::default()
        };

        let response: GetQueueUrlResult = sqs
            .get_queue_url(get_queue_by_name_request)
            .sync()
            .expect("Get queue by URL request failed");

        debug!("SQS Poller get queue response {:?}", response);

        let queue_url = response
            .queue_url
            .expect("Queue url should be available from list queues");

        debug!("SQS Poller queue url {}", queue_url.clone());

        let receive_request = ReceiveMessageRequest {
            queue_url: queue_url.clone(),
            wait_time_seconds: Some(20),
            ..Default::default()
        };

        spawn_thread("sqs_poller", move || {
            loop {
                let response = sqs.receive_message(receive_request.clone()).sync();
                match response.expect("Expected to have a receive message response").messages {
                    Some(messages) => for msg in messages {
                        let message_body: std::result::Result<SNSMessage, serde_json::Error> =  serde_json::from_str(msg.body.unwrap().as_str());

                        if message_body.is_err() {
                            continue;
                        }

                        let script_hash_to_sub = message_body.unwrap().Message;

                        debug!("Sending subscription message for scripthash: {}", script_hash_to_sub);

                        sender.send(SubscriptionMessage::NewScriptHash(script_hash_to_sub));

                        let delete_message_request = DeleteMessageRequest {
                            queue_url: queue_url.clone(),
                            receipt_handle: msg.receipt_handle.clone().unwrap(),
                        };
                        match sqs.delete_message(delete_message_request).sync() {
                            Ok(_) => debug!(
                                "Deleted message via receipt handle {:?}",
                                msg.receipt_handle
                            ),
                            Err(e) => warn!("Couldn't delete message: {:?}", e),
                        }
                    },
                    None => {},
                };
            }
        });

    }
}
