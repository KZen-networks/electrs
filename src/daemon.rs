use base64;
use bitcoin::blockdata::block::{Block, BlockHeader};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hash_types::{BlockHash, Txid};
use bitcoin::network::constants::Network;
use bitcoin_hashes::hex::{FromHex, ToHex};
use bitcoin_hashes::Hash;
use glob;
use hex;
use serde_json::{from_str, from_value, Map, Value};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Lines, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::cache::BlockTxIDsCache;
use crate::errors::*;
use crate::metrics::{HistogramOpts, HistogramVec, Metrics};
use crate::signal::Waiter;
use crate::util::HeaderList;
use bitcoin::consensus::encode::Decodable;
use bitcoin::BitcoinHash;

const BLOCK_HASH_SIZE: u64 = 32;
const TX_HASH_SIZE: u64 = 32;
const LENGTH_FILED_SIZE: u64 = 4;

fn parse_hash<T: Hash>(value: &Value) -> Result<T> {
    Ok(T::from_hex(
        value
            .as_str()
            .chain_err(|| format!("non-string value: {}", value))?,
    )
    .chain_err(|| format!("non-hex value: {}", value))?)
}

fn header_from_value(value: Value, network: Network) -> Result<BlockHeader> {
    let header_hex = value
        .as_str()
        .chain_err(|| format!("non-string header: {}", value))?;
    let header_bytes = hex::decode(header_hex).chain_err(|| "non-hex header")?;
    if network == Network::Dogecoin || network == Network::Dogetest {
        let header_bytes = hex::decode(header_hex).chain_err(|| "non-hex header")?;
        let mut cur = std::io::Cursor::new(&header_bytes);
        let block_header: bitcoin::BlockHeader =
            Decodable::consensus_decode(&mut cur).chain_err(|| "Unable to decode header")?;
        Ok(block_header)
    } else {
        Ok(deserialize(&header_bytes)
            .chain_err(|| format!("failed to parse header {}", header_hex))?)
    }
}

fn block_from_value(value: Value, network: Network) -> Result<Block> {
    let block_hex = value.as_str().chain_err(|| "non-string block")?;
    let block_bytes = hex::decode(block_hex).chain_err(|| "non-hex block")?;

    let mut cur = std::io::Cursor::new(&block_bytes);
    // We first need to parse the header to extract the version.
    // Only some versions of dogecoin blocks require AuxPow parsing
    let block_header: bitcoin::BlockHeader =
        Decodable::consensus_decode(&mut cur).chain_err(|| "Unable to decode header")?;

    // Dogecoin has support for AuxPow headers. These are extra headers attached to the
    // original block header and link to the relevant header on another chain.
    // For the purpose of indexing blocks, these can be ingored.A
    // See merged mining spec here: https://en.bitcoin.it/wiki/Merged_mining_specification
    // Code taken from https://github.com/borkerprotocol/borker-lib/blob/6adb0c7bad01cda7583f638000da90835f9ffc72/src/lib.rs#L41
    // Ideally this code should be in rust-bitcoin, and only call deserialize
    match network {
        Network::Dogecoin | Network::Dogetest if block_header.version & 1 << 8 != 0 => {
            // TODO: Pass this into a sperate function.
            // Parse coinbase tx. Parsing advnaces the pointer
            let _: bitcoin::Transaction =
                Decodable::consensus_decode(&mut cur).chain_err(|| "Unable to decode Tx")?;
            // Skip parent_block
            let pos = cur.position() + BLOCK_HASH_SIZE;
            cur.set_position(pos);
            // Skip coinase_branch
            let len: bitcoin::VarInt =
                Decodable::consensus_decode(&mut cur).chain_err(|| "Unalbe to decode length")?;
            let pos = cur.position() + TX_HASH_SIZE * len.0;
            cur.set_position(pos + LENGTH_FILED_SIZE);
            // Skip blockchain_branch
            let len: bitcoin::VarInt =
                Decodable::consensus_decode(&mut cur).chain_err(|| "Unable to decode length")?;
            let pos = cur.position() + TX_HASH_SIZE * len.0;
            cur.set_position(pos + LENGTH_FILED_SIZE);
            // Skip parent block header
            let _: bitcoin::BlockHeader = Decodable::consensus_decode(&mut cur)
                .chain_err(|| "Unalbe to decode AuxPow header")?;
            // Decode transactions
            Ok(Block {
                header: block_header,
                txdata: Decodable::consensus_decode(&mut cur)
                    .chain_err(|| "Unable to decode Txs")?,
            })
        }
        _ => Ok(deserialize(&block_bytes)
            .chain_err(|| format!("failed to parse block {}", block_hex))?),
    }
}

fn tx_from_value(value: Value) -> Result<Transaction> {
    let tx_hex = value.as_str().chain_err(|| "non-string tx")?;
    let tx_bytes = hex::decode(tx_hex).chain_err(|| "non-hex tx")?;
    Ok(deserialize(&tx_bytes).chain_err(|| format!("failed to parse tx {}", tx_hex))?)
}

/// Parse JSONRPC error code, if exists.
fn parse_error_code(err: &Value) -> Option<i64> {
    if err.is_null() {
        return None;
    }
    err.as_object()?.get("code")?.as_i64()
}

fn check_error_code(reply_obj: &Map<String, Value>, method: &str) -> Result<()> {
    if let Some(err) = reply_obj.get("error") {
        if let Some(code) = parse_error_code(&err) {
            match code {
                // RPC_IN_WARMUP -> retry by later reconnection
                -28 => bail!(ErrorKind::Connection(err.to_string())),
                _ => bail!("{} RPC error: {}", method, err),
            }
        }
    }
    Ok(())
}

fn parse_jsonrpc_reply(mut reply: Value, method: &str, expected_id: u64) -> Result<Value> {
    if let Some(reply_obj) = reply.as_object_mut() {
        check_error_code(reply_obj, method)?;
        let id = reply_obj
            .get("id")
            .chain_err(|| format!("no id in reply: {:?}", reply_obj))?
            .clone();
        if id != expected_id {
            bail!(
                "wrong {} response id {}, expected {}",
                method,
                id,
                expected_id
            );
        }
        if let Some(result) = reply_obj.get_mut("result") {
            return Ok(result.take());
        }
        bail!("no result in reply: {:?}", reply_obj);
    }
    bail!("non-object reply: {:?}", reply);
}

#[derive(Serialize, Deserialize, Debug)]
struct BlockchainInfo {
    chain: String,
    blocks: u32,
    headers: u32,
    verificationprogress: f64,
    bestblockhash: String,
    pruned: bool,
    initialblockdownload: bool,
}

#[derive(Serialize, Deserialize, Debug)]
struct NetworkInfo {
    version: u64,
    subversion: String,
    relayfee: f64, // in BTC
}

#[derive(Serialize, Deserialize, Debug)]
struct FeeEstimate {
    feerate: f64, // in BTC/kilobyte
    blocks: usize,
}

pub struct MempoolEntry {
    fee: u64,   // in satoshis
    vsize: u32, // in virtual bytes (= weight/4)
    fee_per_vbyte: f32,
}

impl MempoolEntry {
    fn new(fee: u64, vsize: u32) -> MempoolEntry {
        MempoolEntry {
            fee,
            vsize,
            fee_per_vbyte: fee as f32 / vsize as f32,
        }
    }

    pub fn fee_per_vbyte(&self) -> f32 {
        self.fee_per_vbyte
    }

    pub fn fee(&self) -> u64 {
        self.fee
    }

    pub fn vsize(&self) -> u32 {
        self.vsize
    }
}

pub trait CookieGetter: Send + Sync {
    fn get(&self) -> Result<Vec<u8>>;
}

struct Connection {
    tx: TcpStream,
    rx: Lines<BufReader<TcpStream>>,
    cookie_getter: Arc<dyn CookieGetter>,
    addr: SocketAddr,
    signal: Waiter,
}

fn tcp_connect(addr: SocketAddr, signal: &Waiter) -> Result<TcpStream> {
    loop {
        match TcpStream::connect(addr) {
            Ok(conn) => return Ok(conn),
            Err(err) => {
                warn!("failed to connect daemon at {}: {}", addr, err);
                signal.wait(Duration::from_secs(3))?;
                continue;
            }
        }
    }
}

impl Connection {
    fn new(
        addr: SocketAddr,
        cookie_getter: Arc<dyn CookieGetter>,
        signal: Waiter,
    ) -> Result<Connection> {
        let conn = tcp_connect(addr, &signal)?;
        let reader = BufReader::new(
            conn.try_clone()
                .chain_err(|| format!("failed to clone {:?}", conn))?,
        );
        Ok(Connection {
            tx: conn,
            rx: reader.lines(),
            cookie_getter,
            addr,
            signal,
        })
    }

    fn reconnect(&self) -> Result<Connection> {
        Connection::new(self.addr, self.cookie_getter.clone(), self.signal.clone())
    }

    fn send(&mut self, request: &str) -> Result<()> {
        let cookie = &self.cookie_getter.get()?;
        let msg = format!(
            "POST / HTTP/1.1\nAuthorization: Basic {}\nContent-Length: {}\n\n{}",
            base64::encode(cookie),
            request.len(),
            request,
        );
        self.tx.write_all(msg.as_bytes()).chain_err(|| {
            ErrorKind::Connection("disconnected from daemon while sending".to_owned())
        })
    }

    fn recv(&mut self) -> Result<String> {
        // TODO: use proper HTTP parser.
        let mut in_header = true;
        let mut contents: Option<String> = None;
        let iter = self.rx.by_ref();
        let status = iter
            .next()
            .chain_err(|| {
                ErrorKind::Connection("disconnected from daemon while receiving".to_owned())
            })?
            .chain_err(|| "failed to read status")?;
        let mut headers = HashMap::new();
        for line in iter {
            let line = line.chain_err(|| ErrorKind::Connection("failed to read".to_owned()))?;
            if line.is_empty() {
                in_header = false; // next line should contain the actual response.
            } else if in_header {
                let parts: Vec<&str> = line.splitn(2, ": ").collect();
                if parts.len() == 2 {
                    headers.insert(parts[0].to_owned(), parts[1].to_owned());
                } else {
                    warn!("invalid header: {:?}", line);
                }
            } else {
                contents = Some(line);
                break;
            }
        }

        let contents =
            contents.chain_err(|| ErrorKind::Connection("no reply from daemon".to_owned()))?;
        let contents_length: &str = headers
            .get("Content-Length")
            .chain_err(|| format!("Content-Length is missing: {:?}", headers))?;
        let contents_length: usize = contents_length
            .parse()
            .chain_err(|| format!("invalid Content-Length: {:?}", contents_length))?;

        let expected_length = contents_length - 1; // trailing EOL is skipped
        if expected_length != contents.len() {
            bail!(ErrorKind::Connection(format!(
                "expected {} bytes, got {}",
                expected_length,
                contents.len()
            )));
        }

        Ok(if status == "HTTP/1.1 200 OK" {
            contents
        } else if status == "HTTP/1.1 500 Internal Server Error" {
            warn!("HTTP status: {}", status);
            contents // the contents should have a JSONRPC error field
        } else {
            bail!(
                "request failed {:?}: {:?} = {:?}",
                status,
                headers,
                contents
            );
        })
    }
}

struct Counter {
    value: AtomicU64,
}

impl Counter {
    fn new() -> Self {
        Counter { value: 0.into() }
    }

    fn next(&self) -> u64 {
        // fetch_add() returns previous value, we want current one
        self.value.fetch_add(1, Ordering::Relaxed) + 1
    }
}

pub struct Daemon {
    daemon_dir: PathBuf,
    network: Network,
    conn: Mutex<Connection>,
    message_id: Counter, // for monotonic JSONRPC 'id'
    signal: Waiter,
    blocktxids_cache: Arc<BlockTxIDsCache>,

    // monitoring
    latency: HistogramVec,
    size: HistogramVec,
}

impl Daemon {
    pub fn new(
        daemon_dir: &PathBuf,
        daemon_rpc_addr: SocketAddr,
        cookie_getter: Arc<dyn CookieGetter>,
        network: Network,
        signal: Waiter,
        blocktxids_cache: Arc<BlockTxIDsCache>,
        metrics: &Metrics,
    ) -> Result<Daemon> {
        let daemon = Daemon {
            daemon_dir: daemon_dir.clone(),
            network,
            conn: Mutex::new(Connection::new(
                daemon_rpc_addr,
                cookie_getter,
                signal.clone(),
            )?),
            message_id: Counter::new(),
            blocktxids_cache: blocktxids_cache,
            signal: signal.clone(),
            latency: metrics.histogram_vec(
                HistogramOpts::new("electrs_daemon_rpc", "Bitcoind RPC latency (in seconds)"),
                &["method"],
            ),
            // TODO: use better buckets (e.g. 1 byte to 10MB).
            size: metrics.histogram_vec(
                HistogramOpts::new("electrs_daemon_bytes", "Bitcoind RPC size (in bytes)"),
                &["method", "dir"],
            ),
        };
        let network_info = daemon.getnetworkinfo()?;
        info!("{:?}", network_info);
        if network_info.version < 16_00_00 {
            bail!(
                "{} is not supported - please use bitcoind 0.16+",
                network_info.subversion,
            )
        }
        let blockchain_info = daemon.getblockchaininfo()?;
        info!("{:?}", blockchain_info);
        if blockchain_info.pruned {
            bail!("pruned node is not supported (use '-prune=0' bitcoind flag)".to_owned())
        }
        loop {
            let info = daemon.getblockchaininfo()?;
            if !info.initialblockdownload {
                break;
            }
            warn!(
                "wait until IBD is over: headers={} blocks={} progress={}",
                info.headers, info.blocks, info.verificationprogress
            );
            signal.wait(Duration::from_secs(3))?;
        }
        Ok(daemon)
    }

    pub fn reconnect(&self) -> Result<Daemon> {
        Ok(Daemon {
            daemon_dir: self.daemon_dir.clone(),
            network: self.network,
            conn: Mutex::new(self.conn.lock().unwrap().reconnect()?),
            message_id: Counter::new(),
            signal: self.signal.clone(),
            blocktxids_cache: Arc::clone(&self.blocktxids_cache),
            latency: self.latency.clone(),
            size: self.size.clone(),
        })
    }

    pub fn list_blk_files(&self) -> Result<Vec<PathBuf>> {
        let mut path = self.daemon_dir.clone();
        path.push("blocks");
        path.push("blk*.dat");
        info!("listing block files at {:?}", path);
        let mut paths: Vec<PathBuf> = glob::glob(path.to_str().unwrap())
            .chain_err(|| "failed to list blk*.dat files")?
            .map(std::result::Result::unwrap)
            .collect();
        paths.sort();
        Ok(paths)
    }

    pub fn magic(&self) -> u32 {
        self.network.magic()
    }

    fn call_jsonrpc(&self, method: &str, request: &Value) -> Result<Value> {
        let mut conn = self.conn.lock().unwrap();
        let timer = self.latency.with_label_values(&[method]).start_timer();
        let request = request.to_string();
        conn.send(&request)?;
        self.size
            .with_label_values(&[method, "send"])
            .observe(request.len() as f64);
        let response = conn.recv()?;
        let result: Value = from_str(&response).chain_err(|| "invalid JSON")?;
        timer.observe_duration();
        self.size
            .with_label_values(&[method, "recv"])
            .observe(response.len() as f64);
        Ok(result)
    }

    fn handle_request_batch(&self, method: &str, params_list: &[Value]) -> Result<Vec<Value>> {
        let id = self.message_id.next();
        let reqs = params_list
            .iter()
            .map(|params| json!({"method": method, "params": params, "id": id}))
            .collect();
        let mut results = vec![];
        let mut replies = self.call_jsonrpc(method, &reqs)?;
        if let Some(replies_vec) = replies.as_array_mut() {
            for reply in replies_vec {
                results.push(parse_jsonrpc_reply(reply.take(), method, id)?)
            }
            return Ok(results);
        }
        bail!("non-array replies: {:?}", replies);
    }

    fn retry_request_batch(&self, method: &str, params_list: &[Value]) -> Result<Vec<Value>> {
        loop {
            match self.handle_request_batch(method, params_list) {
                Err(Error(ErrorKind::Connection(msg), _)) => {
                    warn!("reconnecting to bitcoind: {}", msg);
                    self.signal.wait(Duration::from_secs(3))?;
                    let mut conn = self.conn.lock().unwrap();
                    *conn = conn.reconnect()?;
                    continue;
                }
                result => return result,
            }
        }
    }

    fn request(&self, method: &str, params: Value) -> Result<Value> {
        let mut values = self.retry_request_batch(method, &[params])?;
        assert_eq!(values.len(), 1);
        Ok(values.remove(0))
    }

    fn requests(&self, method: &str, params_list: &[Value]) -> Result<Vec<Value>> {
        self.retry_request_batch(method, params_list)
    }

    // bitcoind JSONRPC API:

    fn getblockchaininfo(&self) -> Result<BlockchainInfo> {
        let info: Value = self.request("getblockchaininfo", json!([]))?;
        Ok(from_value(info).chain_err(|| "invalid blockchain info")?)
    }

    fn getnetworkinfo(&self) -> Result<NetworkInfo> {
        let info: Value = self.request("getnetworkinfo", json!([]))?;
        Ok(from_value(info).chain_err(|| "invalid network info")?)
    }

    pub fn get_subversion(&self) -> Result<String> {
        Ok(self.getnetworkinfo()?.subversion)
    }

    pub fn get_relayfee(&self) -> Result<f64> {
        Ok(self.getnetworkinfo()?.relayfee)
    }

    pub fn estimatesmartfee(&self, conf_target: usize, estimate_mode: &str) -> Result<f64> {
        let val: Value;
        if self.network == Network::Dogecoin || self.network == Network::Dogetest {
            val = self.request("estimatesmartfee", json!([conf_target]))?;
        } else {
            val = self.request("estimatesmartfee", json!([conf_target, estimate_mode]))?;
        }
        let fee_estimate: Result<FeeEstimate> =
            Ok(from_value(val).chain_err(|| "invalid fee estimate")?);
        Ok(fee_estimate?.feerate)
    }

    pub fn getbestblockhash(&self) -> Result<BlockHash> {
        parse_hash(&self.request("getbestblockhash", json!([]))?).chain_err(|| "invalid blockhash")
    }

    pub fn getblockheader(&self, blockhash: &BlockHash) -> Result<BlockHeader> {
        header_from_value(
            self.request(
                "getblockheader",
                json!([blockhash.to_hex(), /*verbose=*/ false]),
            )?,
            self.network,
        )
    }

    pub fn getblockheaders(&self, heights: &[usize]) -> Result<Vec<BlockHeader>> {
        let heights: Vec<Value> = heights.iter().map(|height| json!([height])).collect();
        let params_list: Vec<Value> = self
            .requests("getblockhash", &heights)?
            .into_iter()
            .map(|hash| json!([hash, /*verbose=*/ false]))
            .collect();
        let mut result = vec![];
        for h in self.requests("getblockheader", &params_list)? {
            result.push(header_from_value(h, self.network)?);
        }
        Ok(result)
    }

    pub fn getblock(&self, blockhash: &BlockHash) -> Result<Block> {
        let block = block_from_value(
            self.request("getblock", json!([blockhash.to_hex(), /*verbose=*/ false]))?,
            self.network,
        )?;
        // trace!("latest block {}", block.bitcoin_hash());
        assert_eq!(block.bitcoin_hash(), *blockhash);
        Ok(block)
    }

    fn load_blocktxids(&self, blockhash: &BlockHash) -> Result<Vec<Txid>> {
        if self.network == Network::Dogecoin || self.network == Network::Dogetest {
            self.request("getblock", json!([blockhash.to_hex(), /*verbose=*/ true]))?
                .get("tx")
                .chain_err(|| "block missing txids")?
                .as_array()
                .chain_err(|| "invalid block txids")?
                .iter()
                .map(parse_hash)
                .collect::<Result<Vec<Txid>>>()
        } else {
            self.request("getblock", json!([blockhash.to_hex(), /*verbose=*/ 1]))?
                .get("tx")
                .chain_err(|| "block missing txids")?
                .as_array()
                .chain_err(|| "invalid block txids")?
                .iter()
                .map(parse_hash)
                .collect::<Result<Vec<Txid>>>()
        }
    }

    pub fn getblocktxids(&self, blockhash: &BlockHash) -> Result<Vec<Txid>> {
        self.blocktxids_cache
            .get_or_else(&blockhash, || self.load_blocktxids(blockhash))
    }

    pub fn getblocks(&self, blockhashes: &[BlockHash]) -> Result<Vec<Block>> {
        let params_list: Vec<Value> = blockhashes
            .iter()
            .map(|hash| json!([hash.to_hex(), /*verbose=*/ false]))
            .collect();
        let values = self.requests("getblock", &params_list)?;
        let mut blocks = vec![];
        for value in values {
            let block = block_from_value(value, self.network)?;
            // trace!("get block {}", block.bitcoin_hash());
            blocks.push(block);
        }
        Ok(blocks)
    }

    pub fn gettransaction(
        &self,
        txhash: &Txid,
        blockhash: Option<BlockHash>,
    ) -> Result<Transaction> {
        let mut args = json!([txhash.to_hex(), /*verbose=*/ false]);
        // Dogecoin currently does not support getting Txs with blockhash
        if self.network != Network::Dogecoin && self.network != Network::Dogetest {
            if let Some(blockhash) = blockhash {
                args.as_array_mut().unwrap().push(json!(blockhash.to_hex()));
            }
        }
        debug!("Getting info for {:?}", args);
        tx_from_value(self.request("getrawtransaction", args)?)
    }

    pub fn gettransaction_raw(
        &self,
        txhash: &Txid,
        blockhash: Option<BlockHash>,
        verbose: bool,
    ) -> Result<Value> {
        let mut args = json!([txhash.to_hex(), verbose]);
        // Dogecoin currently does not support getting Txs with blockhash
        if self.network != Network::Dogecoin && self.network != Network::Dogetest {
            if let Some(blockhash) = blockhash {
                args.as_array_mut().unwrap().push(json!(blockhash.to_hex()));
            }
        }
        debug!("Getting raw info for {:?}", args);
        Ok(self.request("getrawtransaction", args)?)
    }

    pub fn gettransactions(&self, txhashes: &[&Txid]) -> Result<Vec<Transaction>> {
        let params_list: Vec<Value> = txhashes
            .iter()
            .map(|txhash| json!([txhash.to_hex(), /*verbose=*/ false]))
            .collect();

        let values = self.requests("getrawtransaction", &params_list)?;
        let mut txs = vec![];
        for value in values {
            txs.push(tx_from_value(value)?);
        }
        assert_eq!(txhashes.len(), txs.len());
        Ok(txs)
    }

    pub fn getmempooltxids(&self) -> Result<HashSet<Txid>> {
        let txids: Value = self.request("getrawmempool", json!([/*verbose=*/ false]))?;
        let mut result = HashSet::new();
        for value in txids.as_array().chain_err(|| "non-array result")? {
            result.insert(parse_hash(&value).chain_err(|| "invalid txid")?);
        }
        Ok(result)
    }

    pub fn getmempoolentry(&self, txid: &Txid) -> Result<MempoolEntry> {
        let entry = self.request("getmempoolentry", json!([txid.to_hex()]))?;
        let fee = (entry
            .get("fee")
            .chain_err(|| "missing fee")?
            .as_f64()
            .chain_err(|| "non-float fee")?
            * 100_000_000f64) as u64;
        let vsize = entry
            .get("size")
            .or_else(|| entry.get("vsize")) // (https://github.com/bitcoin/bitcoin/pull/15637)
            .chain_err(|| "missing vsize")?
            .as_u64()
            .chain_err(|| "non-integer vsize")? as u32;
        Ok(MempoolEntry::new(fee, vsize))
    }

    pub fn broadcast(&self, tx: &Transaction) -> Result<Txid> {
        let tx = hex::encode(serialize(tx));
        let txid = self.request("sendrawtransaction", json!([tx]))?;
        Ok(
            Txid::from_hex(txid.as_str().chain_err(|| "non-string txid")?)
                .chain_err(|| "failed to parse txid")?,
        )
    }

    fn get_all_headers(&self, tip: &BlockHash) -> Result<Vec<BlockHeader>> {
        let info: Value = self.request("getblockheader", json!([tip.to_hex()]))?;
        let tip_height = info
            .get("height")
            .expect("missing height")
            .as_u64()
            .expect("non-numeric height") as usize;
        let all_heights: Vec<usize> = (0..=tip_height).collect();
        let chunk_size = 100_000;
        let mut result = vec![];
        let null_hash = BlockHash::default();
        for heights in all_heights.chunks(chunk_size) {
            trace!("downloading {} block headers", heights.len());
            let mut headers = self.getblockheaders(&heights)?;
            assert!(headers.len() == heights.len());
            result.append(&mut headers);
        }

        let mut blockhash = null_hash;
        for header in &result {
            assert_eq!(header.prev_blockhash, blockhash);
            blockhash = header.bitcoin_hash();
        }
        assert_eq!(blockhash, *tip);
        Ok(result)
    }

    // Returns a list of BlockHeaders in ascending height (i.e. the tip is last).
    pub fn get_new_headers(
        &self,
        indexed_headers: &HeaderList,
        bestblockhash: &BlockHash,
    ) -> Result<Vec<BlockHeader>> {
        // Iterate back over headers until known blockash is found:
        if indexed_headers.is_empty() {
            return self.get_all_headers(bestblockhash);
        }
        debug!(
            "downloading new block headers ({} already indexed) from {}",
            indexed_headers.len(),
            bestblockhash,
        );
        let mut new_headers = vec![];
        let null_hash = BlockHash::default();
        let mut blockhash = *bestblockhash;
        while blockhash != null_hash {
            if indexed_headers.header_by_blockhash(&blockhash).is_some() {
                break;
            }
            let header = self
                .getblockheader(&blockhash)
                .chain_err(|| format!("failed to get {} header", blockhash))?;
            new_headers.push(header);
            blockhash = header.prev_blockhash;
        }
        trace!("downloaded {} block headers", new_headers.len());
        new_headers.reverse(); // so the tip is the last vector entry
        Ok(new_headers)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::network::constants::Network;

    #[test]
    fn deserialize_doge_header() {
        let some_header = "02006200c7200ba555cbde915159e8d3e341822fa2c9c027ed2bd8bd07324206c48fd58a77d834db30a5d77351164eb7deb15f9a1ba896b8f7c89c23798ed94fb43b50a039fb115475df2f1be8afc4ca";

        let header: BlockHeader = header_from_value(json!(some_header), Network::Dogecoin)
            .expect("Can't deserialize correct block header");

        println!("{:?}", header);
    }

    #[test]
    fn deserialize_auxpow_doge_header() {
        let some_header = "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb09b1a8468a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78fbb827ee41fb11548441361b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff380345bf09fabe6d6d980ba42120410de0554d42a5b5ee58167bcd86bf7591f429005f24da45fb51cf0800000000000000cdb1f1ff0e000000ffffffff01800c0c2a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000b3e64e02fff596209c498f1b18f798d62f216f11c8462bf3922319000000000003a979a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a418d29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a3370c334178415c83d1d0c2deeec727c2330617a47691fc5e79203669312d100000000036fa40307b3a439538195245b0de56a2c1db6ba3a64f8bdd2071d00bc48c841b5e77b98e5c7d6f06f92dec5cf6d61277ecb9a0342406f49f34c51ee8ce4abd678038129485de14238bd1ca12cd2de12ff0e383aee542d90437cd664ce139446a00000000002000000d2ec7dfeb7e8f43fe77aba3368df95ac2088034420402730ee0492a2084217083411b3fc91033bfdeea339bc11b9efc986e161c703e07a9045338c165673f09940fb11548b54021b58cc9ae5";

        let header: BlockHeader = header_from_value(json!(some_header), Network::Dogecoin)
            .expect("Can't deserialize correct block header");
        println!("{:?}", header);
    }

    #[test]
    fn deserialize_doge_block_100() {
        let some_block = "0100000030dd3598b1a9dda6a8575c0a703403efbef3b7e074880a798fc48f8646f8ad0a6c1c5d9b68fb67954f3c7f8b0863d63d5b95eebf3c8166783c6d1a6f66670c9293efa352f0ff0f1e00028ed70101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e0493efa3520101062f503253482fffffffff01001333d1325100002321024274baa26a5da9cf9ddc784d6a5cb439cfa840c0eb77c60f2448ff88beb5a734ac00000000";

        let block: Block = block_from_value(json!(some_block), Network::Dogecoin)
            .expect("Can't deserialize correct block");

        println!("{:?}", block);
    }

    #[test]
    fn deserialize_doge_block_10000() {
        let some_block = "0100000083b52ef3267eb9f3204265cbb493b03dd6b3b7356c7d068aaf7a337ea3b19aaf61931635e1df3c834d91accd9f040af31e7a3c7fd1bfe2ccaf757db4ce7b2a42fb94ab52ba5d141c000829ff2801000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e04fb94ab52010b062f503253482fffffffff0100906dee3e1b0000232103fe57f08a602818329f0c9c067d9bf8ce8f7f632e21362e824ae58ce39cf09517ac000000000100000001173a308b4bc6295a829cc16aeea782cdfe9fc117070f8350cf0f06667c7ef829010000006a47304402201065c94cd4440af40052417d4f164d22d9ecc9c211bcd0636a8714633a601e1d0220390a7b60faed26c500e91b9a62198ba5d66fc36e82d208113629eb61840c14e0012103717cf09cd287de3b327ba9f3f638e33eaa9acd207b74df3cafa076ccb440c888ffffffff010080ca39612400001976a9146c727fbc2e1db1f9dd29c7a7e0403e52d29d04b088ac0000000001000000012952939f908b3910acf21284c11748e6a182a4d4c0de45230894214841efb1a2000000006b483045022100e199114c9c98edefea4ad929a8ac1abae2c0b52c81d6e438b98249b51321b18a022074d94a2767e504e66eb7d4f2ad1fa4f4c139116a014ccbbaedc8b966cab7dab901210314aa3c735c9d78638e1aa835e3045f28cd37e375816d57ba136894ede2eac22affffffff02e4d48b723b4d00001976a914cd25d07f51318802e1b3976ad1c53cf2c5602dfe88acc082d17b110000001976a9144fea72c42c666f182e1c332bf511574f6b8c5fdd88ac00000000010000000186b37769ded55b05d70eb80615fbc2d6e40f8cc51b535b3332b475b3e5a2f922000000006a473044022014f6439d5225458fa26df6e892c56a095c911a8b94c0a774912fa5cb16f4aac20220534b66db7dc514eb8fb74bc2e64f60494469f03f58e6682be30eb2133acf0de6012103cf42e164df5084ed85f5261e7b05eebd1d56748eee513723141df8ba0bdd2ad1ffffffff020af2bd279c4800001976a91468d255b6fb51fd64a77bb2304e63d99e3ef0636b88ac2b240a97190000001976a91421235659f342da2018fe2438b6fc6df5082ea54a88ac000000000100000001a4bfe18510c56716cbe90d9d9f3674a5f1ee3ac80d1721206078277648c8bc11000000006b483045022100e82a1850bd05cb68ce981395306428faed77f378ef1c8b818f6c6007866a0e2702204c43017423b00b06931114e112645afeeea13cd66ed568f18bcd64e5d6f682a20121020733e10c6712ab2591f080edbb528e955a58c2fddd86353e9095bbc30c0e282dffffffff02fa1485d1b64700001976a91430e5c0b0dfa1b27dd0803ddae0ed9140022fe3dd88ac57c98d8f220000001976a9142350db3473d595fe3fc3176ca14774c6fadcda4688ac00000000010000000199c4ad426bd3e4b0cfc1a661ba915756b6ae17e98d896a3095fbb22ed17c4f13000000006b483045022100abe53df969d2745d12a5e77ebbe77532896409ac8760e9a4ffef2f85f1c615f00220339bc596cb34c256d20ff2d26d10579617c8b406d5858b00370a402b79971f3b0121021d74c99aca89fe9ff72bda23d8ce0eec60422ea02ebed1a61ebc5c8d63b2a681ffffffff02ee6e8a698a4700001976a914de2ff394c66c5cb1f37bc179eb2f15843974c24188ac6bc5f5182c0000001976a914f9d4bb2bbe3a0c1d154755b242574f187aa7d4c388ac0000000001000000010c7cb72aa49fe4337332813556218d948a73629d02a0a8b7e500704eb5ffd7d4000000006b483045022100a9f6363e28a76a229cc852ff47cb25cd193dc15bb1c89fc43e859d5fb79e234d02206e876df96093ccd7c1b64b635ad25c46397354b6dc2493351a367f618471780a012102fae4c8a277f9775ab500a968bedf46a31874b115827c4f1581e312d579e62c33ffffffff0214f18b528f4700001976a914d8b418e237ef11bc77a6fc7947eee35098caa7a388ac50549851070000001976a91403f42b89685881cc9ba2c85ddae29905290be1f588ac000000000100000001e789c2cb94b65812826157d179399b3319fd84a015d78023c7175e8f31433319000000006b48304502203bf1d175d97c426806120af66f29f1a11573d9aec96481ff9099d55da17825c8022100d3ae251be4fdce92a1a4de44dea8c0756c6b7497d2a45d8187489df005045a15012103dd4bc90490d51bb79356a8ea4eab17ab5037e4a569ca9a816bc2d47502b92fceffffffff023f56b8a9da4400001976a91424e9e348e4543ba29a0b2645fe149bfeb2c496e088ac30e4d8a7280000001976a914f5afd393d022ab839e155696356479fbbafd048d88ac00000000010000000146c3a5da08df1aca3a22d06be463681662b86a041a28cf7faa8fdaa029851a89000000006c493046022100f93963ad2b90f7403674352cbf48cef754371c1b064d02244c06ee02617fe328022100aa93320afbd28ac5db0f75470ee5d113ef5d0d0ea8b835e84ca1af5fe8f2dac3012103975f8e0284c65b8b4816911dbb24b5b31606afbbb5e200aee73fec8d54b3a1b5ffffffff02f06b280dbe4300001976a914eab5a45556ef5d32b3ef2ca39038ff2c22dc0ac388ac702a2d68250000001976a9143b67f8669fe0f20154f6a082b8d409a7ef45a71788ac0000000001000000010f5e2dd0e1345fda806a6e9c04aee0ac4d62744e2a9252904a59c4a17b7a2a98000000006c493046022100adde20f9c4c48a21edbc1c5d8ee7ebb84b1cfd1b165cb03df75b444b3078a2d9022100b3e0196097899ef4a7b4d44dc7eac58619706db2d1bcf10318c7acae1660fc4c01210394bc99f73383e9fdcdcdbc651e1386f898ad701428b340b746845fa32e1c06acffffffff024f0fd7bea44300001976a914c6e702892694a03d45acb1c6a1ac7ba73c12cdd388acc5fd7b620b0000001976a9142cd026c792a73053d09153c77890af5c68a9fef688ac000000000100000001f3a303cdc0af7cdd4b4c8c9e249d8823b29836188a5fc5c8cea194c90b791a65000000006c493046022100fd9ea0732d4cdcfe94ff413c6c268916fad6dfd4f286e9326c74054aae7b7dd1022100c832d033123294ce4bb68f19ea815c07030a5a43e9f9fea5e374e9157f9eef84012102f12131e3fb702021da7f0c104e8ed2bf62defbbc1665e57cf33b30abb9756699ffffffff02df9b893e254500001976a914106941dcc66c2fa9f27390a6078d9b40d9a65ba688acf1d0d8e6430000001976a91430e4ddafe3390a53201b2b92966b081321fe21c788ac00000000010000000189f8ebc5ecdcdb96e2232ab319cda9d0148688037bf918bf1d936c803f6768a2000000006c493046022100902db480a7f96f3f040d1c90a0cb1c0b5ce0f82cb32801c1224f177d1c6a0e57022100bed61d85fd6e567ff8394484dda16f37d03d0f804ab0428e1caba5cc946be7a3012103c2b7e2e3b7f20642e24a8cf09601991534effeb847700b7da1f998c1a4af47cfffffffff023177a4dcc04100001976a914c759d6d84bb8ae179a649a6f422805d73c6d1ed188ac3e35fb659f0000001976a914349aade8a3aea51c53e2219c09159ae8a02c1dc788ac000000000100000001927f0aa9944d6c6c71300c7bce0d52916ca8f860fe8c636b93ed0aa5bf4807bf000000006a473044022025da97f7000b9c457bca72e66e46eb0ffa7a6886da5033250c5b459db606e7de02202cbc057e0dfd3e756b9df3731fde1c161d9060258776914524ca668853f6281e0121038301be0f61a48aa46158df4f21c4f5e88d6ca115c3066840511eec87f1a6d232ffffffff02c476ef7ce63f00001976a9148d00e1f918f564fe73af4b029851692b57ce19ff88ac429db440030000001976a9146f8edbe691126c50d8d476b358dd1b35fc50a74a88ac0000000001000000018b7c1ea529ede1829228dbc1638311ecbad5e877fb6f033abf3cbf727b78288c000000006a47304402201b86f5388e25061fc98d386cf62cc4f2011c20b97f8763f4eabed6a9adb67f2202203e0e5724a2d489e6dc4080a785ccd0d780e46f6a56d028ba29c310e121bb38dd0121028ae2e636f1ab8a75ffedc8d7f9e9f209df65efb5ec01553ad80f6e1abd2d0927ffffffff02d362d223eb3a00001976a914b51bc04c073efd1a5e8580fb99b991475fc83db488acffb50fe1040000001976a914c0739d12a52442fc74b4ed450835fccfd39ba7d688ac00000000010000000112f8d7e247d338e4befdb0958416c55c1dcc9ebed4276bb63d2329cdb8d6386b000000006b4830450220279bbcbfa2126eccf128b0e60cebd6728bb4aa06c1127a74287a8d97fc907a88022100cc717bd88ebf70e12cffab735d34e9deab1d760313727c04d5fc307f1bba925c012102f12131e3fb702021da7f0c104e8ed2bf62defbbc1665e57cf33b30abb9756699ffffffff028297004b654500001976a9141bca2699bcfd22696c4fb48ae17e4388b56c974088acaeee3bb72d0000001976a91439ac5348ef36a7ad3b2e4cdc4dab5b40f0c92ccc88ac00000000010000000160148f4bc471c4eab91adcb1d08a34493d9b1f36983309b020f211a10fb618b9000000006a47304402201d73855c296deb0841732bf8b453dcc5e26c8adb41db94613b9613819cb4603802204de42eaeccf66d00183ac25bccb897403e90d204e81a1793e6f16944972d1b1f012102f12131e3fb702021da7f0c104e8ed2bf62defbbc1665e57cf33b30abb9756699ffffffff02e2f619fc514000001976a914ea4080357193f0262131a5f6d9a7147a9d4808ee88ac2e6d583c9d0100001976a914ac8e7d7cfee0719b65b817f8e19478f4aa52a61988ac00000000010000000198462733af97f0178e24bf43e2762598ab6e859941cf9d88fdd69c70e7f2692f000000006a473044022073bf50e5786c64df8f5b316d784e8b76a6bfe76d78f3bba7e6143e37ddfd1aec02204ca19c1a274b7968835618dd007ea368e40b19451e5cb2f852253e91d276911201210354a3e90adffcc53ab4dfbc5415609bf20aaf7e2977d65199b3a6b402bcabaac5ffffffff020dbbc80bb93700001976a914785945e6e79efa53737b900b369ea9045eede7ae88ac2f3adeb20f0000001976a9149ee142d4933c469dd94d5b8b3facf037551ab34a88ac0000000001000000016dfa5d79a5ceeba2e63ce7f3ecad2a297c056c57ff1a128aa271e412ccd62894000000006a47304402200a76035bc1ec09453015d8886de64ead54ad187bdbfa7a2003262fa9d57710bf02203c67c6c5b1d55b818d731485ba29b58746c0b2cab5a6a372d90cea082d0e9ac9012103c36d0193b48e58df778514d12ed6cef9a6805e15ee17560cd7a36489af7c07d5ffffffff02f665521c313300001976a914442bade72f31a96178b51b56c147f3c3746383a888ac6dbcaaca300000001976a9146710ca622dda2074eb582e6906a06762f8e9877288ac00000000010000000159a7fe7db5a82c75d3336931e945658a10dbcd43367f3ada353051d2165c233c000000006c4930460221009c9450e5cc91ce4d9288c8a33b60b831631d953deee29db417a6a9dff86f28df022100c5172060b942aed5ac25f934f6c6779e981c9e43face06ae7671da074b52db5c012102c9307227839f1bc7a6a0c0cd0e1ce1b66fd1252a6142fd5a933565e90dc6c9deffffffff0222a09839232c00001976a9145540d1f5b1ba0d201d3d65d1f50cb56d0b719e8488acad09d885630000001976a9145488c1dc9696ff149573f0d618a2825ce9b6d89188ac000000000100000001cd383707e40767eb709907c754ce29cd908ebbb253b9ea9af04249c132e5c8e5000000006b483045022100e8f6d6be33d90069f8a2e74b818e06c62314eea3c0ab4399f0327518002b8dc10220478846dac78dff1fa2699e92827d707b685d5b2258e1218068fd4bd53268969c012102dd32c9fca97f0bd283c5700b8cb356784dcb747ad02b834a355bfd610011c1b9ffffffff028ecffee2142300001976a914ee05ad7473ade55f6d5d7935c1784699de03db3888ac9b24fcc56e0000001976a9144cc878fbd60ebd012ff0b0adea67ce1998f3c82488ac00000000010000000195cf853f74d0998660c5bb760f964c5bf2bd684c87f5c163b46f211331a17d6f000000006b4830450220741357334f730b581e9deeebb65413c6cf43a0fa13d784c23f552279653dea4e022100ae37ff5e1dd5256504f8877774305cdaf9f8856be999ed0361ec48d7acdd623f012103f8f4c543bb07c02d8e875015112ba8a53f5bed4fbd1e41dac117cc9c33ed4c29ffffffff020b4d9d6dcc3e00001976a9141d32e1773e9bff9bbcad2e354716cd51ade2b15888ac9cd7498ee20100001976a914ea91ae0d2ed39ef836de955bbdcc5ab5199078eb88ac000000000100000001140285b03cf863ea74f49e37918359faa51b37ba0b6664539254312f0f530c32000000006b483045022100f973269fe9261d371c67248bc77977b56abd9ea6df53ab23578431e6d700121b02205699a7b8e0172c71a0a9e339fa141026f1e5dbf11c375e9915014b002a46cab1012103e6d12b03c46c144cfdbfa455d658ea4aced56eca862b375c93d2b6254128e477ffffffff0205422fbd232000001976a914ede332eca6fe017e4dd28e82e74e19dad25c932588ac3e7b4f75dc0100001976a914a319fe7fcc1af64a0bb227fa136e3c5e68df717f88ac000000000100000001a169984d4b491d3dd85caed0b64ff736368deb6b14da8a1a723dae1c0fd3b8c5000000006c493046022100c0792489e62df87ac50d3577216f1cdf56aed56c470c6cd1bc930a365e4dbdd60221009f07dc7263538419e1ec340b62ebf85e897708cb6b8535cf191311f96a578f5e01210274295f0aaf9feb65c39789974cc6eaa8b02fbbb3082b3f74b7e8088929e8a060ffffffff0200d8c379580000001976a9143ca44a8f52ae6b7664261a6c8bc2d12ab0f95c9188ac00c817a8040000001976a914f7a51d8d827cfd3799c86dd3e49869820432152d88ac000000000100000001fbd22d8646a507b0352f0c9aba4a18ad085f33e405c2a7d82745c0cb8c3c35fa000000006c493046022100a843a84900199a538b1dfe798ccc37764f4be42cc1e1212038cd5a0f959580ef022100ab63b323d1b103f51be6619cd56a91c1c6dec4108e7dea91a79be9c3682444300121028ef3550f2ac386eda4693aab194f0c0b6d705b3cf6aeaae80d4ad8a29bae1453ffffffff02ac88fbcb111900001976a914e4569bd4e2cc5c219d471cc275676c38a49d1b3f88ace6e0e033ed0100001976a91465f472366974dbe61b6afe32b1c5e540fe85374388ac000000000100000001b559ec599ab860f17762165c11fed9d74d165e66c3180ab6197f0b7a9af333f3000000006b483045022016ac64e84fe4752f2ed90d621d50ff8168c5171c0c313132bacaad809267d007022100cd2194881f3b727a79b5c3648f98b1308684a2bc57359e08ee6d0fab844019b401210395d67ed3e4bcd475e2220340111979410177ca883c03e59ab0dd7ed3dccf546cffffffff02b9e21fd9ff0a00001976a9142d52b77df72ecaa916d64c977c65f0920a42cf6288acd76bbc9c820200001976a91451c1e3a14e552ed48d8c017e03f640209191f66188ac0000000001000000016f57d172ed0b0be8fed5e592e006c8572db7e9c7d7f7becd100d060625e61c20000000006b483045022100e9d98e3ed4e14408e851be0a409f31c4d120a05fe35b853198f978de742be0cd02203a82730c134a3df9f7884b03777a023f72182abf9c3c273d1b01226fa2535373012102765abf7f2e9bc9fdb7875e296fba7c237dc3a89aed556c3d21bd6e8fee1b7c64ffffffff025172e9fd820100001976a914b34d27ada5f4564a6591731dbeb85359bd23e56588ac089d0972450000001976a9143f5795cc18b8ddcfc6959cd21bdf172d550b622d88ac000000000100000001e9e6c80ea548acc353e80d9e01c62a9219dc86bc55399ce5f0a6326cac9b88cc000000006c493046022100f08fc68ecf2932c1393fff190e26bacbd8301b8b71b3f078c65156f172bd75890221009d447a389fb98d0e2d09b88748f06514af27d946f11bfac9e8a303d1f65503320121030325c56bbe07f5c0c15daac9c93045ff43147227979ff64edaa9ae6a6cf944cfffffffff02800006215d0000001976a91491de980eef8bc18dcf1c8f5f24a91de114ced97b88ac00e87648170000001976a914ee3dfe91f45cc8609f3ab360f9c8434b5072d8bf88ac000000000100000001ad384cd6fc42ac07a32e98fe04237b5e767acc8cc5649b397a27ea0f07a7793c000000006b483045022027a48904b6e268cc68d80779f9937d0bec1c38ac85992f7c5baf697410639bd9022100a98206045bcd7bc993820982802182b17a0acebc850f253eec8cfc8f4f116db501210384019126ddfd0840f2a2183cb2a2ef03484363de1e76ded2fd6503264a7cc375ffffffff02ba3afec3020000001976a91402a1bd3c172ce6a7dc48c1b26a4cf4fe7a50a88688ac8a6aa1a0700000001976a91435817dbf7712242707ceee16c75a66c217e46b5e88ac000000000100000001c3b341fe8c7c2aeefeb2ec45b8db11439f42eebd9250036b0ade36893bd69441000000006a473044022022b96539208ec7695c1e179fe46892c8c1801718142128bf41ee90eef8e6058302202bb7fc004af5fda94f60eb0c6645e0a22c926ad8272b9e6076a1f3ba6b7b1257012103677c99f3795d776b3382210c7ace9c60fc602bf5132f40f6c86f77805bf00ebaffffffff026ce5fd5d0c0000001976a914b0fa13c804a4fb2b71477deb8bd3fe1c97c54c6788ac3350ff43020000001976a9142f3766ffae062cdf5abc0b6afebf11b1ec482f9088ac000000000100000001608147c1c4242b8269df1cd094b73acc8cc63e12368f70405a88b9f1f4a23cbb000000006b4830450221008d7e607b6cbb751888cbfd7745018db3a18fb823880f5e70a1b197f23c8478e602202d20ced76725380c443abc09eb0b64a0f81475a2c530456c751dadb9f5d5a928012102bca287c29330e82e97490a70d3172943d534c0eef5a647bd2601f46d20d4f895ffffffff02b0efe152120000001976a914bd51cbacc2f51f56c4658095402bd1b523c4071588ac002f6859000000001976a914379d450d8f0fec803f4a7177e4790cf71892ff0288ac0000000001000000014f1dbadc8b1d9aca76fc0e86b5ee838a2af96cfaa53c4bd7d0e886374551303c000000006b48304502206b918932accbad034e02c93c7bd50e9f0ba09dadf4e724909c8798200acc4e63022100a3c710892db562e317a76db93aaa23798aa6a01015270752c4717e2ff44abbfd0121026ee313706b2b5e43378e385c0100197d9f4b9cbfad41f4b3343e7f4e1dfadefbffffffff02c030d3df0b0000001976a914a12a0ba8aee0bacd20897e3fdbcca4ec69fa635a88ac002f6859000000001976a91417702b2fb402036c34966d1e1bef9437b963b0b588ac0000000001000000025c5001b99c7420de0a3a4dd990b9262c29b1e21423c7e27c345c4460cbb0e0f3010000006b4830450220599243b08bd2d1bae0eb441e9722533ea9ce48a81d24ceec8025527af83b6b1702210096f8ccb3d01bde2f0292eda38d7749027eeb2bddadf32049936f299304cb7ed2012102cca48ff13d91d8cb0a6c3ed4621afe4808a34219611cedf0d161b199f2a9495effffffffc365e98c4f561e5a94e3c478d8ef5f810619fba8106e6bf924b2f196d3dcd380010000006c493046022100d377faba853e431113350085a053722334a6914387450c37b8e2b47300936d2c022100f200c6ddabdf0aa942b1f418eb957eb68c4404e4e03baa1129e7e33eaacadb3a012102722fbee877b3574c15ae68494c26daf0f6f66fef3fea560a536649e5c4e9d788ffffffff032010ec0b000000001976a9142e7bad4e6b8fb320526c244baba7b1e117fe15f988ac460a1f02000000001976a914a86238d772862d5d49c02df4f3a44a3334c8f78c88ac00e1f505000000001976a9147176d74cfc80e881c1e246073c7b7f54a08aa9a988ac0000000001000000011836a740e6b1a606d3b5683758f9d4dd8c8414b0665b2520676ebd439141e1ad010000006b483045022100840369aec703f2755899a7a210e02b45bd05fa1b7850487fd77a5e637aab21920220373d210df5773f94e78c75cde8e8e232597846b27d392c80ca9866af87299acc01210259dfe32e03297251c28218ee30bd9442f806a9933ed0c4e3a44646537946028dffffffff02f03dcd1d000000001976a914175766046f1a4d0b27bf65595b23afa089469ad888ac0065cd1d000000001976a9141848712e8bdb27f8f5851e02628405e82fec5c3188ac0000000001000000015a05b5fdfb63567852b8e65da966a0dd8aeed08495fb00546db33da0a2430b7f010000006a4730440220333029caff63e744e4273e215435fd4cc630a9059643989db8edf3b6efdc6baf022057c95582e6e18647d70706ada16ff00c409a206c6a133f7c7d19ada425e8dab30121036d62a4b2abf90f055348b65ea191a245dd35adc08d0d62ca841315ff3cbefd8dffffffff02f0326202000000001976a9140c57e2412e1b141cdd887b7fd682717ebcb3317f88ac002a7515000000001976a914ec4ce286a8f13b159b0b6b780dd739f88466ab2588ac00000000010000000190f4444ea19c3976c869aa811f022315e24bf8352aa53f5e166e14c4c4e93d60000000006c493046022100a0c1c046f278eb91caf3ed0b6fab3141af668008dc025c675e489d0226b22aa00221008736cfaf34d1e9f960a87e1fe73e1e057e946904bb36d8895c68df7628263ac9012103be44e7d8ce17e6e2c16ec410ba6887dbc1ecce046fc7680d0d1b8f2f6110bae6ffffffff027405296ab31d00001976a91439f0714728198d0977ab5d99861962c181891c2188ac81150653700200001976a9143b2ca6388d1584e322ef5b9bbb19b6b126d31db188ac0000000001000000016145ca32406d87dd1796b4a63108baf8b2131ab6a7bf876ec0d0e9b178ad2ba9000000006b48304502203d063e2e174fad8aad15135475fb759c1ca43bb3cc2070e2d6e0305f2348b96d0221009a6a91ac562e538ce373f98249b9aa97a9fb60cbc29c556fee840a4d595497c20121024764f035175e356ea61c4265758a559d55707c1bcddba43cac794656330eb7beffffffff0236ff3fe3d50000001976a914e9ff7390c984b1b1f95547210e45dcb18782ba5388ac0b4ca91aad0000001976a9143fdeef661804f5007deb3ef814c1fd96895ffce288ac000000000100000001de7964a90543f362edc16ee1946478b1aab0ef8346516221b880c16ad3282abf000000006c493046022100b8497f78025f4b75628ed0819374d32d191ee672fb8bf24770680215d7accca502210095a34e6ad1a86abc8bdf8fe52c1be8ff7f05ee411fc836454c6c224044e947ad012103f40772c3b66966830c4ec3719ab4cb0bb2723e104da517cb4a21d9c735936dcaffffffff0242ccde1f001d00001976a9142dc19e20544793d2463541ba9c940a20e7f412f188ac22124a4ab30000001976a914601fbafed7e20c89f3fe82f2613e5f4237013fe788ac00000000010000000199b5c7044148e1b70e9be6536e78fa86d065f35aba1f45e1dfb628b89de998cd000000006c4930460221009253c8e1b69eda103d1c3cd68a50434eb65f5734ff829ba79a9593cdfc0435f702210095ac80d2c4247b41c9661f634581eeba578d4098913833c52ea66788c74e5b8d012102d696799157cf883ea4481341d4b3946753065fd9fc070f6ce2e62ae91a73bb29ffffffff02a38d5153700000001976a914b32b21602dd0d5f4c915615cca2359b0cdc8042688ac834aee8f650000001976a91471e32802f0633cde6ebebd8be62d2d8e160a78d888ac000000000100000001ff6a3b75785f06f723ba2c223706c082f9fe7af2879fbece9cddff210387ccfe000000006b4830450221008b9e087380b5b867af3830fc058a18ad3683fbc13724a18486b2ecb92b1e5b5202200eb097f7f37d6f629b8fdb21677770d27852813af84dfec5c5423d14729bfc570121026b8d2d7b55d3eb7f8b0fe5329ecc0162d15024b350ea934d50e630f6aa4b9c53ffffffff029936333b9a1c00001976a914513ccacb7d3184369abfe95194e1ab0c0f834e7088ac996eabe4650000001976a9140729a22f5c0a09c90c7f449cdb5d1958367bc1c388ac00000000010000000187ac1346ff2814f1c466fac8d447cffa89ac987d4eb4c798815434b61244ee83000000006a4730440220712ca819e728281ab5de5812f458c0ff5c3c7f91f4d8d128ee1d12397ebcb4f80220264888e0964beeccbfe0505ac34cd0701bd4d792d7509f5658779e598102c97c012102033a5cb1264a04439d8bdb134ebbef6a5682c1bb7c536456bd5ad4db37041e84ffffffff0234f7635f390000001976a914968ced36b3cfebd16eb80339ba7d539b54be710488ac5f6fedf3360000001976a914d29fccf37034c310adde6e63bbd0cdbd107c695588ac00000000";

        block_from_value(json!(some_block), Network::Dogecoin)
            .expect("Can't deserialize correct block");
    }

    // Test AuxPow block
    #[test]
    fn deserialize_doge_block_371337() {
        let some_block = "020162000d6f03470d329026cd1fc720c0609cd378ca8691a117bd1aa46f01fb09b1a8468a15bf6f0b0e83f2e5036684169eafb9406468d4f075c999fb5b2a78fbb827ee41fb11548441361b0000000001000000010000000000000000000000000000000000000000000000000000000000000000ffffffff380345bf09fabe6d6d980ba42120410de0554d42a5b5ee58167bcd86bf7591f429005f24da45fb51cf0800000000000000cdb1f1ff0e000000ffffffff01800c0c2a010000001976a914aa3750aa18b8a0f3f0590731e1fab934856680cf88ac00000000b3e64e02fff596209c498f1b18f798d62f216f11c8462bf3922319000000000003a979a636db2450363972d211aee67b71387a3daaa3051be0fd260c5acd4739cd52a418d29d8a0e56c8714c95a0dc24e1c9624480ec497fe2441941f3fee8f9481a3370c334178415c83d1d0c2deeec727c2330617a47691fc5e79203669312d100000000036fa40307b3a439538195245b0de56a2c1db6ba3a64f8bdd2071d00bc48c841b5e77b98e5c7d6f06f92dec5cf6d61277ecb9a0342406f49f34c51ee8ce4abd678038129485de14238bd1ca12cd2de12ff0e383aee542d90437cd664ce139446a00000000002000000d2ec7dfeb7e8f43fe77aba3368df95ac2088034420402730ee0492a2084217083411b3fc91033bfdeea339bc11b9efc986e161c703e07a9045338c165673f09940fb11548b54021b58cc9ae50601000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d0389aa050101062f503253482fffffffff010066f33caf050000232102b73438165461b826b30a46078f211aa005d1e7e430b1e0ed461678a5fe516c73ac000000000100000001ef2e86aa5f027e13d7fc1f0bd4a1fc677d698e42850680634ccd1834668ff320010000006b483045022100fcf5dc43afa85978a71e76a9f4c11cd6bf2a7d5677212f9001ad085d420a5d3a022068982e1e53e94fc6007cf8b60ff3919bcaf7f0b70fefb79112cb840777d8c7cf0121022b050b740dd02c1b4e1e7cdbffe6d836d987c9db4c4db734b58526f08942193bffffffff02004e7253000000001976a91435cb1f77e88e96fb3094d84e8d3b7789a092636d88ac00d4b7e8b00700001976a9146ca1f634daa4efc7871abab945c7cefd282b481f88ac0000000001000000010a6c24bbc92fd0ec32bb5b0a051c44eba0c1325f0b24d9523c109f8bb1281f49000000006a4730440220608577619fb3a0b826f09df5663ffbf121c8e0164f43b73d9affe2f9e4576bd0022040782c9a7df0a20afe1a7e3578bf27e1331c862253af21ced4fde5ef1b44b787012103e4f91ad831a87cc532249944bc7138a355f7d0aac25dc4737a8701181ce680a5ffffffff010019813f0d0000001976a91481db1aa49ebc6a71cad96949eb28e22af85eb0bd88ac0000000001000000017b82db0f644ecff378217d9b8dc0de8817eaf85ceefacab23bf344e2e495dca5010000006b483045022100f07ced6bfdbd6cdeb8b2c8fc92b9803f5798754b5b6c454c8f084198bea303f402205616f84d7ec882af9c34a3fd2457ca3fb81ec5a463a963a6e684edee427d4525012102c056b10494520dbd7b37e2e6bb8f72f98d73a609a926901221bfb114fa1d5a80ffffffff02f0501a22000000001976a914ca63ded8b23d0252158a3bdc816747ef89fb438988ac80b65ea1350700001976a914fb26a7c16ace531a8e7bbd925e46c67c3150c1c888ac000000000100000001c9bdba900e1579ebf4e44415fe8b9abec57a763f8c70a30604bea7fbe7c55d42000000006a47304402204ccbeeace0630e72102fdaf0836e41f8f6dcdde6a178f0fbc2d96a4d17a1df8f02207e4a91203a2abd87fdddee96510482ef96535741b6c17a1acae93c977ad248e5012103e0747583a342b76a5de9c21db138b9640d49b4f3b67a306d3b3f217416d49b55ffffffff020058850c020000001976a9144417c63a91208a02a5f46a0f7a2b806adc7d19a788ac0042dc06030000001976a9147b61c5adef0d559e5acf2901c2989294624b651988ac0000000001000000017c1423b198dfc3da37ae9a5fc11a3720e4343b3049d3b289b8285eb04595c04b000000006b483045022100b0c1cb9608bf644d7a8916bf61f36ced95bd045e97612804ca774f60e05e7bde022017c12255eecc474c8d8b05d0910013b2df8703af68212cf0962b6b8ee0e101ee01210341e154088c23b8ea943bca94c1d4f65361668a242b168522f00199365414b46affffffff01019891ad000000001976a91481db1aa49ebc6a71cad96949eb28e22af85eb0bd88ac00000000";

        block_from_value(json!(some_block), Network::Dogecoin)
            .expect("Can't deserialize correct block");
    }
}
