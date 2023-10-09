cargo_component_bindings::generate!();

use alloy_primitives::FixedBytes;
use alloy_sol_types::{sol, SolEvent};
use bindings::component::uq_process::types::*;
use bindings::{
    get_payload, print_to_terminal, receive, send_request, send_response,
    Guest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{HashMap, HashSet};

mod process_lib;

struct Component;

#[derive(Debug, Serialize, Deserialize)]
enum AllActions {
    EventSubscription(EthEvent),
}

#[derive(Debug, Serialize, Deserialize)]
struct EthEvent {
    address: String,
    blockHash: String,
    blockNumber: String,
    data: String,
    logIndex: String,
    removed: bool,
    topics: Vec<String>,
    transactionHash: String,
    transactionIndex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Bid {
    from: String, // .uq name
    amount: String,
    block: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Secret {
    from: String, // .uq name
    message: String,
    messageHash: String,
    topBid: Option<Bid>,
    secret: Option<String>,
    block: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct State {
    secrets: HashMap<String, Secret>, // NOTE order these by time
    mySecrets: HashMap<String, String>,
    myBids: HashSet<String>,
    // last block we read from TODO might not need this
    block: u64,
}

sol! {
    event NewSecret(bytes32 indexed messageHash, string message, bytes uqname);
    event BidPlaced(bytes32 indexed messageHash, uint256 amount, bytes uqname);
    event SecretRevealed(bytes32 indexed messageHash, string secret, bytes uqname);
}

fn subscribe_to_secrets(from_block: u64) -> String {
    json!({
        "SubscribeEvents": {
            "addresses": [
                // Secrets on sepolia
                "0xfd571a1a8Ba4bAe58f5729aF52E2ED7277ed3DF2",
            ],
            "from_block": from_block,
            "to_block": null,
            "events": [
                "NewSecret(bytes32,string,bytes)",
                "BidPlaced(bytes32,uint256,bytes)",
                "SecretRevealed(bytes32,string,bytes)",
            ],
            "topic1": null,
            "topic2": null,
            "topic3": null,
        }
    }).to_string()
}

const SECRETS_PAGE: &str = include_str!("index.html");
const SECRETS_JS: &str = include_str!("index.js");
const SECRETS_CSS: &str = include_str!("index.css");

impl Guest for Component {
    fn init(our: Address) {
        print_to_terminal(0, "secrets: start");

        let mut state = State {
            secrets: HashMap::new(),
            mySecrets: HashMap::new(),
            myBids: HashSet::new(),
            block: 1,
        };

        match process_lib::get_state(our.node.clone()) {
            None => {},
            Some(p) => {
                match bincode::deserialize::<State>(&p.bytes) {
                    Err(e) => print_to_terminal(
                        0,
                        &format!("secrets: failed to deserialize payload from fs: {}", e),
                    ),
                    Ok(s) => {
                        state = s;
                    },
                }
            },
        }

        let _subscribe_to_events_res = send_request(
            &Address{
                node: our.node.clone(),
                process: ProcessId::Name("eth_rpc".to_string()),
            },
            &Request{
                inherit: false, // TODO what
                expects_response: Some(5), // TODO evaluate
                metadata: None,
                // -1 because there could be other events in the last processed block
                ipc: Some(subscribe_to_secrets(state.block - 1)),
            },
            None,
            None,
        );

        let _bind_app_res = send_request(
            &Address{
                node: our.node.clone(),
                process: ProcessId::Name("http_bindings".to_string()),
            },
            &Request{
                inherit: false,
                expects_response: None,
                metadata: None,
                ipc: Some(serde_json::json!({
                    "action": "bind-app",
                    "path": "/secrets",
                    "app": "secrets",
                    "authenticated": false, // TODO true
                }).to_string()),
            },
            None,
            None,
        );

        let _bind_app_res = send_request(
            &Address{
                node: our.node.clone(),
                process: ProcessId::Name("http_bindings".to_string()),
            },
            &Request{
                inherit: false,
                expects_response: None,
                metadata: None,
                ipc: Some(serde_json::json!({
                    "action": "bind-app",
                    "path": "/secrets/feed",
                    "app": "secrets",
                    "authenticated": true,
                }).to_string()),
            },
            None,
            None,
        );

        let _bind_app_res = send_request(
            &Address{
                node: our.node.clone(),
                process: ProcessId::Name("http_bindings".to_string()),
            },
            &Request{
                inherit: false,
                expects_response: None,
                metadata: None,
                ipc: Some(serde_json::json!({
                    "action": "bind-app",
                    "path": "/secrets/save-secret",
                    "app": "secrets",
                    "authenticated": false, // TODO true
                }).to_string()),
            },
            None,
            None,
        );

        let _bind_app_res = send_request(
            &Address{
                node: our.node.clone(),
                process: ProcessId::Name("http_bindings".to_string()),
            },
            &Request{
                inherit: false,
                expects_response: None,
                metadata: None,
                ipc: Some(serde_json::json!({
                    "action": "bind-app",
                    "path": "/secrets/my-secrets",
                    "app": "secrets",
                    "authenticated": false, // TODO true
                }).to_string()),
            },
            None,
            None,
        );

        loop {
            let Ok((source, message)) = receive() else {
                print_to_terminal(0, "secrets: got network error");
                continue;
            };
            let Message::Request(request) = message else {
                print_to_terminal(0, "secrets: got unexpected response");
                continue;
            };

            if source.process == ProcessId::Name("http_bindings".to_string()) {
                print_to_terminal(0, "secrets: got http request");
                let Ok(ipc) = serde_json::from_str::<serde_json::Value>(&request.ipc.clone().unwrap_or_default()) else {
                    print_to_terminal(0, "secrets: got invalid http request");
                    continue;
                };
                print_to_terminal(0, &format!("{}", ipc.as_str().unwrap_or_default()));
                if ipc["path"].as_str().unwrap_or_default() == "/secrets" &&
                    ipc["method"].as_str().unwrap_or_default() == "GET" {
                        send_response(
                            &Response {
                                ipc: Some(serde_json::json!({
                                    "status": 200,
                                    "headers": {
                                        "Content-Type": "text/html",
                                    },
                                }).to_string()),
                                metadata: None,
                            },
                            Some(&Payload {
                                mime: Some("text/html".to_string()),
                                bytes: SECRETS_PAGE
                                    .replace("${node}", our.node.as_str())
                                    .replace("${js}", SECRETS_JS)
                                    .replace("${css}", SECRETS_CSS)
                                    .to_string()
                                    .as_bytes()
                                    .to_vec(),
                            })
                        );
                        continue;
                } else if ipc["path"].as_str().unwrap_or_default() == "/secrets/feed" {
                    let mut secrets = Vec::new();
                    for (_, secret) in state.secrets.iter() { // TODO sort these by block
                        secrets.push(json!({
                            "message": secret.message,
                            "messageHash": secret.messageHash,
                            "from": secret.from,
                            "topBid": secret.topBid,
                            "secret":
                                if let Some(sec) = &secret.secret {
                                    Some(sec.clone())
                                } else if secret.from == our.node {
                                    if let Some(msg) = state.mySecrets.get(&secret.messageHash){ 
                                        Some(msg.clone())
                                    } else { None }
                                } else { None },
                            "block": secret.block,
                        }));
                    }
                    let response = json!({
                        "secrets": secrets,
                    }).to_string();
                    send_response(
                        &Response {
                            ipc: Some(serde_json::json!({
                                "status": 200,
                                "headers": {
                                    "Content-Type": "application/json",
                                },
                            }).to_string()),
                            metadata: None,
                        },
                        Some(&Payload {
                            mime: Some("application/json".to_string()),
                            bytes: response.as_bytes().to_vec(),
                        })
                    );
                    continue;
                } else if ipc["path"].as_str().unwrap_or_default() == "/secrets/save-secret" &&
                          ipc["method"].as_str().unwrap_or_default() == "POST" {
                    let Some(payload) = get_payload() else {
                        print_to_terminal(0, "secrets: got invalid http request1");
                        continue;
                    };
                    let Ok(body) = serde_json::from_slice::<serde_json::Value>(&payload.bytes) else {
                        print_to_terminal(0, "secrets: got invalid http request2");
                        continue;
                    };
                    let Some(message) = body["message"].as_str() else {
                        print_to_terminal(0, "secrets: got invalid http request3");
                        continue;
                    };
                    let Some(secretToStore) = body["secret"].as_str() else {
                        print_to_terminal(0, "secrets: got invalid http request4");
                        continue;
                    };

                    state.mySecrets.insert(message.to_string(), secretToStore.to_string());
                    print_to_terminal(0, "secrets: saved secret");
                    send_response(
                        &Response {
                            ipc: Some(serde_json::json!({
                                "status": 200,
                                "headers": {
                                    "Content-Type": "application/json",
                                },
                            }).to_string()),
                            metadata: None,
                        },
                        Some(&Payload {
                            mime: Some("application/json".to_string()),
                            bytes: "success".to_string().as_bytes().to_vec(),
                        })
                    );
                    process_lib::await_set_state(our.node.clone(), &state);
                    continue;
                } else if ipc["path"].as_str().unwrap_or_default() == "/secrets/my-secrets" &&
                          ipc["method"].as_str().unwrap_or_default() == "GET" {
                    print_to_terminal(0, "secrets: got my secrets");
                    send_response(
                        &Response {
                            ipc: Some(serde_json::json!({
                                "status": 200,
                                "headers": {
                                    "Content-Type": "application/json",
                                },
                            }).to_string()),
                            metadata: None,
                        },
                        Some(&Payload {
                            mime: Some("application/json".to_string()),
                            bytes: json!(state.mySecrets).to_string().as_bytes().to_vec(),
                        })
                    );
                    continue;
                } else {
                    print_to_terminal(0, "secrets: got invalid http request5");
                    print_to_terminal(0, &format!("{}", ipc.as_str().unwrap_or_default()));
                    // print_to_terminal(0, &format!("{}", ipc["method"].as_str().unwrap_or_default()));
                    continue;
                }
            }

            let Ok(msg) = serde_json::from_str::<AllActions>(&request.ipc.clone().unwrap_or_default()) else {
                print_to_terminal(0, "secrets: got invalid message");
                continue;
            };

            match msg {
                AllActions::EventSubscription(e) => {
                    match decode_hex(&e.topics[0].clone()) {
                        NewSecret::SIGNATURE_HASH => {
                            print_to_terminal(0, "secrets: new secret");
                            let message_hash       = &e.topics[1];
                            let decoded    = NewSecret::decode_data(&decode_hex_to_vec(&e.data), true).unwrap();
                            let message = decoded.0;
                            let name = dnswire_decode(decoded.1);
                            let block = e.blockNumber;

                            let secret = Secret {
                                from: name,
                                message: message,
                                messageHash: message_hash.clone(),
                                topBid: None,
                                secret: None,
                                block: block,
                            };

                            state.secrets.insert(message_hash.clone(), secret);
                        }
                        BidPlaced::SIGNATURE_HASH => {
                            print_to_terminal(0, "secrets: bid placed");
                            let message_hash    = &e.topics[1];
                            let decoded    = BidPlaced::decode_data(&decode_hex_to_vec(&e.data), true).unwrap();
                            let amount = decoded.0;
                            let name = dnswire_decode(decoded.1);

                            let bid = Bid {
                                from: name,
                                amount: amount.to_string(),
                                block: e.blockNumber,
                            };

                            let secret = state.secrets.get_mut(&message_hash.clone()).unwrap();
                            secret.topBid = Some(bid);
                        }
                        SecretRevealed::SIGNATURE_HASH => {
                            print_to_terminal(0, "secrets: secret revealed");
                            let message_hash   = &e.topics[1];
                            let decoded    = SecretRevealed::decode_data(&decode_hex_to_vec(&e.data), true).unwrap();
                            let revealed_message = decoded.0;
                            let name = dnswire_decode(decoded.1);
                            
                            print_to_terminal(0, &format!("secrets: REVEALED {}", revealed_message));

                            let Some(mut secret) = state.secrets.get_mut(&message_hash.clone()) else {
                                panic!("secrets: got secret revealed event for unknown secret"); // this should never happen
                            };

                            secret.secret = Some(revealed_message);
                        }
                        event => {
                            bindings::print_to_terminal(0, format!("qns_indexer: got unknown event: {:?}", event).as_str());
                        }
                    }
                }
            }
            process_lib::await_set_state(our.node.clone(), &state);
        }
    }
}

// helpers
// TODO these probably exist somewhere in alloy...not sure where though.
fn decode_hex(s: &str) -> FixedBytes<32> {
    // If the string starts with "0x", skip the prefix
    let hex_part = if s.starts_with("0x") {
        &s[2..]
    } else {
        s
    };

    let mut arr = [0_u8; 32];
    arr.copy_from_slice(&hex::decode(hex_part).unwrap()[0..32]);
    FixedBytes(arr)
}

fn decode_hex_to_vec(s: &str) -> Vec<u8> {
    // If the string starts with "0x", skip the prefix
    let hex_part = if s.starts_with("0x") {
        &s[2..]
    } else {
        s
    };

    hex::decode(hex_part).unwrap()
}

fn dnswire_decode(wire_format_bytes: Vec<u8>) -> String {
    let mut i = 0;
    let mut result = Vec::new();

    while i < wire_format_bytes.len() {
        let len = wire_format_bytes[i] as usize;
        if len == 0 { break; }
        let end = i + len + 1;
        let mut span = wire_format_bytes[i+1..end].to_vec();
        span.push('.' as u8);
        result.push(span);
        i = end;
    };

    let flat: Vec<_> = result.into_iter().flatten().collect();

    let name = String::from_utf8(flat).unwrap();

    // Remove the trailing '.' if it exists (it should always exist)
    if name.ends_with('.') {
        name[0..name.len()-1].to_string()
    } else {
        name
    }
}
