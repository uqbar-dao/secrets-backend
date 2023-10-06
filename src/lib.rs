cargo_component_bindings::generate!();

use alloy_primitives::FixedBytes;
use alloy_sol_types::{sol, SolEvent};
use bindings::component::uq_process::types::*;
use bindings::{
    get_payload, print_to_terminal, receive, send_and_await_response, send_request, send_requests,
    send_response, Guest,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

// mod process_lib;

struct Component;

#[derive(Debug, Serialize, Deserialize)]
enum AllActions {
    EventSubscription(EthEvent),
    StoreSecret(String),
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
struct State {
    // namehash to human readable name
    // allSecrets: HashMap<String, String>,
    // mySecrets: HashMap<String, String>,
    // myBids: HashMap<String, String>,

    // last block we read from
    block: u64,
}

sol! {
    event NewSecret(bytes32 indexed messageHash, string message, bytes uqname);
    event BidPlaced(bytes32 indexed messageHash, address indexed bidder, uint256 amount, bytes uqname);
    event SecretRevealed(bytes32 indexed messageHash, address indexed who, string secret, bytes uqname);
}

fn subscribe_to_secrets(from_block: u64) -> String {
    json!({
        "SubscribeEvents": {
            "addresses": [
                // Secrets on sepolia
                "0x79c3e8Fe22579c7a00E9C1c2130a2F628D3D636D",
            ],
            "from_block": from_block,
            "to_block": null,
            "events": [
                "NewSecret(bytes32,string,bytes)",
                "BidPlaced(bytes32,address,uint256,bytes)",
                "SecretRevealed(bytes32,address,string,bytes)",
            ],
            "topic1": null,
            "topic2": null,
            "topic3": null,
        }
    }).to_string()
}

impl Guest for Component {
    fn init(our: Address) {
        print_to_terminal(0, "secrets: start");

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
                ipc: Some(subscribe_to_secrets(0)), // TODO
            },
            None,
            None,
        );

        // let _bind_app_res = send_request(
        //     &Address{
        //         node: our.node.clone(),
        //         process: ProcessId::Name("http_bindings".to_string()),
        //     },
        //     &Request{
        //         inherit: false,
        //         expects_response: None,
        //         metadata: None,
        //         ipc: Some(serde_json::json!({
        //             "action": "bind-app",
        //             "path": "/secrets",
        //             "app": "secrets",
        //             "authenticated": true,
        //         }).to_string()),
        //     },
        //     None,
        //     None,
        // );

        loop {
            let Ok((source, message)) = receive() else {
                print_to_terminal(0, "secrets: got network error");
                continue;
            };
            let Message::Request(request) = message else {
                print_to_terminal(0, "secrets: got unexpected message");
                continue;
            };

            let Ok(msg) = serde_json::from_str::<AllActions>(&request.ipc.unwrap_or_default()) else {
                print_to_terminal(0, "qns_indexer: got invalid message");
                continue;
            };

            match msg {
                AllActions::EventSubscription(e) => {
                    match decode_hex(&e.topics[0].clone()) {
                        NewSecret::SIGNATURE_HASH => {
                            print_to_terminal(0, "got new secret");
                        }
                        BidPlaced::SIGNATURE_HASH => {
                            print_to_terminal(0, "new bid placed");
                        }
                        SecretRevealed::SIGNATURE_HASH => {
                            print_to_terminal(0, "secret revealed");
                        }
                        event => {
                            bindings::print_to_terminal(0, format!("qns_indexer: got unknown event: {:?}", event).as_str());
                        }
                    }
                }
                AllActions::StoreSecret(s) => {
                    print_to_terminal(0, "store secret");
                }
            }
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
