use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn saved_receipt_inspection_uses_the_writer_decoders_offline() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("receipt.json");
    let hash = format!("0x{}", "12".repeat(32));
    let contract = format!("0x{}", "34".repeat(20));
    let block = format!("0x{}", "56".repeat(32));
    let log = json!({"transactionHash":hash,"address":contract,"blockHash":block,"removed":false});
    let mut receipt =
        json!({"transactionHash":hash,"to":contract,"status":"0x1","blockHash":block,"logs":[log]});
    let check = |kind: &str, receipt: &Value, status, outcome, ids: &[&str]| {
        fs::write(&path, serde_json::to_vec(receipt).unwrap()).unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_pyloros"))
            .args(["--inspect-iam-creation", kind, &hash, &contract])
            .arg(&path)
            .env_remove("DATABASE_URL")
            .env_remove("BLOCKCHAIN_RPC_ENDPOINT")
            .env_remove("BLOCKCHAIN_PRIVATE_KEY")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(status), "{:?}", output.stderr);
        assert_eq!(
            serde_json::from_slice::<Value>(&output.stdout).unwrap(),
            json!({"outcome":outcome,"candidate_ids":ids})
        );
    };
    check(
        "identity",
        &receipt,
        2,
        "missing_data_zero_fallback",
        &["0"],
    );
    receipt["logs"][0]["data"] = json!("0x3166");
    for kind in ["group", "policy", "role", "identity"] {
        check(kind, &receipt, 0, "decoded_candidates", &["31"]);
    }
    receipt["logs"][0]["data"] = json!(format!("0x{}", "31".repeat(32)));
    check(
        "policy",
        &receipt,
        0,
        "decoded_candidates",
        &[
            "22250244598543112061784228491865519548275408818103480933072241632893111185713",
            "22685491128062564230891640495451214097",
        ],
    );
    receipt["logs"][0]["data"] = json!(format!("0x{}", "ff".repeat(32)));
    check(
        "group",
        &receipt,
        0,
        "decoded_candidates",
        &["115792089237316195423570985008687907853269984665640564039457584007913129639935"],
    );
    check("role", &receipt, 2, "no_matching_identifier", &[]);
    receipt["logs"][0]["data"] = json!("0x");
    receipt["logs"][0]["topics"] = json!([hash]);
    check("identity", &receipt, 2, "no_matching_identifier", &[]);
    receipt["logs"][0]["data"] = json!("0x31");
    receipt["logs"][0]["blockHash"] = json!(hash);
    check("group", &receipt, 2, "no_matching_identifier", &[]);
    receipt["status"] = json!("0x0");
    check("group", &receipt, 2, "reported_revert", &[]);
    receipt["transactionHash"] = json!(block);
    check("group", &receipt, 2, "hash_mismatch", &[]);
}
