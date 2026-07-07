/// Generate a minimal MaxMind-format ASN MMDB for use in symphony unit and integration tests.
///
/// Maps:
///   127.0.0.0/8   → AS64512  "Test-AS-A"
///   192.0.2.0/24  → AS64513  "Test-AS-B"
///
/// Provenance: generated programmatically using the `maxminddb-writer` crate (MIT/Apache-2.0).
/// The output file contains no third-party data and is freely redistributable.
///
/// Usage:
///   cargo run --example gen_test_mmdb -- __test__/fixtures/test-asn.mmdb
use maxminddb_writer::{
	metadata::IpVersion,
	paths::IpAddrWithMask,
	Database,
};
use serde::Serialize;
use std::collections::HashMap;
use std::io::Write;
use std::path::PathBuf;

#[derive(Serialize)]
struct AsnRecord {
	autonomous_system_number: u32,
	autonomous_system_organization: String,
}

fn main() {
	let out_path: PathBuf = std::env::args()
		.nth(1)
		.map(PathBuf::from)
		.unwrap_or_else(|| PathBuf::from("__test__/fixtures/test-asn.mmdb"));

	let mut db = Database::default();
	// Set only public fields (node_count and record_size are managed by the writer).
	db.metadata.ip_version = IpVersion::V4;
	db.metadata.database_type = "GeoLite2-ASN".to_string();
	db.metadata.languages = vec!["en".to_string()];
	db.metadata.binary_format_major_version = 2;
	db.metadata.binary_format_minor_version = 0;
	db.metadata.build_epoch = 0;
	db.metadata.description = HashMap::from([("en".to_string(), "Symphony test ASN DB".to_string())]);

	let ref_a = db
		.insert_value(AsnRecord {
			autonomous_system_number: 64512,
			autonomous_system_organization: "Test-AS-A".to_string(),
		})
		.expect("insert AS64512");
	let ref_b = db
		.insert_value(AsnRecord {
			autonomous_system_number: 64513,
			autonomous_system_organization: "Test-AS-B".to_string(),
		})
		.expect("insert AS64513");

	db.insert_node("127.0.0.0/8".parse::<IpAddrWithMask>().unwrap(), ref_a);
	db.insert_node("192.0.2.0/24".parse::<IpAddrWithMask>().unwrap(), ref_b);

	if let Some(parent) = out_path.parent() {
		std::fs::create_dir_all(parent).expect("create output directory");
	}
	let mut file = std::fs::File::create(&out_path).expect("create output file");
	db.write_to(&mut file).expect("write MMDB");
	file.flush().expect("flush");

	println!("Wrote test ASN MMDB to {}", out_path.display());
	println!("  127.0.0.1 → AS64512");
	println!("  192.0.2.1 → AS64513");
}
