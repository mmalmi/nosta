use nostr::nips::nip19::FromBech32;
use nostr::PublicKey;

fn main() {
    let npub = std::env::args().nth(1).unwrap_or_else(|| "npub1g53mukxnjkcmr94fhryzkqutdz2ukq4ks0gvy5af25rgmwsl4ngq43drvk".to_string());
    let pk = PublicKey::from_bech32(&npub).unwrap();
    println!("{}", pk.to_hex());
}
