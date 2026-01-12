use rystra_config::ClientConfig;

fn main() {
    println!("rystra-client boot");
    let config = ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap();
    println!("{:#?}", config);
}
