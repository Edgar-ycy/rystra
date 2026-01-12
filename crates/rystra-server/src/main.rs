use rystra_config::ServerConfig;

fn main() {
    let config = ServerConfig::load_from_file("./crates/rystra-config/server.toml").unwrap();
    println!("rystra-server boot");
    println!("{:#?}", config);

}
