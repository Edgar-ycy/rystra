use rystra_core::config::common_config::ClientConfig;
use toml;
fn main() {
    let content = std::fs::read_to_string("config/client.toml").expect("配置文件读取失败");
    let config: ClientConfig = toml::from_str(&content.as_str()).expect("配置文件解析失败");
    println!("{:#?}", config);
}
