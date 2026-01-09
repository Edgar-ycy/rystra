use rystra_core::config::common_config::ServerConfig;
use toml;
fn main() {
    let content = std::fs::read_to_string("config/server.toml").expect("配置文件读取失败");
    let config: ServerConfig = toml::from_str(&content.as_str()).expect("配置文件解析失败");
    println!("{:#?}", config);
}