use rystra_config::{ConfigValidation, ServerConfig};

fn main() {
    let config = ServerConfig::load_from_file("./crates/rystra-config/server.toml").unwrap();
    println!("rystra-server boot");
    println!("{:#?}", config);
    let ans: bool = config.validate().is_err();
    let ans = if ans { "错误" } else { "正常" };
    println!("数据是否有合理：{}", ans)
}
