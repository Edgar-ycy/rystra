use rystra_config::{ClientConfig, ConfigValidation};

fn main() {
    let config = ClientConfig::load_from_file("./crates/rystra-config/client.toml").unwrap();
    println!("rystra-client boot");
    println!("{:#?}", config);
    let ans: bool = config.validate().is_err();
    let ans = if ans { "错误" } else { "正常" };
    println!("数据是否有合理：{}", ans)
}
