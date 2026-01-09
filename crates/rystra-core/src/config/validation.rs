use crate::config::common_config::*;

/// 配置验证trait
pub trait ConfigValidation {
    fn validate(&self) -> Result<(), String>;
}

impl ConfigValidation for ServerConfig{
    fn validate(&self) -> Result<(), String> {
        if self.bind_port==0{
            return Err("bind_port can not be zero".to_string());
        }
        Ok(())
    }
}