use rystra_model::Result;

/// 配置验证trait
pub trait ConfigValidation {
    fn validate(&self) -> Result<()>;
}
