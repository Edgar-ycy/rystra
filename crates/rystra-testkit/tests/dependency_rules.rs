use cargo_metadata::{MetadataCommand, Package, PackageId};
use std::collections::{BTreeSet, HashMap, HashSet};

use rystra_testkit::workspace_manifest_path;

/// Dependency layers from lowest to highest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Layer {
    Model,
    Proto,
    PluginApi,
    Plugins,
    Core,
    App,
    Testkit,
}

impl Layer {
    fn label(self) -> &'static str {
        match self {
            Layer::Model => "model",
            Layer::Proto => "proto",
            Layer::PluginApi => "plugin-api",
            Layer::Plugins => "plugins",
            Layer::Core => "core",
            Layer::App => "app",
            Layer::Testkit => "testkit",
        }
    }
}

fn is_plugin_package(pkg: &Package) -> bool {
    let normalized = pkg.manifest_path.as_str().replace('\\', "/");
    normalized.contains("/crates/plugins/")
}

fn layer_for(pkg: &Package) -> Option<Layer> {
    if is_plugin_package(pkg) {
        return Some(Layer::Plugins);
    }

    match pkg.name.as_str() {
        "rystra-model" => Some(Layer::Model),
        "rystra-proto" => Some(Layer::Proto),
        "rystra-plugin" => Some(Layer::PluginApi),
        "rystra-plugin-registry" => Some(Layer::Core),
        "rystra-net" => Some(Layer::Core),
        "rystra-runtime" => Some(Layer::Core),
        "rystra-config" => Some(Layer::Core),
        "rystra-observe" => Some(Layer::Core),
        "rystra-core" => Some(Layer::Core),
        "rystra-server" | "rystra-client" | "rystra-cli" => Some(Layer::App),
        "rystra-testkit" => Some(Layer::Testkit),
        _ => None,
    }
}

#[test]
fn dependency_rules_are_respected() {
    let manifest_path = workspace_manifest_path();
    let metadata = MetadataCommand::new()
        .manifest_path(&manifest_path)
        .no_deps()
        .exec()
        .expect("cargo metadata failed");

    let workspace_members: HashSet<PackageId> =
        metadata.workspace_members.iter().cloned().collect();

    let mut workspace_packages: Vec<&Package> = Vec::new();
    for pkg in &metadata.packages {
        if workspace_members.contains(&pkg.id) {
            workspace_packages.push(pkg);
        }
    }

    let mut workspace_by_name: HashMap<String, &Package> = HashMap::new();
    for pkg in &workspace_packages {
        workspace_by_name.insert(pkg.name.clone(), *pkg);
    }

    let mut violations: Vec<String> = Vec::new();
    let mut unknown: BTreeSet<String> = BTreeSet::new();

    for pkg in &workspace_packages {
        let pkg_layer = match layer_for(pkg) {
            Some(layer) => layer,
            None => {
                unknown.insert(pkg.name.clone());
                continue;
            }
        };

        for dep in &pkg.dependencies {
            let dep_pkg = match workspace_by_name.get(&dep.name) {
                Some(dep_pkg) => *dep_pkg,
                None => continue,
            };

            let dep_layer = match layer_for(dep_pkg) {
                Some(layer) => layer,
                None => {
                    unknown.insert(dep_pkg.name.clone());
                    continue;
                }
            };

            if pkg_layer == Layer::Plugins && dep_layer == Layer::Plugins {
                violations.push(format!(
                    "plugin crate `{}` must not depend on plugin crate `{}`",
                    pkg.name, dep_pkg.name
                ));
                continue;
            }

            if dep_layer > pkg_layer {
                violations.push(format!(
                    "`{}` ({}) must not depend on `{}` ({})",
                    pkg.name,
                    pkg_layer.label(),
                    dep_pkg.name,
                    dep_layer.label()
                ));
            }
        }
    }

    if !unknown.is_empty() {
        violations.push(format!(
            "unmapped workspace packages: {}",
            unknown.into_iter().collect::<Vec<_>>().join(", ")
        ));
    }

    if !violations.is_empty() {
        panic!("dependency rules violated:\n{}", violations.join("\n"));
    }
}
