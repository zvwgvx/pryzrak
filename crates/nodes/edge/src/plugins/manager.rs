use std::collections::HashMap;
use log::{info, error};
use plugin_api::{PluginHandle, PluginCreate, HostContext};

#[cfg(target_os = "windows")]
use super::native_library::NativeLibrary;

#[cfg(not(target_os = "windows"))]
use libloading::Library as NativeLibrary;

/// Manages the lifecycle of dynamic plugins (FFI-Safe Version)
/// 
/// IMPORTANT: Field order matters for Drop!
/// - registry MUST be declared BEFORE libraries
/// - This ensures plugin handles are destroyed BEFORE library unload
pub struct PluginManager {
    /// Map of Opcode -> Plugin Handle (dropped FIRST)
    registry: HashMap<u8, PluginHandle>,
    /// Map of Name -> Opcode
    registry_names: HashMap<String, u8>,
    /// Loaded libraries - kept alive until after handles are destroyed
    libraries: Vec<NativeLibrary>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            registry: HashMap::new(),
            registry_names: HashMap::new(),
        }
    }

    /// Load a plugin from a file path (.dll / .so)
    #[cfg(target_os = "windows")]
    pub unsafe fn load_plugin(&mut self, path: &str) -> Result<(), String> {
        info!("plugin: loading {}", path);
        
        // Convert path to null-terminated bytes
        let mut path_bytes: Vec<u8> = path.bytes().collect();
        path_bytes.push(0);
        
        let lib = NativeLibrary::new(&path_bytes).map_err(|_| "E40".to_string())?;
        
        // Find the constructor symbol
        let constructor: PluginCreate = lib.get(b"_create_plugin\0")
            .map_err(|_| "E41".to_string())?;

        // Create the plugin handle (FFI-safe struct)
        let handle = constructor();
        let name = handle.name().to_string();
        let opcode = handle.opcode();

        info!("plugin: '{}' -> 0x{:02X}", name, opcode);
        
        // Register
        self.registry.insert(opcode, handle);
        self.registry_names.insert(name, opcode);
        self.libraries.push(lib);

        Ok(())
    }
    
    /// Load a plugin from a file path (.dll / .so) - Non-Windows
    #[cfg(not(target_os = "windows"))]
    pub unsafe fn load_plugin(&mut self, path: &str) -> Result<(), String> {
        info!("plugin: loading {}", path);
        
        let lib = NativeLibrary::new(path).map_err(|e| format!("load: {}", e))?;
        
        // Find the constructor symbol
        let constructor: libloading::Symbol<PluginCreate> = lib.get(b"_create_plugin\0")
            .map_err(|e| format!("symbol: {}", e))?;

        // Create the plugin handle (FFI-safe struct)
        let handle = constructor();
        let name = handle.name().to_string();
        let opcode = handle.opcode();

        info!("plugin: '{}' -> 0x{:02X}", name, opcode);
        
        // Register
        self.registry.insert(opcode, handle);
        self.registry_names.insert(name, opcode);
        self.libraries.push(lib);

        Ok(())
    }

    /// Dispatch a command to the appropriate plugin
    pub fn handle_command(&self, opcode: u8, payload: &[u8]) -> bool {
        if let Some(handle) = self.registry.get(&opcode) {
            info!("plugin: exec '{}' (0x{:02X})", handle.name(), opcode);
            
            let ctx = HostContext::default();

            match handle.execute(payload, &ctx) {
                Ok(_) => info!("plugin: ok"),
                Err(e) => error!("plugin: {}", e),
            }
            true
        } else {
            false 
        }
    }

    /// Dispatch command by Name (e.g. "test")
    pub fn handle_command_by_name(&self, name: &str, payload: &[u8]) -> bool {
        if let Some(opcode) = self.registry_names.get(name) {
            self.handle_command(*opcode, payload)
        } else {
            error!("plugin: name '{}' not found", name);
            false
        }
    }
}
