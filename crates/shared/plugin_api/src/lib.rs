use std::ffi::{c_char, CStr};

/// Result code for plugin operations
pub const PLUGIN_OK: i32 = 0;
pub const PLUGIN_ERR: i32 = -1;

/// Context passed from Host to Plugin during execution
/// All fields must be C-compatible
#[repr(C)]
pub struct HostContext {
    pub version: u32,
    pub _reserved: [u64; 4],
}

impl Default for HostContext {
    fn default() -> Self {
        Self {
            version: 1,
            _reserved: [0; 4],
        }
    }
}

/// FFI-Safe Virtual Function Table
/// Each function pointer uses C calling convention
#[repr(C)]
pub struct PluginVTable {
    /// Returns plugin name as null-terminated C string
    pub name: unsafe extern "C" fn(data: *const ()) -> *const c_char,
    
    /// Returns the opcode this plugin handles
    pub opcode: unsafe extern "C" fn(data: *const ()) -> u8,
    
    /// Execute the plugin logic
    /// Returns PLUGIN_OK (0) on success, PLUGIN_ERR (-1) on failure
    pub execute: unsafe extern "C" fn(
        data: *const (),
        cmd: *const u8,
        cmd_len: usize,
        ctx: *const HostContext,
    ) -> i32,
    
    /// Destroy the plugin instance and free memory
    pub destroy: unsafe extern "C" fn(data: *mut ()),
}

/// FFI-Safe Plugin Handle
/// This replaces the fat pointer (*mut dyn Plugin)
#[repr(C)]
pub struct PluginHandle {
    /// Opaque pointer to plugin-specific data
    pub data: *mut (),
    /// Pointer to the virtual function table
    pub vtable: *const PluginVTable,
}

// Safety: PluginHandle is Send+Sync because we control access through vtable
unsafe impl Send for PluginHandle {}
unsafe impl Sync for PluginHandle {}

impl PluginHandle {
    /// Create a new PluginHandle from data and vtable
    pub fn new(data: *mut (), vtable: *const PluginVTable) -> Self {
        Self { data, vtable }
    }

    /// Get plugin name (safe wrapper)
    pub fn name(&self) -> &str {
        unsafe {
            let name_ptr = ((*self.vtable).name)(self.data);
            if name_ptr.is_null() {
                return "unknown";
            }
            CStr::from_ptr(name_ptr).to_str().unwrap_or("unknown")
        }
    }

    /// Get opcode (safe wrapper)
    pub fn opcode(&self) -> u8 {
        unsafe { ((*self.vtable).opcode)(self.data) }
    }

    /// Execute plugin (safe wrapper)
    pub fn execute(&self, cmd: &[u8], ctx: &HostContext) -> Result<(), String> {
        if self.vtable.is_null() || self.data.is_null() {
            return Err("plugin handle is null".to_string());
        }
        
        unsafe {
            let result = ((*self.vtable).execute)(
                self.data,
                cmd.as_ptr(),
                cmd.len(),
                ctx as *const HostContext,
            );
            if result == PLUGIN_OK {
                Ok(())
            } else {
                Err("plugin execution failed".to_string())
            }
        }
    }
}

impl Drop for PluginHandle {
    fn drop(&mut self) {
        if !self.data.is_null() && !self.vtable.is_null() {
            unsafe {
                ((*self.vtable).destroy)(self.data);
            }
        }
    }
}

/// Type signature for the plugin constructor
/// This is now FFI-safe (returns a simple C struct)
pub type PluginCreate = unsafe extern "C" fn() -> PluginHandle;

/// Helper macro to create a static VTable for a plugin
#[macro_export]
macro_rules! declare_plugin {
    ($plugin_type:ty, $name_str:expr) => {
        static PLUGIN_NAME: &[u8] = concat!($name_str, "\0").as_bytes();
        
        static VTABLE: plugin_api::PluginVTable = plugin_api::PluginVTable {
            name: plugin_name,
            opcode: plugin_opcode,
            execute: plugin_execute,
            destroy: plugin_destroy,
        };

        unsafe extern "C" fn plugin_name(_data: *const ()) -> *const std::ffi::c_char {
            PLUGIN_NAME.as_ptr() as *const std::ffi::c_char
        }

        unsafe extern "C" fn plugin_opcode(data: *const ()) -> u8 {
            let plugin = &*(data as *const $plugin_type);
            plugin.opcode()
        }

        unsafe extern "C" fn plugin_execute(
            data: *const (),
            cmd: *const u8,
            cmd_len: usize,
            ctx: *const plugin_api::HostContext,
        ) -> i32 {
            let plugin = &*(data as *const $plugin_type);
            let cmd_slice = std::slice::from_raw_parts(cmd, cmd_len);
            let context = &*ctx;
            match plugin.execute(cmd_slice, context) {
                Ok(_) => plugin_api::PLUGIN_OK,
                Err(_) => plugin_api::PLUGIN_ERR,
            }
        }

        unsafe extern "C" fn plugin_destroy(data: *mut ()) {
            if !data.is_null() {
                let _ = Box::from_raw(data as *mut $plugin_type);
            }
        }

        #[no_mangle]
        pub extern "C" fn _create_plugin() -> plugin_api::PluginHandle {
            let plugin = Box::new(<$plugin_type>::new());
            let data = Box::into_raw(plugin) as *mut ();
            plugin_api::PluginHandle::new(data, &VTABLE)
        }
    };
}
