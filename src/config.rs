use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Limits {
    #[serde(default = "default_hello_timeout_ms")]
    pub hello_timeout_ms: u64,
    #[serde(default = "default_command_timeout_ms")]
    pub command_timeout_ms: u64,
    #[serde(default = "default_tls_handshake_timeout_ms")]
    pub tls_handshake_timeout_ms: u64,
    #[serde(default = "default_pull_timeout_ms")]
    pub pull_timeout_ms: u64,
    #[serde(default = "default_push_timeout_ms")]
    pub push_timeout_ms: u64,
    #[serde(default = "default_max_active_conns")]
    pub max_active_conns: usize,
    #[serde(default = "default_max_hello_frame_bytes")]
    pub max_hello_frame_bytes: usize,
    #[serde(default = "default_max_cmd_frame_bytes")]
    pub max_cmd_frame_bytes: usize,
    #[serde(default = "default_max_pull_items")]
    pub max_pull_items: usize,
    #[serde(default = "default_max_push_items")]
    pub max_push_items: usize,
    #[serde(default = "default_max_del_items")]
    pub max_del_items: usize,
    #[serde(default = "default_max_hist_items")]
    pub max_hist_items: usize,
    #[serde(default = "default_max_name_bytes")]
    pub max_name_bytes: usize,
    #[serde(default = "default_max_data_bytes")]
    pub max_data_bytes: usize,
    #[serde(default = "default_per_connection_inflight_bytes")]
    pub per_connection_inflight_bytes: usize,
    #[serde(default = "default_global_inflight_bytes")]
    pub global_inflight_bytes: usize,
    #[serde(default = "default_lumina_max_cstr_bytes")]
    pub lumina_max_cstr_bytes: usize,
    #[serde(default = "default_lumina_max_hash_bytes")]
    pub lumina_max_hash_bytes: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TLS {
    #[serde(default = "default_pkcs12_path")]
    pub pkcs12_path: String,
    #[serde(default = "default_env_password_var")]
    pub env_password_var: String,
    #[serde(default = "default_min_protocol_sslv3")]
    pub min_protocol_sslv3: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Http {
    #[serde(default = "default_http_bind_addr")]
    pub bind_addr: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Engine {
    #[serde(default = "default_data_dir")]
    pub data_dir: String,
    #[serde(default = "default_segment_bytes")]
    pub segment_bytes: u64,
    #[serde(default = "default_shard_count")]
    pub shard_count: usize,
    #[serde(default = "default_index_capacity")]
    pub index_capacity: usize,
    #[serde(default = "default_sync_interval_ms")]
    pub sync_interval_ms: u64,
    #[serde(default = "default_compaction_check_ms")]
    pub compaction_check_ms: u64,
    #[serde(default = "default_use_mmap_reads")]
    pub use_mmap_reads: bool,
    #[serde(default = "default_deduplicate_on_startup")]
    pub deduplicate_on_startup: bool,

    #[serde(default)]
    pub index_dir: Option<String>,
    #[serde(default = "default_index_memtable_max_entries")]
    pub index_memtable_max_entries: usize,
    #[serde(default = "default_index_block_entries")]
    pub index_block_entries: usize,
    #[serde(default = "default_index_level0_compact_trigger")]
    pub index_level0_compact_trigger: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Debug {
    #[serde(default = "default_dump_hello")]
    pub dump_hello: bool,
    #[serde(default = "default_dump_hello_dir")]
    pub dump_hello_dir: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Lumina {
    #[serde(default = "default_lumina_bind_addr")]
    pub bind_addr: String,
    #[serde(default = "default_server_name")]
    pub server_name: String,
    #[serde(default = "default_allow_deletes")]
    pub allow_deletes: bool,
    #[serde(default = "default_get_history_limit")]
    pub get_history_limit: u32,
    #[serde(default = "default_use_tls")]
    pub use_tls: bool,
    
    #[serde(default)]
    pub tls: Option<TLS>,
    
    #[serde(default)]
    pub credentials: Vec<Credentials>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Upstream {
    #[serde(default = "default_upstream_enabled")]
    pub enabled: bool,
    #[serde(default = "default_upstream_priority")]
    pub priority: u32,
    #[serde(default = "default_upstream_host")]
    pub host: String,
    #[serde(default = "default_upstream_port")]
    pub port: u16,
    #[serde(default = "default_upstream_use_tls")]
    pub use_tls: bool,
    #[serde(default = "default_insecure_no_verify")]
    pub insecure_no_verify: bool,
    #[serde(default = "default_hello_protocol_version")]
    pub hello_protocol_version: u32,
    
    #[serde(default)]
    pub license_path: Option<String>,
    
    #[serde(default = "default_upstream_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_upstream_batch_max")]
    pub batch_max: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Scoring {
    #[serde(default = "default_w_md5")]
    pub w_md5: f64,
    #[serde(default = "default_w_name")]
    pub w_name: f64,
    #[serde(default = "default_w_coh")]
    pub w_coh: f64,
    #[serde(default = "default_w_stab")]
    pub w_stab: f64,
    #[serde(default = "default_w_rec")]
    pub w_rec: f64,
    #[serde(default = "default_w_pop_bin")]
    pub w_pop_bin: f64,
    #[serde(default = "default_w_host")]
    pub w_host: f64,
    #[serde(default = "default_w_origin")]
    pub w_origin: f64,
    #[serde(default = "default_max_versions_per_key")]
    pub max_versions_per_key: usize,
    #[serde(default = "default_max_md5_per_key")]
    pub max_md5_per_key: usize,
    #[serde(default = "default_max_md5_per_version")]
    pub max_md5_per_version: usize,
}

impl Default for Scoring {
    fn default() -> Self {
        Self {
            w_md5: default_w_md5(),
            w_name: default_w_name(),
            w_coh: default_w_coh(),
            w_stab: default_w_stab(),
            w_rec: default_w_rec(),
            w_pop_bin: default_w_pop_bin(),
            w_host: default_w_host(),
            w_origin: default_w_origin(),
            max_versions_per_key: default_max_versions_per_key(),
            max_md5_per_key: default_max_md5_per_key(),
            max_md5_per_version: default_max_md5_per_version(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub limits: Limits,
    
    #[serde(default)]
    pub http: Option<Http>,
    
    #[serde(default)]
    pub engine: Engine,
    
    #[serde(default)]
    pub lumina: Lumina,
    
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    
    #[serde(default)]
    pub scoring: Scoring,
    
    #[serde(default)]
    pub debug: Debug,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            limits: Limits::default(),
            http: Some(Http::default()),
            engine: Engine::default(),
            lumina: Lumina::default(),
            upstreams: Vec::new(),
            scoring: Scoring::default(),
            debug: Debug::default(),
        }
    }
}

// Default functions for Limits
fn default_hello_timeout_ms() -> u64 { 3000 }
fn default_command_timeout_ms() -> u64 { 15000 }
fn default_tls_handshake_timeout_ms() -> u64 { 5000 }
fn default_pull_timeout_ms() -> u64 { 15000 }
fn default_push_timeout_ms() -> u64 { 15000 }
fn default_max_active_conns() -> usize { 2048 }
fn default_max_hello_frame_bytes() -> usize { 16 * 1024 * 1024 }
fn default_max_cmd_frame_bytes() -> usize { 256 * 1024 * 1024 }
fn default_max_pull_items() -> usize { 524288 }
fn default_max_push_items() -> usize { 524288 }
fn default_max_del_items() -> usize { 524288 }
fn default_max_hist_items() -> usize { 4096 }
fn default_max_name_bytes() -> usize { 65535 }
fn default_max_data_bytes() -> usize { 8 * 1024 * 1024 }
fn default_per_connection_inflight_bytes() -> usize { 32 * 1024 * 1024 }
fn default_global_inflight_bytes() -> usize { 512 * 1024 * 1024 }
fn default_lumina_max_cstr_bytes() -> usize { 4096 }
fn default_lumina_max_hash_bytes() -> usize { 64 }

impl Default for Limits {
    fn default() -> Self {
        Self {
            hello_timeout_ms: default_hello_timeout_ms(),
            command_timeout_ms: default_command_timeout_ms(),
            tls_handshake_timeout_ms: default_tls_handshake_timeout_ms(),
            pull_timeout_ms: default_pull_timeout_ms(),
            push_timeout_ms: default_push_timeout_ms(),
            max_active_conns: default_max_active_conns(),
            max_hello_frame_bytes: default_max_hello_frame_bytes(),
            max_cmd_frame_bytes: default_max_cmd_frame_bytes(),
            max_pull_items: default_max_pull_items(),
            max_push_items: default_max_push_items(),
            max_del_items: default_max_del_items(),
            max_hist_items: default_max_hist_items(),
            max_name_bytes: default_max_name_bytes(),
            max_data_bytes: default_max_data_bytes(),
            per_connection_inflight_bytes: default_per_connection_inflight_bytes(),
            global_inflight_bytes: default_global_inflight_bytes(),
            lumina_max_cstr_bytes: default_lumina_max_cstr_bytes(),
            lumina_max_hash_bytes: default_lumina_max_hash_bytes(),
        }
    }
}

// Default functions for TLS
fn default_pkcs12_path() -> String { String::new() }
fn default_env_password_var() -> String { "PKCSPASSWD".into() }
fn default_min_protocol_sslv3() -> bool { true }

impl Default for TLS {
    fn default() -> Self {
        Self {
            pkcs12_path: default_pkcs12_path(),
            env_password_var: default_env_password_var(),
            min_protocol_sslv3: default_min_protocol_sslv3(),
        }
    }
}

// Default functions for Http
fn default_http_bind_addr() -> String { "127.0.0.1:8080".into() }

impl Default for Http {
    fn default() -> Self {
        Self {
            bind_addr: default_http_bind_addr(),
        }
    }
}

// Default functions for Engine
fn default_data_dir() -> String { "data".into() }
fn default_segment_bytes() -> u64 { 1 << 30 } // 1GB
fn default_shard_count() -> usize { 64 }
fn default_index_capacity() -> usize { 1 << 30 } // 1GB
fn default_sync_interval_ms() -> u64 { 200 }
fn default_compaction_check_ms() -> u64 { 30000 }
fn default_use_mmap_reads() -> bool { false }
fn default_deduplicate_on_startup() -> bool { false }
fn default_index_memtable_max_entries() -> usize { 200_000 }
fn default_index_block_entries() -> usize { 128 }
fn default_index_level0_compact_trigger() -> usize { 8 }

impl Default for Engine {
    fn default() -> Self {
        Self {
            data_dir: default_data_dir(),
            segment_bytes: default_segment_bytes(),
            shard_count: default_shard_count(),
            index_capacity: default_index_capacity(),
            sync_interval_ms: default_sync_interval_ms(),
            compaction_check_ms: default_compaction_check_ms(),
            use_mmap_reads: default_use_mmap_reads(),
            deduplicate_on_startup: default_deduplicate_on_startup(),
            index_dir: None,
            index_memtable_max_entries: default_index_memtable_max_entries(),
            index_block_entries: default_index_block_entries(),
            index_level0_compact_trigger: default_index_level0_compact_trigger(),
        }
    }
}

// Default functions for Debug
fn default_dump_hello() -> bool { false }
fn default_dump_hello_dir() -> String { "debug_dumps".into() }

impl Default for Debug {
    fn default() -> Self {
        Self {
            dump_hello: default_dump_hello(),
            dump_hello_dir: default_dump_hello_dir(),
        }
    }
}

// Default functions for Lumina
fn default_lumina_bind_addr() -> String { "0.0.0.0:20667".into() }
fn default_server_name() -> String { "dazhbog".into() }
fn default_allow_deletes() -> bool { false }
fn default_get_history_limit() -> u32 { 0 }
fn default_use_tls() -> bool { false }

impl Default for Lumina {
    fn default() -> Self {
        Self {
            bind_addr: default_lumina_bind_addr(),
            server_name: default_server_name(),
            allow_deletes: default_allow_deletes(),
            get_history_limit: default_get_history_limit(),
            use_tls: default_use_tls(),
            tls: None,
            credentials: Vec::new(),
        }
    }
}

// Default functions for Upstream
fn default_upstream_enabled() -> bool { false }
fn default_upstream_priority() -> u32 { 0 }
fn default_upstream_host() -> String { String::new() }
fn default_upstream_port() -> u16 { 0 }
fn default_upstream_use_tls() -> bool { true }
fn default_insecure_no_verify() -> bool { true }
fn default_hello_protocol_version() -> u32 { 6 }
fn default_upstream_timeout_ms() -> u64 { 8000 }
fn default_upstream_batch_max() -> usize { 1024 }

impl Default for Upstream {
    fn default() -> Self {
        Self {
            enabled: default_upstream_enabled(),
            priority: default_upstream_priority(),
            host: default_upstream_host(),
            port: default_upstream_port(),
            use_tls: default_upstream_use_tls(),
            insecure_no_verify: default_insecure_no_verify(),
            hello_protocol_version: default_hello_protocol_version(),
            license_path: None,
            timeout_ms: default_upstream_timeout_ms(),
            batch_max: default_upstream_batch_max(),
        }
    }
}

// Default functions for Scoring
fn default_w_md5() -> f64 { 2.0 }
fn default_w_name() -> f64 { 1.0 }
fn default_w_coh() -> f64 { 2.0 }
fn default_w_stab() -> f64 { 0.5 }
fn default_w_rec() -> f64 { 0.5 }
fn default_w_pop_bin() -> f64 { 0.5 }
fn default_w_host() -> f64 { 0.25 }
fn default_w_origin() -> f64 { 0.25 }
fn default_max_versions_per_key() -> usize { 16 }
fn default_max_md5_per_key() -> usize { 16 }
fn default_max_md5_per_version() -> usize { 16 }

impl Config {
    pub fn load(path: impl AsRef<Path>) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        
        Ok(config)
    }
    
    pub fn save(&self, path: impl AsRef<Path>) -> io::Result<()> {
        let toml = toml::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        
        fs::write(path, toml)
    }
}

// Example of a TOML config file that this would parse:
/*
[limits]
hello_timeout_ms = 3000
command_timeout_ms = 15000
tls_handshake_timeout_ms = 5000
pull_timeout_ms = 15000
push_timeout_ms = 15000
max_active_conns = 2048
max_hello_frame_bytes = 16777216
max_cmd_frame_bytes = 268435456
max_pull_items = 524288
max_push_items = 524288
max_del_items = 524288
max_hist_items = 4096
max_name_bytes = 65535
max_data_bytes = 8388608
per_connection_inflight_bytes = 33554432
global_inflight_bytes = 536870912
lumina_max_cstr_bytes = 4096
lumina_max_hash_bytes = 64

[http]
bind_addr = "127.0.0.1:8080"

[engine]
data_dir = "data"
segment_bytes = 1073741824
shard_count = 64
index_capacity = 1073741824
sync_interval_ms = 200
compaction_check_ms = 30000
use_mmap_reads = false
deduplicate_on_startup = false
index_dir = "index"
index_memtable_max_entries = 200000
index_block_entries = 128
index_level0_compact_trigger = 8

[lumina]
bind_addr = "0.0.0.0:20667"
server_name = "dazhbog"
allow_deletes = false
get_history_limit = 0
use_tls = false

# Configure multiple username/password pairs for authentication
# If credentials are empty, only "guest" user is allowed
[[lumina.credentials]]
username = "user1"
password = "password1"

[[lumina.credentials]]
username = "user2"
password = "password2"

[[lumina.credentials]]
username = "admin"
password = "secure_password"

[lumina.tls]
pkcs12_path = "cert.p12"
env_password_var = "PKCSPASSWD"
min_protocol_sslv3 = true

[[upstreams]]
enabled = true
priority = 1
host = "upstream.example.com"
port = 20667
use_tls = true
insecure_no_verify = false
hello_protocol_version = 6
license_path = "license.txt"
timeout_ms = 8000
batch_max = 1024

[scoring]
w_md5 = 2.0
w_name = 1.0
w_coh = 2.0
w_stab = 0.5
w_rec = 0.5
w_pop_bin = 0.5
w_host = 0.25
w_origin = 0.25
max_versions_per_key = 16
max_md5_per_key = 16
max_md5_per_version = 16

[debug]
dump_hello = false
dump_hello_dir = "debug_dumps"
*/
