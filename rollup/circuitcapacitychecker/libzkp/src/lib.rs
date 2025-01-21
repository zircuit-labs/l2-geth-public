#![feature(once_cell)]

pub mod checker {
    use crate::utils::{c_char_to_str, vec_to_c_char};
    use anyhow::{anyhow, bail, Error};
    use capacity_checker::CircuitCapacityChecker;
    use libc::c_char;
    use serde::{Deserialize, Serialize};
    use std::cell::OnceCell;
    use std::collections::HashMap;
    use std::panic;
    use std::ptr::null;
    use std::time::Instant;
    use traits::capacity_checker::{CapacityChecker, RowUsage};

    static mut CHECKERS: OnceCell<HashMap<u64, CircuitCapacityChecker>> = OnceCell::new();

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct TxNumResult {
        pub tx_num: u64,
        pub error: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct CommonResult {
        pub error: Option<String>,
    }

    #[derive(Debug, Clone, Deserialize, Serialize)]
    pub struct RowUsageResult {
        pub acc_row_usage: Option<RowUsage>,
        pub error: Option<String>,
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn init() {
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
            .format_timestamp_millis()
            .init();
        let checkers = HashMap::new();
        CHECKERS
            .set(checkers)
            .expect("circuit capacity checker initialized twice");
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn new_circuit_capacity_checker() -> u64 {
        let checkers = CHECKERS
            .get_mut()
            .expect("fail to get circuit capacity checkers map in new_circuit_capacity_checker");
        let id = checkers.len() as u64;
        let checker = CircuitCapacityChecker::new();
        checkers.insert(id, checker);
        id
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn reset_circuit_capacity_checker(id: u64) {
        CHECKERS
            .get_mut()
            .expect("fail to get circuit capacity checkers map in reset_circuit_capacity_checker")
            .get_mut(&id)
            .unwrap_or_else(|| panic!("fail to get circuit capacity checker (id: {id:?}) in reset_circuit_capacity_checker"))
            .reset()
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn apply_tx(
        id: u64,
        tx_traces: *const c_char,
        proof_traces: *const c_char,
        code_traces: *const c_char,
    ) -> *const c_char {
        let block_trace_str = c_char_to_str(tx_traces).expect("Malformed block_trace");
        let proof_trace_str = c_char_to_str(proof_traces).expect("Malformed proof_trace");
        let code_trace_str = c_char_to_str(code_traces).expect("Malformed code_trace");

        let start = Instant::now();
        let result = apply_tx_inner(id, block_trace_str, proof_trace_str, code_trace_str);
        let duration = start.elapsed();
        println!("Time elapsed in apply_tx_inner is: {duration:?}");

        let r = match result {
            Ok(acc_row_usage) => {
                log::debug!(
                    "id: {:?}, acc_row_usage: {:?}",
                    id,
                    acc_row_usage.row_number,
                );
                RowUsageResult {
                    acc_row_usage: Some(acc_row_usage),
                    error: None,
                }
            }
            Err(e) => {
                let enforce_ccc_rejection = std::env::var("CCC_REJECT_PANIC_TXS").is_ok();
                log::warn!("|CCC ERROR| An error occurred during CCC apply_tx call. If CCC_REJECT_PANIC_TXS is disabled, stateful CCC 
                (StateDB/CodeDB) will not contain the state changes regarding this very transaction. Error: {e:?}, CCC_REJECT_PANIC_TXS: {enforce_ccc_rejection}, id: {id:?}, block_trace_str: {block_trace_str}, proof_trace_str: {proof_trace_str}, code_trace_str: {code_trace_str}");
                // We can't just set acc_row_usage to None as that's a considered an error as well
                if !enforce_ccc_rejection {
                    RowUsageResult {
                        acc_row_usage: Some(RowUsage::new(0)),
                        error: None,
                    }
                } else {
                    RowUsageResult {
                        acc_row_usage: None,
                        error: Some(format!("{e:?}")),
                    }
                }
            }
        };
        serde_json::to_vec(&r).map_or(null(), vec_to_c_char)
    }

    unsafe fn apply_tx_inner(
        id: u64,
        block_trace_str: &str,
        proof_trace_str: &str,
        code_trace_str: &str,
    ) -> Result<RowUsage, Error> {
        let enforce_ccc_panic_txs_rejection = std::env::var("CCC_REJECT_PANIC_TXS").is_ok();

        log::debug!(
            "ccc apply_tx raw input, id: {:?}, proof_trace_str: {}, code_trace_str: {}, block_trace: {:?}",
            id,
            proof_trace_str,
            code_trace_str,
            block_trace_str
        );

        // TODO: We need to make sure that this trace only contains one transaction
        // What if we get witness block here and check the number of txs before calling
        // estimate_circuit_capacity() ?

        let r = panic::catch_unwind(|| {
            CHECKERS
                .get_mut()
                .ok_or(anyhow!(
                    "fail to get circuit capacity checkers map in apply_tx"
                ))?
                .get_mut(&id)
                .ok_or(anyhow!(
                    "fail to get circuit capacity checker (id: {id:?}) in apply_tx"
                ))?
                .estimate_circuit_capacity(block_trace_str, proof_trace_str, code_trace_str, true)
        });
        match r {
            Ok(result) => result,
            Err(e) => {
                log::warn!("|CCC ERROR| A panic occurred during CCC apply_tx call. If CCC_REJECT_PANIC_TXS is disabled, stateful CCC 
                (StateDB/CodeDB) will not contain the state changes regarding this very transaction. Error: {e:?}, CCC_REJECT_PANIC_TXS: {enforce_ccc_panic_txs_rejection}, id: {id:?}, block_trace_str: {block_trace_str}, proof_trace_str: {proof_trace_str}, code_trace_str: {code_trace_str}");
                if enforce_ccc_panic_txs_rejection {
                    bail!("estimate_circuit_capacity (id: {id:?}) error in apply_tx, error: {e:?}")
                }
                Ok(RowUsage::new(0))
            }
        }
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn apply_block(
        id: u64,
        block_trace: *const c_char,
        proof_traces: *const c_char,
        code_traces: *const c_char,
    ) -> *const c_char {
        let block_trace_str = c_char_to_str(block_trace).expect("Malformed block_trace");
        let proof_trace_str = c_char_to_str(proof_traces).expect("Malformed proof_trace");
        let code_trace_str = c_char_to_str(code_traces).expect("Malformed code_trace");

        let start = Instant::now();
        let result = apply_block_inner(id, block_trace_str, proof_trace_str, code_trace_str);
        let duration = start.elapsed();
        println!("Time elapsed in apply_block_inner is: {duration:?}");
        let r = match result {
            Ok(acc_row_usage) => {
                log::debug!(
                    "id: {:?}, acc_row_usage: {:?}",
                    id,
                    acc_row_usage.row_number,
                );
                RowUsageResult {
                    acc_row_usage: Some(acc_row_usage),
                    error: None,
                }
            }
            Err(e) => {
                let enforce_ccc_rejection = std::env::var("CCC_REJECT_PANIC_TXS").is_ok();
                log::warn!("|CCC ERROR| An error occurred during CCC apply_block call. Error: {e:?}, CCC_REJECT_PANIC_TXS: {enforce_ccc_rejection}, id: {id:?}, block_trace_str: {block_trace_str}, proof_trace_str: {proof_trace_str}, code_trace_str: {code_trace_str}");
                // We can't just set acc_row_usage to None as that's a considered an error as well
                if !enforce_ccc_rejection {
                    RowUsageResult {
                        acc_row_usage: Some(RowUsage::new(0)),
                        error: None,
                    }
                } else {
                    RowUsageResult {
                        acc_row_usage: None,
                        error: Some(format!("{e:?}")),
                    }
                }
            }
        };
        serde_json::to_vec(&r).map_or(null(), vec_to_c_char)
    }

    unsafe fn apply_block_inner(
        id: u64,
        block_trace_str: &str,
        proof_trace_str: &str,
        code_trace_str: &str,
    ) -> Result<RowUsage, Error> {
        let enforce_ccc_panic_txs_rejection = std::env::var("CCC_REJECT_PANIC_TXS").is_ok();

        log::debug!(
            "ccc apply_block raw input, id: {:?}, proof_trace_str: {}, code_trace_str: {}, block_trace: {:?}",
            id,
            proof_trace_str,
            code_trace_str,
            block_trace_str
        );

        let r = panic::catch_unwind(|| {
            CHECKERS
                .get_mut()
                .ok_or(anyhow!(
                    "fail to get circuit capacity checkers map in apply_block"
                ))?
                .get_mut(&id)
                .ok_or(anyhow!(
                    "fail to get circuit capacity checker (id: {id:?}) in apply_block"
                ))?
                .estimate_circuit_capacity(block_trace_str, proof_trace_str, code_trace_str, false)
        });
        match r {
            Ok(result) => result,
            Err(e) => {
                log::warn!("|CCC ERROR| A panic occurred during CCC apply_block call. Error: {e:?}, CCC_REJECT_PANIC_TXS: {enforce_ccc_panic_txs_rejection}, id: {id:?}, block_trace_str: {block_trace_str}, proof_trace_str: {proof_trace_str}, code_trace_str: {code_trace_str}");
                if enforce_ccc_panic_txs_rejection {
                    bail!(
                        "estimate_circuit_capacity (id: {id:?}) error in apply_block, error: {e:?}"
                    )
                }
                Ok(RowUsage::new(0))
            }
        }
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn get_tx_num(id: u64) -> *const c_char {
        let result = get_tx_num_inner(id);
        let r = match result {
            Ok(tx_num) => {
                log::debug!("id: {id}, tx_num: {tx_num}");
                TxNumResult {
                    tx_num,
                    error: None,
                }
            }
            Err(e) => TxNumResult {
                tx_num: 0,
                error: Some(format!("{e:?}")),
            },
        };
        serde_json::to_vec(&r).map_or(null(), vec_to_c_char)
    }

    unsafe fn get_tx_num_inner(id: u64) -> Result<u64, Error> {
        log::debug!("ccc get_tx_num raw input, id: {id}");
        panic::catch_unwind(|| {
            Ok(CHECKERS
                .get_mut()
                .ok_or(anyhow!(
                    "fail to get circuit capacity checkers map in get_tx_num"
                ))?
                .get_mut(&id)
                .ok_or(anyhow!(
                    "fail to get circuit capacity checker (id: {id}) in get_tx_num"
                ))?
                .get_tx_num() as u64)
        })
        .map_or_else(
            |e| bail!("circuit capacity checker (id: {id}) error in get_tx_num: {e:?}"),
            |result| result,
        )
    }

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn set_light_mode(id: u64, light_mode: bool) -> *const c_char {
        let result = set_light_mode_inner(id, light_mode);
        let r = match result {
            Ok(()) => CommonResult { error: None },
            Err(e) => CommonResult {
                error: Some(format!("{e:?}")),
            },
        };
        serde_json::to_vec(&r).map_or(null(), vec_to_c_char)
    }

    unsafe fn set_light_mode_inner(id: u64, light_mode: bool) -> Result<(), Error> {
        log::debug!("ccc set_light_mode raw input, id: {id}");
        panic::catch_unwind(|| {
            CHECKERS
                .get_mut()
                .ok_or(anyhow!(
                    "fail to get circuit capacity checkers map in set_light_mode"
                ))?
                .get_mut(&id)
                .ok_or(anyhow!(
                    "fail to get circuit capacity checker (id: {id}) in set_light_mode"
                ))?
                .set_light_mode(light_mode);
            Ok(())
        })
        .map_or_else(
            |e| bail!("circuit capacity checker (id: {id}) error in set_light_mode: {e:?}"),
            |result| result,
        )
    }
}

pub mod utils {
    use std::ffi::{CStr, CString};
    use std::os::raw::c_char;
    use std::str::Utf8Error;

    /// # Safety
    #[no_mangle]
    pub unsafe extern "C" fn free_c_chars(ptr: *mut c_char) {
        if ptr.is_null() {
            log::warn!("Try to free an empty pointer!");
            return;
        }

        let _ = CString::from_raw(ptr);
    }

    #[allow(dead_code)]
    pub(crate) fn c_char_to_str(c: *const c_char) -> Result<&'static str, Utf8Error> {
        let cstr = unsafe { CStr::from_ptr(c) };
        cstr.to_str()
    }

    #[allow(dead_code)]
    pub(crate) fn c_char_to_vec(c: *const c_char) -> Vec<u8> {
        let cstr = unsafe { CStr::from_ptr(c) };
        cstr.to_bytes().to_vec()
    }

    #[allow(dead_code)]
    pub(crate) fn vec_to_c_char(bytes: Vec<u8>) -> *const c_char {
        CString::new(bytes)
            .expect("fail to create new CString from bytes")
            .into_raw()
    }

    #[allow(dead_code)]
    pub(crate) fn bool_to_int(b: bool) -> u8 {
        match b {
            true => 1,
            false => 0,
        }
    }
}
