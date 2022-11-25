
use std::{collections::HashMap, ffi::{c_int, CStr, c_void}};
pub use crate::bindings_peer::*;


enum EapPeerResult {
    Respond(Vec<u8>),
    Ok,
    Finished,
}

pub struct EapPeer {
    callbacks : Box<eapol_callbacks>,
    config : Box<eap_config>,
    peer_config : Box<eap_peer_config>,
    state : *mut eap_sm,

    wpabuf : *mut wpabuf,

    state_bool : HashMap<eapol_bool_var, bool>,
    state_int : HashMap<eapol_int_var, u32>
}

impl EapPeer {
    fn new() -> Box<Self> {
        // ! BOX, should not be moved 
        let callbacks : Box<eapol_callbacks> = Box::new(eapol_callbacks { 
            get_config: Some(Self::get_config), 
            get_bool: Some(Self::get_bool), 
            set_bool: Some(Self::set_bool), 
            get_int: Some(Self::get_int), 
            set_int: Some(Self::set_int), 
            get_eapReqData: Some(Self::get_eapReqData), 
            set_config_blob: Some(Self::set_config_blob), 
            get_config_blob: Some(Self::get_config_blob), 
            notify_pending: Some(Self::notify_pending), 
            eap_param_needed: None, 
            notify_cert: None,
            notify_status: None, 
            notify_eap_error: None, 
            set_anon_id: None 
        });

        let peer_config : Box<eap_peer_config> = Box::new(unsafe { std::mem::zeroed() });
        let config : Box<eap_config> = Box::new(unsafe { std::mem::zeroed() });
        let wpabuf : *mut wpabuf = unsafe { wpabuf_alloc(0) };
        assert!(!wpabuf.is_null());

        let mut me = Box::new(Self {
            callbacks,
            config,
            peer_config,
            state: std::ptr::null_mut(),
            wpabuf,
            state_bool: HashMap::new(),
            state_int: HashMap::new()
        });
    

        me.state = unsafe { 
            let me_ptr = me.as_mut() as *mut Self as *mut c_void;
            let callback_ptr = (&*me.callbacks) as *const eapol_callbacks;

            eap_peer_sm_init(
                me_ptr, 
                callback_ptr, 
                me_ptr, 
                me.config.as_mut(),
            )
        };
        assert!(!me.state.is_null());

        me
    }

    fn step(&mut self) -> Option<Vec<u8>> {
        let mut ret = None;
        let _state_changed = unsafe { eap_peer_sm_step(self.state) } == 1;

        let should_sent_response = *self.state_bool.get(&eapol_bool_var_EAPOL_eapResp).unwrap_or(&false);
        
        if should_sent_response {
            let data = unsafe { eap_get_eapRespData(self.state) };
            if data.is_null() {
                return None;
            }

            ret = Some(unsafe { std::slice::from_raw_parts((*data).buf, (*data).used) }.to_vec());
            unsafe {wpabuf_free(data) };
        }

        /* 
            // Key Material
            if (eap_ctx.eapSuccess) {
                res = 0;
                if (eap_key_available(eap_ctx.eap)) {
                    const u8 *key;
                    size_t key_len;
                    key = eap_get_eapKeyData(eap_ctx.eap, &key_len);
                    wpa_hexdump(MSG_DEBUG, "EAP keying material",
                            key, key_len);
                }
            }
        */
        ret
    }

    fn receive(&mut self, input : &[u8]) {
        self.state_bool.insert(eapol_bool_var_EAPOL_eapResp, true);
        self.wpabuf = unsafe {
            wpabuf_alloc_copy(input.as_ptr() as *const c_void, input.len())
        };

    }


    unsafe extern "C" fn get_config(ctx : *mut c_void) -> *mut eap_peer_config {
        let eap = &mut *(ctx as *mut Self);
        &mut *eap.peer_config
    }

    unsafe extern "C" fn get_bool(ctx : *mut c_void, variable : eapol_bool_var) -> bool {
        let eap = &mut *(ctx as *mut Self);
        eap.state_bool.get(&variable).copied().unwrap_or(false)
    }
    
    unsafe extern "C" fn set_bool(ctx : *mut c_void, variable : eapol_bool_var, value : bool) {
        let eap = &mut *(ctx as *mut Self);
        eap.state_bool.insert(variable, value);
    }

    unsafe extern "C" fn get_int(ctx : *mut c_void, variable : eapol_int_var) -> u32 {
        let eap = &mut *(ctx as *mut Self);
        eap.state_int.get(&variable).copied().unwrap_or(0)
    }

    unsafe extern "C" fn set_int(ctx : *mut c_void, variable : eapol_int_var, value : u32) {
        let eap = &mut *(ctx as *mut Self);
        eap.state_int.insert(variable, value);
    }

    unsafe extern "C" fn get_eapReqData(ctx : *mut c_void) -> *mut wpabuf {
        let eap = &mut *(ctx as *mut Self);
        eap.wpabuf
    }

    unsafe extern "C" fn set_config_blob(ctx : *mut c_void, blob : *mut wpa_config_blob) {
        unimplemented!()
    }

    unsafe extern "C" fn get_config_blob(ctx : *mut c_void, name : *const i8) -> *const wpa_config_blob {
        unimplemented!()
    }

    unsafe extern "C" fn notify_pending(ctx : *mut c_void) {
        // NOP
    }

}

impl Drop for EapPeer {
    fn drop(&mut self) {
        unsafe { 
            // TODO : More cleanup
            eap_peer_sm_deinit(self.state);
            wpabuf_free(self.wpabuf);
        };
    }
}