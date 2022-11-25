use std::{collections::HashMap, ffi::{c_int, CStr, c_void}};
pub use crate::bindings_server::*;


pub struct EapServerStepResult {
    pub response : Option<Vec<u8>>,
    pub status : EapStatus,
}

pub enum EapStatus {
    Ok,
    Finished,
    Failed,
}

pub struct EapServer {
    interface : *mut eap_eapol_interface,
    callbacks : eapol_callbacks,
    eap_config : eap_config,
    state : *mut eap_sm,
    session : eap_session_data,
}

impl EapServer {
    fn new() -> Box<Self> {
        // TODO: Init TLS

        let callbacks : eapol_callbacks = eapol_callbacks {
            get_eap_user: Some(Self::server_get_eap_user),
            get_eap_req_id_text: Some(Self::get_eap_req_id_text),
            log_msg: None,
            get_erp_send_reauth_start: None,
            get_erp_domain: None,
            erp_get_key: None,
            erp_add_key: None,
        };

        let mut eap_config : eap_config = unsafe { std::mem::zeroed() };
        eap_config.eap_server = 1;

        let mut eap_session = unsafe { std::mem::zeroed() };
        
        let mut me = Box::new(Self {
            interface: std::ptr::null_mut(),
            callbacks,
            eap_config,
            state: std::ptr::null_mut(),
            session: eap_session
        });
        
        me.state = unsafe { 
            let me_ptr = me.as_mut() as *mut Self as *mut c_void;
            let callback_ptr = (&me.callbacks) as *const eapol_callbacks;

            eap_server_sm_init(
                me_ptr, 
                callback_ptr, 
                &mut me.eap_config, 
                &mut me.session, 
            )
        };
        assert!(!me.state.is_null());

        me.interface = unsafe { eap_get_interface(me.state) };
        unsafe {
            (*me.interface).portEnabled = true;
            (*me.interface).eapRestart = true;
        }
        unimplemented!()

    }

    fn step(&mut self) -> EapServerStepResult{
        let _state_changed = unsafe { eap_server_sm_step(self.state) } == 1;

        let sent_message = unsafe { (*self.interface).eapReq };
        let finished = unsafe { (*self.interface).eapSuccess };
        let failed = unsafe { (*self.interface).eapFail };

        let status = if failed {
            EapStatus::Failed
        } else if finished {
            EapStatus::Finished
        } else {
            EapStatus::Ok
        };

        if sent_message || finished || failed && unsafe { (*self.interface).eapRespData.is_null() } {
            let data = unsafe { (*self.interface).eapRespData };
            let data = unsafe { std::slice::from_raw_parts((*data).buf, (*data).used) }.to_vec();
            
            EapServerStepResult {
                response: Some(data),
                status
            }
        } else {
            EapServerStepResult {
                response: None,
                status
            }
        }

    }

    unsafe extern "C"  fn server_get_eap_user(ctx : *mut c_void, identity : *const u8, identity_len : usize,  phase2 : c_int, user : *mut eap_user) -> i32 {
        unimplemented!()
    }

    unsafe extern "C" fn get_eap_req_id_text(ctx : *mut c_void, len : *mut usize) -> *const i8 {
        *len = 0;
        std::ptr::null()
    }


}

impl Drop for EapServer {
    fn drop(&mut self) {
        
        // TODO : More cleanup
        unimplemented!()
    }
}