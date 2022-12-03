use std::{collections::HashMap, ffi::{c_int, CStr, c_void}, sync::Once};
pub use crate::bindings_server::*;
use crate::util;


static SERVER_INIT: Once = Once::new();

pub struct EapServerStepResult {
    pub response : Option<Vec<u8>>,
    pub status : EapStatus,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
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

    tls_ctx : *mut c_void,

    tls_params: Box<tls_connection_params>,
    tls_config: Box<tls_config>,
}

impl EapServer {
    pub fn new() -> Box<Self> {
        // TODO: Init TLS
        SERVER_INIT.call_once(|| {
            unsafe {
                assert!(eap_server_identity_register() == 0);
                //assert!(eap_server_md5_register() == 0);
                assert!(eap_server_tls_register() == 0);
            }
        });

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


        // Init Tls

        let mut tls_config : Box<tls_config> = Box::new(unsafe { std::mem::zeroed() });
        let mut tls_params : Box<tls_connection_params> = Box::new(unsafe { std::mem::zeroed() });

        let tls_ctx;
        unsafe {
            tls_ctx = tls_init(&* tls_config);
            assert!(!tls_ctx.is_null());

            let ca_cert = include_bytes!("dummy/ca.pem");
            tls_params.ca_cert_blob = ca_cert.as_ptr();
            tls_params.ca_cert_blob_len = ca_cert.len();

            let client_cert = include_bytes!("dummy/server-cert.pem");
            tls_params.client_cert_blob = client_cert.as_ptr();
            tls_params.client_cert_blob_len = client_cert.len();

            let private_key = include_bytes!("dummy/server-key.pem");
            tls_params.private_key_blob = private_key.as_ptr();
            tls_params.private_key_blob_len = private_key.len();

            let dh = include_bytes!("dummy/dh.pem");
            tls_params.dh_blob = dh.as_ptr();
            tls_params.dh_blob_len = dh.len();

            assert_eq!(tls_global_set_params(tls_ctx, &* tls_params), 0);
            assert_eq!(tls_global_set_verify(tls_ctx, 0, 1), 0);
        }

        eap_config.ssl_ctx = tls_ctx as *mut c_void;
        
        let mut me = Box::new(Self {
            interface: std::ptr::null_mut(),
            callbacks,
            eap_config,
            state: std::ptr::null_mut(),
            tls_ctx,
            tls_params,
            tls_config,
        });

        
        me.state = unsafe { 
            let me_ptr = me.as_mut() as *mut Self as *mut c_void;
            let callback_ptr = (&me.callbacks) as *const eapol_callbacks;

            eap_server_sm_init(
                me_ptr, 
                callback_ptr, 
                &mut me.eap_config, 
            )
        };
        assert!(!me.state.is_null());

        me.interface = unsafe { eap_get_interface(me.state) };
        unsafe {
            (*me.interface).portEnabled = true as _;
            (*me.interface).eapRestart = true as _;
        }

        me

    }

    pub fn receive(&mut self, buffer : &[u8]) {
        /*
        wpabuf_free(eap_ctx.eap_if->eapRespData);
	eap_ctx.eap_if->eapRespData = wpabuf_alloc_copy(data, data_len);
	if (eap_ctx.eap_if->eapRespData)
		eap_ctx.eap_if->eapResp = true;
        */
        unsafe {
            wpabuf_free(
                (*self.interface).eapRespData
            );
            (*self.interface).eapRespData = wpabuf_alloc_copy(buffer.as_ptr() as *const c_void, buffer.len());
            (*self.interface).eapResp = true as _;
        }
    }

    pub fn step(&mut self) -> EapServerStepResult{
        let _state_changed = unsafe { eap_server_sm_step(self.state) } == 1;

        let sent_message = unsafe { (*self.interface).eapReq } != 0;
        let finished = unsafe { (*self.interface).eapSuccess } != 0 ;
        let failed = unsafe { (*self.interface).eapFail } != 0;

        // clear flags
        unsafe {
            (*self.interface).eapReq = false as _;
            (*self.interface).eapSuccess = false as _;
            (*self.interface).eapFail = false as _;
        }

        let status = if failed {
            EapStatus::Failed
        } else if finished {
            EapStatus::Finished
        } else {
            EapStatus::Ok
        };

        let buffer_filled = unsafe { !(*self.interface).eapReqData.is_null() };
        if (sent_message || finished || failed) && buffer_filled  {
            let data = unsafe { (*self.interface).eapReqData };
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
        // NOTE: 
        // user seems to get freed automaticly via `eap_user_free`.

        dbg!();

        unsafe {*user =  std::mem::zeroed();}

        /*
        Optional check for username
        if (identity_len != 4 || identity == NULL ||
            os_memcmp(identity, "user", 4) != 0) {
            printf("Unknown user\n");
            return -1;
	    }
        */

        /* Only allow EAP-MD5 as the Phase 2 method */
        unsafe {
            (*user).methods[0].vendor = EAP_VENDOR_IETF as _;
            (*user).methods[0].method = EapType_EAP_TYPE_TLS;
            
            //let password = "password";
            //((*user).password, (*user).password_len) = util::malloc_str(password);
        }
        
        0
    }

    unsafe extern "C" fn get_eap_req_id_text(ctx : *mut c_void, len : *mut usize) -> *const i8 {
        *len = 0;
        std::ptr::null()
    }
}

impl Drop for EapServer {
    fn drop(&mut self) {
        unsafe {
            eap_server_sm_deinit(self.state);
            tls_deinit(self.tls_ctx);
        }
        // TODO : More cleanup ???
    }
}

