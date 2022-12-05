pub use crate::bindings_server::*;
use crate::util;
use crate::{EapMethod, EapStatus, TlsConfig};

use std::{
    collections::HashMap,
    ffi::{c_int, c_void, CStr},
    sync::Once,
};

static SERVER_INIT: Once = Once::new();

pub struct EapServerStepResult {
    pub response: Option<Vec<u8>>,
    pub key_material: Option<Vec<u8>>,
    pub status: EapStatus,
}

#[derive(Default, Clone)]
pub struct EapServerBuilder {
    passwords: HashMap<String, String>,
    tls_config: Option<TlsConfig>,
    method_priorities: Vec<EapMethod>,
}

impl EapServerBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_password(&mut self, username: &str, password: &str) -> &mut Self {
        self.passwords
            .insert(username.to_string(), password.to_string());
        self
    }

    pub fn set_tls_config(&mut self, tls_config: TlsConfig) -> &mut Self {
        self.tls_config = Some(tls_config);
        self
    }

    pub fn allow_md5(&mut self) -> &mut Self {
        self.allow_method(EapMethod::MD5)
    }

    pub fn allow_tls(&mut self) -> &mut Self {
        self.allow_method(EapMethod::TLS)
    }

    fn allow_method(&mut self, method: EapMethod) -> &mut Self {
        if !self.method_priorities.contains(&method) {
            self.method_priorities.push(method);
        }
        self
    }

    pub fn build(&mut self) -> Box<EapServer> {
        EapServer::init(self.clone())
    }
}

pub struct EapServer {
    interface: *mut eap_eapol_interface,
    callbacks: eapol_callbacks,
    eap_config: eap_config,
    state: *mut eap_sm,
    tls_state: Option<EapServerTlsState>,
    users: HashMap<String, String>,
    method_priorities: Vec<EapMethod>,
}

// This is keep around to prevent the memory from being freed
struct EapServerTlsState {
    tls_ctx: *mut c_void,
    tls_params: Box<tls_connection_params>,
    tls_config: Box<tls_config>,
    TlsConfig: TlsConfig,
}

impl Drop for EapServerTlsState {
    fn drop(&mut self) {
        unsafe {
            tls_deinit(self.tls_ctx);
        }
    }
}

impl EapServer {
    pub fn new() -> EapServerBuilder {
        EapServerBuilder::new()
    }

    fn init(builder: EapServerBuilder) -> Box<Self> {
        SERVER_INIT.call_once(|| unsafe {
            assert!(eap_server_identity_register() == 0);
            assert!(eap_server_md5_register() == 0);
            assert!(eap_server_tls_register() == 0);
        });

        let callbacks: eapol_callbacks = eapol_callbacks {
            get_eap_user: Some(Self::server_get_eap_user),
            get_eap_req_id_text: Some(Self::get_eap_req_id_text),
            log_msg: None,
            get_erp_send_reauth_start: None,
            get_erp_domain: None,
            erp_get_key: None,
            erp_add_key: None,
        };

        let mut eap_config: eap_config = unsafe { std::mem::zeroed() };
        eap_config.eap_server = 1;

        // Init Tls
        // Note: Cannot free builder.tls_config as it used by tls config.
        let tls_state = if let Some(tls) = builder.tls_config {
            let mut tls_config: Box<tls_config> = Box::new(unsafe { std::mem::zeroed() });
            let mut tls_params: Box<tls_connection_params> =
                Box::new(unsafe { std::mem::zeroed() });

            let tls_ctx;
            unsafe {
                tls_ctx = tls_init(&*tls_config);
                assert!(!tls_ctx.is_null());

                let ca_cert = &tls.ca_cert[..];
                tls_params.ca_cert_blob = ca_cert.as_ptr();
                tls_params.ca_cert_blob_len = ca_cert.len();

                let client_cert = &tls.server_cert[..];
                tls_params.client_cert_blob = client_cert.as_ptr();
                tls_params.client_cert_blob_len = client_cert.len();

                let private_key = &tls.server_key[..];
                tls_params.private_key_blob = private_key.as_ptr();
                tls_params.private_key_blob_len = private_key.len();

                let dh = &tls.dh_params[..];
                tls_params.dh_blob = dh.as_ptr();
                tls_params.dh_blob_len = dh.len();

                assert_eq!(tls_global_set_params(tls_ctx, &*tls_params), 0);
                assert_eq!(tls_global_set_verify(tls_ctx, 0, 1), 0);
            }

            eap_config.ssl_ctx = tls_ctx as *mut c_void;

            Some(EapServerTlsState {
                tls_ctx,
                tls_params,
                tls_config,
                TlsConfig: tls,
            })
        } else {
            None
        };

        let mut me = Box::new(Self {
            interface: std::ptr::null_mut(),
            callbacks,
            eap_config,
            state: std::ptr::null_mut(),
            tls_state,
            users: builder.passwords,
            method_priorities: builder.method_priorities,
        });

        me.state = unsafe {
            let me_ptr = me.as_mut() as *mut Self as *mut c_void;
            let callback_ptr = (&me.callbacks) as *const eapol_callbacks;

            eap_server_sm_init(me_ptr, callback_ptr, &mut me.eap_config)
        };
        assert!(!me.state.is_null());

        me.interface = unsafe { eap_get_interface(me.state) };
        unsafe {
            (*me.interface).portEnabled = true as _;
            (*me.interface).eapRestart = true as _;
        }

        me
    }

    pub fn receive(&mut self, buffer: &[u8]) {
        unsafe {
            wpabuf_free((*self.interface).eapRespData);
            (*self.interface).eapRespData =
                wpabuf_alloc_copy(buffer.as_ptr() as *const c_void, buffer.len());
            (*self.interface).eapResp = true as _;
        }
    }

    pub fn step(&mut self) -> EapServerStepResult {
        let _state_changed = unsafe { eap_server_sm_step(self.state) } == 1;

        let sent_message = unsafe { (*self.interface).eapReq } != 0;
        let finished = unsafe { (*self.interface).eapSuccess } != 0;
        let failed = unsafe { (*self.interface).eapFail } != 0;
        let has_key_material = unsafe { (*self.interface).eapKeyAvailable } != 0;

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
        let response = if (sent_message || finished || failed) && buffer_filled {
            let data = unsafe { (*self.interface).eapReqData };
            let data = unsafe { std::slice::from_raw_parts((*data).buf, (*data).used) }.to_vec();

            Some(data)
        } else {
            None
        };

        let key_material = if has_key_material {
            unsafe {
                let key = (*self.interface).eapKeyData;
                let length = (*self.interface).eapKeyDataLen;
                let key = std::slice::from_raw_parts(key, length).to_vec();
                Some(key)
            }
        } else {
            None
        };

        EapServerStepResult {
            status,
            response,
            key_material,
        }
    }

    unsafe extern "C" fn server_get_eap_user(
        ctx: *mut c_void,
        identity: *const u8,
        identity_len: usize,
        phase2: c_int,
        user: *mut eap_user,
    ) -> i32 {
        let me = &mut *(ctx as *mut Self);

        // user is freed automaticly via `eap_user_free`.
        unsafe {
            *user = std::mem::zeroed();
        }

        let identity = unsafe { std::slice::from_raw_parts(identity, identity_len) };
        let identity = String::from_utf8_lossy(identity);

        let password = me.users.get(&identity.to_string());
        for (i, meth) in me.method_priorities.iter().enumerate() {
            assert!(i < 8); // max 8 methods, else out of bounds

            match meth {
                EapMethod::MD5 => {
                    if let Some(password) = password {
                        unsafe {
                            (*user).methods[i].vendor = EAP_VENDOR_IETF as _;
                            (*user).methods[i].method = EapType_EAP_TYPE_TLS as _;
                            ((*user).password, (*user).password_len) = util::malloc_str(password);
                        }
                    }
                }
                EapMethod::TLS => unsafe {
                    (*user).methods[i].vendor = EAP_VENDOR_IETF as _;
                    (*user).methods[i].method = EapType_EAP_TYPE_TLS as _;
                },
            }
        }

        0
    }

    unsafe extern "C" fn get_eap_req_id_text(ctx: *mut c_void, len: *mut usize) -> *const i8 {
        *len = 0;
        std::ptr::null()
    }
}

impl Drop for EapServer {
    fn drop(&mut self) {
        unsafe {
            eap_server_sm_deinit(self.state);
        }
        // TODO : More cleanup ???
    }
}
