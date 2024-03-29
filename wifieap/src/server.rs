use common::{EapStepResult, EapStepStatus, EapWrapper};

pub use crate::bindings_server::*;
use crate::util;
use crate::{EapMethod, TlsConfig};

use std::{
    collections::HashMap,
    ffi::{c_int, c_void},
    sync::Once,
};

static SERVER_INIT: Once = Once::new();

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
    _tls_state: Option<EapServerTlsState>,
    users: HashMap<String, String>,
    method_priorities: Vec<EapMethod>,
    response_buffer: Vec<u8>,
    final_status: Option<EapStepStatus>,
}

// This is keep around to prevent the memory from being freed
struct EapServerTlsState {
    tls_ctx: *mut c_void,
    _tls_params: Box<tls_connection_params>,
    _tls_config: Box<tls_config>,
    _cfg: TlsConfig,
    _temp_files: Vec<tempfile::NamedTempFile>,
}

impl Drop for EapServerTlsState {
    fn drop(&mut self) {
        unsafe {
            tls_deinit(self.tls_ctx);
        }
    }
}

impl EapServer {
    pub fn builder() -> EapServerBuilder {
        EapServerBuilder::new()
    }

    pub fn new_password(identity: &str, password: &str) -> Box<EapServer> {
        let mut builder = EapServerBuilder::new();
        builder.set_password(identity, password);
        builder.allow_md5();
        builder.build()
    }

    pub fn new_tls(tls: TlsConfig) -> Box<EapServer> {
        let mut builder = EapServerBuilder::new();
        builder.set_tls_config(tls);
        builder.allow_tls();
        builder.build()
    }

    fn init(builder: EapServerBuilder) -> Box<Self> {
        SERVER_INIT.call_once(|| unsafe {
            wpa_debug_level = 0;

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
            let tls_config: Box<tls_config> = Box::new(unsafe { std::mem::zeroed() });
            let mut tls_params: Box<tls_connection_params> =
                Box::new(unsafe { std::mem::zeroed() });

            let tls_ctx;
            unsafe {
                tls_ctx = tls_init(&*tls_config);
                assert!(!tls_ctx.is_null());
            }

            let mut temp_files = vec![];

            tls_params.ca_cert = crate::util::create_tempfile(&tls.ca_cert, &mut temp_files);
            tls_params.client_cert =
                crate::util::create_tempfile(&tls.server_cert, &mut temp_files);
            tls_params.private_key = crate::util::create_tempfile(&tls.server_key, &mut temp_files);

            unsafe {
                assert_eq!(tls_global_set_params(tls_ctx, &*tls_params), 0);
                assert_eq!(tls_global_set_verify(tls_ctx, 0, 1), 0);
            }

            eap_config.ssl_ctx = tls_ctx as *mut c_void;

            Some(EapServerTlsState {
                tls_ctx,
                _tls_params: tls_params,
                _tls_config: tls_config,
                _cfg: tls,
                _temp_files: temp_files,
            })
        } else {
            None
        };

        let mut me = Box::new(Self {
            interface: std::ptr::null_mut(),
            callbacks,
            eap_config,
            state: std::ptr::null_mut(),
            _tls_state: tls_state,
            users: builder.passwords,
            method_priorities: builder.method_priorities,
            response_buffer: vec![],
            final_status: None,
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
    unsafe extern "C" fn server_get_eap_user(
        ctx: *mut c_void,
        identity: *const u8,
        identity_len: usize,
        _phase2: c_int,
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
                            (*user).methods[i].method = EapType_EAP_TYPE_MD5 as _;
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

    unsafe extern "C" fn get_eap_req_id_text(_ctx: *mut c_void, len: *mut usize) -> *const i8 {
        *len = 0;
        std::ptr::null()
    }
}

impl EapWrapper for Box<EapServer> {
    fn receive(&mut self, buffer: &[u8]) {
        unsafe {
            wpabuf_free((*self.interface).eapRespData);
            (*self.interface).eapRespData =
                wpabuf_alloc_copy(buffer.as_ptr() as *const c_void, buffer.len());
            (*self.interface).eapResp = true as _;
        }
    }

    fn step(&mut self) -> EapStepResult {
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
            self.final_status = Some(EapStepStatus::Error);
            EapStepStatus::Error
        } else if finished {
            self.final_status = Some(EapStepStatus::Finished);
            EapStepStatus::Finished
        } else if let Some(f) = self.final_status {
            f
        } else {
            EapStepStatus::Ok
        };

        let buffer_filled = unsafe { !(*self.interface).eapReqData.is_null() };
        let response = if (sent_message || finished || failed) && buffer_filled {
            let data = unsafe { (*self.interface).eapReqData };
            let data = unsafe { std::slice::from_raw_parts((*data).buf, (*data).used) }.to_vec();

            Some(data)
        } else {
            None
        };

        let _key_material = if has_key_material {
            unsafe {
                let key = (*self.interface).eapKeyData;
                let length = (*self.interface).eapKeyDataLen;
                let key = std::slice::from_raw_parts(key, length).to_vec();
                Some(key)
            }
        } else {
            None
        };

        EapStepResult {
            status,
            response: response.map(|buffer| {
                self.response_buffer = buffer;
                self.response_buffer.as_slice()
            }),
        }
    }
}

impl Drop for EapServer {
    fn drop(&mut self) {
        unsafe {
            eap_server_sm_deinit(self.state);
        }
    }
}
