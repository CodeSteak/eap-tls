use common::{EapStepResult, EapStepStatus, EapWrapper};
use std::{collections::HashMap, ffi::c_void, sync::Once};
use tempfile::NamedTempFile;

pub use crate::bindings_peer::*;
use crate::TlsConfig;

static PEER_INIT: Once = Once::new();

pub struct EapPeer {
    callbacks: Box<eapol_callbacks>,
    config: Box<eap_config>,
    peer_config: Box<eap_peer_config>,
    state: *mut eap_sm,

    wpabuf: *mut wpabuf,

    state_bool: HashMap<eapol_bool_var, bool>,
    state_int: HashMap<eapol_int_var, u32>,
    _temp_files: Vec<NamedTempFile>,

    response_buffer: Vec<u8>,
    final_status: Option<EapStepStatus>,
}

pub struct EapPeerBuilder {
    identity: String,
    password: Option<String>,
    tls_config: Option<TlsConfig>,
}

impl EapPeerBuilder {
    pub fn new(identity: &str) -> Self {
        Self {
            identity: identity.to_string(),
            password: None,
            tls_config: None,
        }
    }

    pub fn set_password(&mut self, password: &str) -> &mut Self {
        self.password = Some(password.to_string());
        self
    }

    pub fn set_tls_config(&mut self, tls_config: TlsConfig) -> &mut Self {
        self.tls_config = Some(tls_config);
        self
    }

    pub fn build(&mut self) -> Box<EapPeer> {
        EapPeer::new(self)
    }
}

impl EapPeer {
    pub fn builder(identity: &str) -> EapPeerBuilder {
        EapPeerBuilder::new(identity)
    }

    pub fn new_password(identity: &str, password: &str) -> Box<EapPeer> {
        let mut builder = EapPeerBuilder::new(identity);
        builder.set_password(password);
        builder.build()
    }

    pub fn new_tls(identity: &str, tls: TlsConfig) -> Box<EapPeer> {
        let mut builder = EapPeerBuilder::new(identity);
        builder.set_tls_config(tls);
        builder.build()
    }

    fn new(builder: &EapPeerBuilder) -> Box<Self> {
        PEER_INIT.call_once(|| {
            unsafe {
                wpa_debug_level = 0;

                //assert!(eap_peer_mschapv2_register() == 0);
                assert!(eap_peer_md5_register() == 0);
                assert!(eap_peer_tls_register() == 0);
            }
        });

        // ! BOX, should not be moved
        let callbacks: Box<eapol_callbacks> = Box::new(eapol_callbacks {
            get_config: Some(Self::get_config),
            get_bool: Some(Self::get_bool),
            set_bool: Some(Self::set_bool),
            get_int: Some(Self::get_int),
            set_int: Some(Self::set_int),
            get_eapReqData: Some(Self::get_eap_req_data),
            set_config_blob: Some(Self::set_config_blob),
            get_config_blob: Some(Self::get_config_blob),
            notify_pending: Some(Self::notify_pending),
            eap_param_needed: None,
            notify_cert: None,
            notify_status: None,
            notify_eap_error: None,
            set_anon_id: None,
        });

        let mut peer_config: Box<eap_peer_config> = Box::new(unsafe { std::mem::zeroed() });
        peer_config.fragment_size = 1400; // <- needs to be set, otherwise it get stuck sending 0 sized fragments.
        let config: Box<eap_config> = Box::new(unsafe { std::mem::zeroed() });

        // Identity
        unsafe {
            (peer_config.identity, peer_config.identity_len) =
                crate::util::malloc_str(&builder.identity);
        }

        // Password
        if let Some(password) = &builder.password {
            unsafe {
                (peer_config.password, peer_config.password_len) =
                    crate::util::malloc_str(password);
            }
        }

        // TLS / Ca
        let temp_files = if let Some(tls) = &builder.tls_config {
            let mut registry = vec![];

            peer_config.ca_cert = crate::util::create_tempfile(&tls.ca_cert, &mut registry);
            peer_config.client_cert = crate::util::create_tempfile(&tls.server_cert, &mut registry);
            peer_config.private_key = crate::util::create_tempfile(&tls.server_key, &mut registry);

            registry
        } else {
            vec![]
        };

        let wpabuf: *mut wpabuf = unsafe { wpabuf_alloc(0) };
        assert!(!wpabuf.is_null());

        let mut me = Box::new(Self {
            callbacks,
            config,
            peer_config,
            state: std::ptr::null_mut(),
            wpabuf,
            state_bool: HashMap::new(),
            state_int: HashMap::new(),
            _temp_files: temp_files,
            response_buffer: vec![],
            final_status: None,
        });

        me.state = unsafe {
            let me_ptr = me.as_mut() as *mut Self as *mut c_void;
            let callback_ptr = (&*me.callbacks) as *const eapol_callbacks;

            eap_peer_sm_init(me_ptr, callback_ptr, me_ptr, me.config.as_mut())
        };
        assert!(!me.state.is_null());

        me.state_bool.insert(eapol_bool_var_EAPOL_portEnabled, true);

        me
    }

    unsafe extern "C" fn get_config(ctx: *mut c_void) -> *mut eap_peer_config {
        let eap = &mut *(ctx as *mut Self);
        &mut *eap.peer_config
    }

    unsafe extern "C" fn get_bool(ctx: *mut c_void, variable: eapol_bool_var) -> u32 {
        let eap = &mut *(ctx as *mut Self);
        eap.state_bool
            .get(&variable)
            .copied()
            .unwrap_or(false)
            .into()
    }

    unsafe extern "C" fn set_bool(ctx: *mut c_void, variable: eapol_bool_var, value: u32) {
        let eap = &mut *(ctx as *mut Self);
        eap.state_bool.insert(variable, value != 0);
    }

    unsafe extern "C" fn get_int(ctx: *mut c_void, variable: eapol_int_var) -> u32 {
        let eap = &mut *(ctx as *mut Self);
        eap.state_int.get(&variable).copied().unwrap_or(0)
    }

    unsafe extern "C" fn set_int(ctx: *mut c_void, variable: eapol_int_var, value: u32) {
        let eap = &mut *(ctx as *mut Self);
        eap.state_int.insert(variable, value);
    }

    unsafe extern "C" fn get_eap_req_data(ctx: *mut c_void) -> *mut wpabuf {
        let eap = &mut *(ctx as *mut Self);
        eap.wpabuf
    }

    unsafe extern "C" fn set_config_blob(_ctx: *mut c_void, _blob: *mut wpa_config_blob) {
        unimplemented!()
    }

    unsafe extern "C" fn get_config_blob(
        _ctx: *mut c_void,
        _name: *const i8,
    ) -> *const wpa_config_blob {
        std::ptr::null()
    }

    unsafe extern "C" fn notify_pending(_ctx: *mut c_void) {
        // NOP
    }
}

impl EapWrapper for Box<EapPeer> {
    fn receive(&mut self, msg: &[u8]) {
        self.state_bool.insert(eapol_bool_var_EAPOL_eapReq, true);
        unsafe {
            wpabuf_free(self.wpabuf);
        }

        self.wpabuf = unsafe { wpabuf_alloc_copy(msg.as_ptr() as *const c_void, msg.len()) };
    }

    fn step(&mut self) -> EapStepResult<'_> {
        let _state_changed = unsafe { eap_peer_sm_step(self.state) } == 1;

        let should_sent_response = *self
            .state_bool
            .get(&eapol_bool_var_EAPOL_eapResp)
            .unwrap_or(&false);
        let success = *self
            .state_bool
            .get(&eapol_bool_var_EAPOL_eapSuccess)
            .unwrap_or(&false);
        let failure = *self
            .state_bool
            .get(&eapol_bool_var_EAPOL_eapFail)
            .unwrap_or(&false);

        let response = if should_sent_response {
            let data = unsafe { eap_get_eapRespData(self.state) };
            if data.is_null() {
                None
            } else {
                let ret =
                    Some(unsafe { std::slice::from_raw_parts((*data).buf, (*data).used) }.to_vec());
                unsafe { wpabuf_free(data) };
                ret
            }
        } else {
            None
        };

        let _key_material = if success && unsafe { eap_key_available(self.state) } != 0 {
            unsafe {
                let mut length: usize = 0;
                let key_data = eap_get_eapKeyData(self.state, (&mut length) as *mut usize);

                Some(std::slice::from_raw_parts(key_data, length).to_vec())
            }
        } else {
            None
        };

        assert!(!(failure && success));

        let status = if success {
            self.final_status = Some(EapStepStatus::Finished);
            EapStepStatus::Finished
        } else if failure {
            self.final_status = Some(EapStepStatus::Error);
            EapStepStatus::Error
        } else if let Some(f) = self.final_status {
            f
        } else {
            EapStepStatus::Ok
        };

        EapStepResult {
            response: response.map(|buffer| {
                self.response_buffer = buffer;
                &self.response_buffer[..]
            }),
            status,
        }
    }
}

impl Drop for EapPeer {
    fn drop(&mut self) {
        unsafe {
            eap_peer_sm_deinit(self.state);
            wpabuf_free(self.wpabuf);
        };
    }
}
