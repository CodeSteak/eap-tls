use lazy_static::__Deref;
use std::{
    collections::HashMap,
    ffi::{c_int, c_void, CStr},
    sync::Once,
};

pub use crate::bindings_peer::*;
use crate::EapStatus;

static PEER_INIT: Once = Once::new();

pub struct EapPeerResult {
    pub status: EapStatus,
    pub response: Option<Vec<u8>>,
    pub key_material: Option<Vec<u8>>,
}

pub struct EapPeer {
    callbacks: Box<eapol_callbacks>,
    config: Box<eap_config>,
    peer_config: Box<eap_peer_config>,
    state: *mut eap_sm,

    wpabuf: *mut wpabuf,

    state_bool: HashMap<eapol_bool_var, bool>,
    state_int: HashMap<eapol_int_var, u32>,
    blobs: Vec<WpaBlobEntry>,
}

impl EapPeer {
    pub fn new() -> Box<Self> {
        PEER_INIT.call_once(|| {
            unsafe {
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
            get_eapReqData: Some(Self::get_eapReqData),
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

        let username = "user";
        let password = "password";

        unsafe {
            ((*peer_config).identity, (*peer_config).identity_len) =
                crate::util::malloc_str(username);
            ((*peer_config).password, (*peer_config).password_len) =
                crate::util::malloc_str(password);

            peer_config.ca_cert = crate::util::malloc_str("blob://ca").0 as *mut i8;
            peer_config.client_cert = crate::util::malloc_str("blob://client").0 as *mut i8;
            peer_config.private_key = crate::util::malloc_str("blob://private").0 as *mut i8;
        }

        let blobs = vec![
            WpaBlobEntry::new("ca", include_bytes!("dummy/ca.pem")),
            WpaBlobEntry::new("client", include_bytes!("dummy/client-cert.pem")),
            WpaBlobEntry::new("private", include_bytes!("dummy/client-key.pem")),
        ];

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
            blobs,
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

    pub fn step(&mut self) -> EapPeerResult {
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

        let key_material = if success && unsafe { eap_key_available(self.state) } != 0 {
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
            EapStatus::Finished
        } else if failure {
            EapStatus::Failed
        } else {
            EapStatus::Ok
        };

        EapPeerResult {
            status,
            response,
            key_material,
        }
    }

    pub fn receive(&mut self, input: &[u8]) {
        self.state_bool.insert(eapol_bool_var_EAPOL_eapReq, true);
        unsafe {
            wpabuf_free(self.wpabuf);
        }

        self.wpabuf = unsafe { wpabuf_alloc_copy(input.as_ptr() as *const c_void, input.len()) };
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

    unsafe extern "C" fn get_eapReqData(ctx: *mut c_void) -> *mut wpabuf {
        let eap = &mut *(ctx as *mut Self);
        eap.wpabuf
    }

    unsafe extern "C" fn set_config_blob(ctx: *mut c_void, blob: *mut wpa_config_blob) {
        unimplemented!()
    }

    unsafe extern "C" fn get_config_blob(
        ctx: *mut c_void,
        name: *const i8,
    ) -> *const wpa_config_blob {
        let key = CStr::from_ptr(name).to_str().unwrap();
        dbg!(&key);
        let eap = &mut *(ctx as *mut Self);

        for blob in &eap.blobs {
            if blob.name == key {
                return blob.blob.deref() as *const wpa_config_blob;
            }
        }

        std::ptr::null()
    }

    unsafe extern "C" fn notify_pending(ctx: *mut c_void) {
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

struct WpaBlobEntry {
    name: String,
    _data: Box<[u8]>,
    blob: Box<wpa_config_blob>,
}

impl WpaBlobEntry {
    pub fn new(name: &str, data: &[u8]) -> Self {
        let name = name.to_string();
        let data = data.to_vec().into_boxed_slice();
        let blob = Box::new(wpa_config_blob {
            name: name.as_str().as_ptr() as *const i8 as *mut i8,
            data: data.as_ptr() as *const u8 as *mut u8,
            len: data.len(),
            next: std::ptr::null_mut(),
        });

        Self {
            name,
            _data: data,
            blob,
        }
    }
}
