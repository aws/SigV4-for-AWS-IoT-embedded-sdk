// SigV4 Rust bindings
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

#![no_std]

#[allow(
    dead_code,
    non_upper_case_globals,
    non_camel_case_types,
    non_snake_case,
    clippy::enum_variant_names
)]
mod c {
    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

use core::fmt;
use core::mem::MaybeUninit;
use core::slice;

/// Error type wrapping SigV4 status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigV4Error {
    InvalidParameter = 1,
    InsufficientMemory = 2,
    ISOFormattingError = 3,
    MaxHeaderPairCountExceeded = 4,
    MaxQueryPairCountExceeded = 5,
    HashError = 6,
    InvalidHttpHeaders = 7,
}

impl fmt::Display for SigV4Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidParameter => write!(f, "invalid parameter"),
            Self::InsufficientMemory => write!(f, "insufficient memory"),
            Self::ISOFormattingError => write!(f, "ISO formatting error"),
            Self::MaxHeaderPairCountExceeded => {
                write!(f, "max header pair count exceeded")
            }
            Self::MaxQueryPairCountExceeded => {
                write!(f, "max query pair count exceeded")
            }
            Self::HashError => write!(f, "hash error"),
            Self::InvalidHttpHeaders => write!(f, "invalid HTTP headers"),
        }
    }
}

fn status_to_result(status: c::SigV4Status) -> Result<(), SigV4Error> {
    match status {
        c::SigV4Status::SigV4Success => Ok(()),
        c::SigV4Status::SigV4InvalidParameter => {
            Err(SigV4Error::InvalidParameter)
        }
        c::SigV4Status::SigV4InsufficientMemory => {
            Err(SigV4Error::InsufficientMemory)
        }
        c::SigV4Status::SigV4ISOFormattingError => {
            Err(SigV4Error::ISOFormattingError)
        }
        c::SigV4Status::SigV4MaxHeaderPairCountExceeded => {
            Err(SigV4Error::MaxHeaderPairCountExceeded)
        }
        c::SigV4Status::SigV4MaxQueryPairCountExceeded => {
            Err(SigV4Error::MaxQueryPairCountExceeded)
        }
        c::SigV4Status::SigV4HashError => Err(SigV4Error::HashError),
        c::SigV4Status::SigV4InvalidHttpHeaders => {
            Err(SigV4Error::InvalidHttpHeaders)
        }
    }
}

/// User-provided SHA-256 hash implementation.
pub trait Sha256Hasher: Default {
    fn init(&mut self) -> bool;
    fn update(&mut self, input: &[u8]) -> bool;
    fn finalize(&mut self, output: &mut [u8]) -> bool;
    fn block_len(&self) -> usize;
    fn digest_len(&self) -> usize;
}

/// AWS credentials.
pub struct Credentials<'a> {
    pub access_key_id: &'a str,
    pub secret_access_key: &'a str,
}

/// HTTP request parameters for signing.
pub struct HttpRequest<'a> {
    pub method: &'a str,
    pub path: Option<&'a str>,
    pub query: Option<&'a str>,
    pub headers: &'a str,
    pub payload: Option<&'a [u8]>,
    pub flags: u32,
}

/// Parameters for generating the authorization header.
pub struct SigningParams<'a> {
    pub credentials: &'a Credentials<'a>,
    pub date_iso8601: &'a str,
    pub region: &'a str,
    pub service: &'a str,
    pub http: &'a HttpRequest<'a>,
}

// C callback trampolines — generic over H, defined inside generate_http_authorization.

/// Generate the SigV4 HTTP Authorization header value.
///
/// Returns `(auth_header_len, signature_len)` on success.
/// The authorization header is written into `auth_buf`.
pub fn generate_http_authorization<H: Sha256Hasher>(
    params: &SigningParams<'_>,
    auth_buf: &mut [u8],
) -> Result<(usize, usize), SigV4Error> {
    unsafe extern "C" fn hash_init_cb<H: Sha256Hasher>(
        ctx: *mut core::ffi::c_void,
    ) -> i32 {
        unsafe {
            let h = &mut *(ctx.cast::<H>());
            if h.init() { 0 } else { -1 }
        }
    }

    unsafe extern "C" fn hash_update_cb<H: Sha256Hasher>(
        ctx: *mut core::ffi::c_void,
        input: *const u8,
        len: usize,
    ) -> i32 {
        unsafe {
            let h = &mut *(ctx.cast::<H>());
            let slice = if input.is_null() || len == 0 {
                &[]
            } else {
                core::slice::from_raw_parts(input, len)
            };
            if h.update(slice) { 0 } else { -1 }
        }
    }

    unsafe extern "C" fn hash_final_cb<H: Sha256Hasher>(
        ctx: *mut core::ffi::c_void,
        output: *mut u8,
        len: usize,
    ) -> i32 {
        unsafe {
            let h = &mut *(ctx.cast::<H>());
            if output.is_null() || len == 0 {
                return -1;
            }
            let slice = core::slice::from_raw_parts_mut(output, len);
            if h.finalize(slice) { 0 } else { -1 }
        }
    }

    // Validate date is exactly 16 chars as required by the C library.
    if params.date_iso8601.len() != 16 {
        return Err(SigV4Error::InvalidParameter);
    }

    let mut hasher = H::default();

    let mut crypto_iface = c::SigV4CryptoInterface {
        hashInit: Some(hash_init_cb::<H>),
        hashUpdate: Some(hash_update_cb::<H>),
        hashFinal: Some(hash_final_cb::<H>),
        pHashContext: core::ptr::from_mut(&mut hasher).cast(),
        hashBlockLen: hasher.block_len(),
        hashDigestLen: hasher.digest_len(),
    };

    let mut creds = c::SigV4Credentials {
        pAccessKeyId: params.credentials.access_key_id.as_ptr().cast(),
        accessKeyIdLen: params.credentials.access_key_id.len(),
        pSecretAccessKey: params.credentials.secret_access_key.as_ptr().cast(),
        secretAccessKeyLen: params.credentials.secret_access_key.len(),
    };

    let mut http_params = c::SigV4HttpParameters {
        pHttpMethod: params.http.method.as_ptr().cast(),
        httpMethodLen: params.http.method.len(),
        flags: params.http.flags,
        pPath: params
            .http
            .path
            .map_or(core::ptr::null(), |p| p.as_ptr().cast()),
        pathLen: params.http.path.map_or(0, |p| p.len()),
        pQuery: params
            .http
            .query
            .map_or(core::ptr::null(), |q| q.as_ptr().cast()),
        queryLen: params.http.query.map_or(0, |q| q.len()),
        pHeaders: params.http.headers.as_ptr().cast(),
        headersLen: params.http.headers.len(),
        pPayload: params
            .http
            .payload
            .map_or(core::ptr::null(), |p| p.as_ptr().cast()),
        payloadLen: params.http.payload.map_or(0, |p| p.len()),
    };

    let sigv4_params = c::SigV4Parameters {
        pCredentials: &mut creds,
        pDateIso8601: params.date_iso8601.as_ptr().cast(),
        pAlgorithm: core::ptr::null(),
        algorithmLen: 0,
        pRegion: params.region.as_ptr().cast(),
        regionLen: params.region.len(),
        pService: params.service.as_ptr().cast(),
        serviceLen: params.service.len(),
        pCryptoInterface: &mut crypto_iface,
        pHttpParameters: &mut http_params,
    };

    let mut auth_buf_len = auth_buf.len();
    let mut signature_ptr: *mut core::ffi::c_char = core::ptr::null_mut();
    let mut signature_len: usize = 0;

    // SAFETY: All pointers in sigv4_params reference stack-local variables or
    // borrowed data that outlives this call. The C function is synchronous.
    let status = unsafe {
        c::SigV4_GenerateHTTPAuthorization(
            &sigv4_params,
            auth_buf.as_mut_ptr().cast(),
            &mut auth_buf_len,
            &mut signature_ptr,
            &mut signature_len,
        )
    };

    status_to_result(status)?;
    Ok((auth_buf_len, signature_len))
}

/// Convert an AWS IoT date header to ISO 8601 format.
///
/// Accepts RFC 3339 ("2018-01-18T09:18:06Z", 20 chars) or
/// RFC 5322 ("Thu, 18 Jan 2018 09:18:06 GMT", 29 chars).
/// Writes the 16-character ISO 8601 string ("20180118T091806Z") into `output`.
pub fn date_to_iso8601<'a>(
    date: &str,
    output: &'a mut [MaybeUninit<u8>; 16],
) -> Result<&'a str, SigV4Error> {
    if date.len() != 20 && date.len() != 29 {
        return Err(SigV4Error::InvalidParameter);
    }

    let status = unsafe {
        c::SigV4_AwsIotDateToIso8601(
            date.as_ptr().cast(),
            date.len(),
            output.as_mut_ptr().cast(),
            output.len(),
        )
    };
    status_to_result(status)?;
    Ok(unsafe {
        core::str::from_utf8_unchecked(slice::from_raw_parts(
            output.as_ptr().cast(),
            16,
        ))
    })
}

/// URI-encode a string per RFC 3986.
///
/// Writes the encoded URI into `buf` and returns the used slice as a `&str`.
/// The buffer must be large enough for the encoded output (worst case: 3x input length).
pub fn encode_uri<'a>(
    uri: &str,
    buf: &'a mut [MaybeUninit<u8>],
    encode_slash: bool,
    double_encode_equals: bool,
) -> Result<&'a str, SigV4Error> {
    let mut buf_len = buf.len();

    let status = unsafe {
        c::SigV4_EncodeURI(
            uri.as_ptr().cast(),
            uri.len(),
            buf.as_mut_ptr().cast(),
            &mut buf_len,
            encode_slash,
            double_encode_equals,
        )
    };

    status_to_result(status)?;
    Ok(unsafe {
        core::str::from_utf8_unchecked(slice::from_raw_parts(
            buf.as_ptr().cast(),
            buf_len,
        ))
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[derive(Default)]
    struct StubSha256;

    impl Sha256Hasher for StubSha256 {
        fn init(&mut self) -> bool {
            true
        }
        fn update(&mut self, _input: &[u8]) -> bool {
            true
        }
        fn finalize(&mut self, output: &mut [u8]) -> bool {
            for (i, b) in output.iter_mut().enumerate() {
                *b = (i as u8).wrapping_add(1);
            }
            true
        }
        fn block_len(&self) -> usize {
            64
        }
        fn digest_len(&self) -> usize {
            32
        }
    }

    #[test]
    fn date_to_iso8601_rfc3339() {
        let mut buf = [MaybeUninit::uninit(); 16];
        let result = date_to_iso8601("2018-01-18T09:18:06Z", &mut buf).unwrap();
        assert_eq!(result, "20180118T091806Z");
    }

    #[test]
    fn date_to_iso8601_rfc5322() {
        let mut buf = [MaybeUninit::uninit(); 16];
        let result =
            date_to_iso8601("Thu, 18 Jan 2018 09:18:06 GMT", &mut buf).unwrap();
        assert_eq!(result, "20180118T091806Z");
    }

    #[test]
    fn date_to_iso8601_invalid_length() {
        let mut buf = [MaybeUninit::uninit(); 16];
        let result = date_to_iso8601("bad", &mut buf);
        assert_eq!(result, Err(SigV4Error::InvalidParameter));
    }

    #[test]
    fn encode_uri_no_encoding_needed() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result = encode_uri("simple", &mut buf, false, false).unwrap();
        assert_eq!(result, "simple");
    }

    #[test]
    fn encode_uri_encodes_spaces() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result = encode_uri("hello world", &mut buf, false, false).unwrap();
        assert_eq!(result, "hello%20world");
    }

    #[test]
    fn encode_uri_preserves_slashes() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result =
            encode_uri("/path/to/resource", &mut buf, false, false).unwrap();
        assert_eq!(result, "/path/to/resource");
    }

    #[test]
    fn encode_uri_encodes_slashes() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result =
            encode_uri("/path/to/resource", &mut buf, true, false).unwrap();
        assert_eq!(result, "%2Fpath%2Fto%2Fresource");
    }

    #[test]
    fn encode_uri_double_encodes_equals() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result = encode_uri("key=value", &mut buf, false, true).unwrap();
        assert_eq!(result, "key%253Dvalue");
    }

    #[test]
    fn encode_uri_empty_string() {
        let mut buf = [MaybeUninit::uninit(); 64];
        let result = encode_uri("", &mut buf, false, false).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn generate_auth_header_success() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "GET",
            path: Some("/"),
            query: None,
            headers: "host:example.amazonaws.com\r\n",
            payload: Some(b""),
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "20230830T123600Z",
            region: "us-east-1",
            service: "service",

            http: &request,
        };

        let mut auth_buf = [0u8; 2048];
        let (auth_len, sig_len) =
            generate_http_authorization::<StubSha256>(&params, &mut auth_buf)
                .unwrap();

        let auth_header = core::str::from_utf8(&auth_buf[..auth_len]).unwrap();
        assert!(
            auth_header.starts_with(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/"
            )
        );
        assert!(auth_header.contains("SignedHeaders=host"));
        assert!(auth_header.contains("Signature="));
        assert!(sig_len > 0);
    }

    #[test]
    fn generate_auth_header_with_query() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "GET",
            path: Some("/"),
            query: Some("Action=ListUsers&Version=2010-05-08"),
            headers: "host:iam.amazonaws.com\r\n",
            payload: Some(b""),
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "20230830T123600Z",
            region: "us-east-1",
            service: "iam",

            http: &request,
        };

        let mut auth_buf = [0u8; 2048];
        let result =
            generate_http_authorization::<StubSha256>(&params, &mut auth_buf);
        assert!(result.is_ok());
    }

    #[test]
    fn generate_auth_header_post_with_payload() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "POST",
            path: Some("/"),
            query: None,
            headers: "host:example.amazonaws.com\r\ncontent-type:application/json\r\n",
            payload: Some(b"{\"key\":\"value\"}"),
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "20230830T123600Z",
            region: "us-west-2",
            service: "execute-api",

            http: &request,
        };

        let mut auth_buf = [0u8; 2048];
        let (auth_len, _) =
            generate_http_authorization::<StubSha256>(&params, &mut auth_buf)
                .unwrap();
        let auth_header = core::str::from_utf8(&auth_buf[..auth_len]).unwrap();
        assert!(auth_header.contains("us-west-2"));
        assert!(auth_header.contains("execute-api"));
    }

    #[test]
    fn generate_auth_header_invalid_date_length() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "GET",
            path: Some("/"),
            query: None,
            headers: "host:example.amazonaws.com\r\n",
            payload: None,
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "bad-date",
            region: "us-east-1",
            service: "s3",

            http: &request,
        };

        let mut auth_buf = [0u8; 2048];
        let result =
            generate_http_authorization::<StubSha256>(&params, &mut auth_buf);
        assert_eq!(result, Err(SigV4Error::InvalidParameter));
    }

    #[test]
    fn generate_auth_header_buffer_too_small() {
        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "GET",
            path: Some("/"),
            query: None,
            headers: "host:example.amazonaws.com\r\n",
            payload: Some(b""),
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "20230830T123600Z",
            region: "us-east-1",
            service: "s3",

            http: &request,
        };

        let mut auth_buf = [0u8; 10];
        let result =
            generate_http_authorization::<StubSha256>(&params, &mut auth_buf);
        assert_eq!(result, Err(SigV4Error::InsufficientMemory));
    }

    #[test]
    fn error_display() {
        assert_eq!(
            format!("{}", SigV4Error::InvalidParameter),
            "invalid parameter"
        );
        assert_eq!(
            format!("{}", SigV4Error::InsufficientMemory),
            "insufficient memory"
        );
        assert_eq!(format!("{}", SigV4Error::HashError), "hash error");
    }

    #[test]
    fn hash_interface_failing_impl() {
        #[derive(Default)]
        struct FailingHash;
        impl Sha256Hasher for FailingHash {
            fn init(&mut self) -> bool {
                false
            }
            fn update(&mut self, _: &[u8]) -> bool {
                false
            }
            fn finalize(&mut self, _: &mut [u8]) -> bool {
                false
            }
            fn block_len(&self) -> usize {
                64
            }
            fn digest_len(&self) -> usize {
                32
            }
        }

        let credentials = Credentials {
            access_key_id: "AKIAIOSFODNN7EXAMPLE",
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        };
        let request = HttpRequest {
            method: "GET",
            path: Some("/"),
            query: None,
            headers: "host:example.amazonaws.com\r\n",
            payload: Some(b""),
            flags: 0,
        };

        let params = SigningParams {
            credentials: &credentials,
            date_iso8601: "20230830T123600Z",
            region: "us-east-1",
            service: "s3",

            http: &request,
        };

        let mut auth_buf = [0u8; 2048];
        let result =
            generate_http_authorization::<FailingHash>(&params, &mut auth_buf);
        assert_eq!(result, Err(SigV4Error::HashError));
    }
}
