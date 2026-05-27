// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//! Example: Generate a SigV4 HTTP Authorization header using `ring` for SHA-256.

use ring::digest::{Context, SHA256};
use sigv4::{
    Credentials, HttpRequest, Sha256Hasher, SigningParams,
    generate_http_authorization,
};

#[derive(Default)]
struct RingSha256(Option<Context>);

impl Sha256Hasher for RingSha256 {
    fn init(&mut self) -> bool {
        self.0 = Some(Context::new(&SHA256));
        true
    }
    fn update(&mut self, input: &[u8]) -> bool {
        match self.0.as_mut() {
            Some(ctx) => {
                ctx.update(input);
                true
            }
            None => false,
        }
    }
    fn finalize(&mut self, output: &mut [u8]) -> bool {
        match self.0.take() {
            Some(ctx) => {
                let digest = ctx.finish();
                if output.len() < 32 {
                    return false;
                }
                output[..32].copy_from_slice(digest.as_ref());
                true
            }
            None => false,
        }
    }
    fn block_len(&self) -> usize {
        64
    }
    fn digest_len(&self) -> usize {
        32
    }
}

fn main() {
    let credentials = Credentials {
        access_key_id: "AKIAIOSFODNN7EXAMPLE",
        secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    };

    let request = HttpRequest {
        method: "GET",
        path: Some("/"),
        query: None,
        headers: "host:example.amazonaws.com\r\nx-amz-date:20150830T123600Z\r\n",
        payload: Some(b""),
        flags: 0,
    };

    let date = "20150830T123600Z";

    let params = SigningParams {
        credentials: &credentials,
        date_iso8601: date,
        region: "us-east-1",
        service: "service",
        http: &request,
    };

    let mut auth_buf = [0u8; 2048];

    match generate_http_authorization::<RingSha256>(&params, &mut auth_buf) {
        Ok((auth_len, sig_len)) => {
            let auth_header =
                std::str::from_utf8(&auth_buf[..auth_len]).unwrap();
            println!("Authorization: {auth_header}");
            println!("Signature length: {sig_len} bytes");
        }
        Err(e) => {
            eprintln!("Error: {e}");
        }
    }
}
