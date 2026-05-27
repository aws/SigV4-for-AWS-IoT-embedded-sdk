// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//! Example: URI-encode a path per RFC 3986 for SigV4 canonical requests.

use sigv4::encode_uri;
use std::mem::MaybeUninit;

fn main() {
    let uri = "/documents and settings/my file.txt";
    let mut buf = [MaybeUninit::uninit(); 256];

    // Encode slashes (for query parameters)
    let encoded =
        encode_uri(uri, &mut buf, true, false).expect("Failed to encode URI");
    println!("Original:             {uri}");
    println!("Encoded (with slash): {encoded}");

    // Preserve slashes (for paths)
    let encoded =
        encode_uri(uri, &mut buf, false, false).expect("Failed to encode URI");
    println!("Encoded (no slash):   {encoded}");
}
