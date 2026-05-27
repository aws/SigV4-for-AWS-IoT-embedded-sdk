// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT

//! Example: Convert an RFC 3339 date to ISO 8601 format for SigV4 signing.

use sigv4::date_to_iso8601;
use std::mem::MaybeUninit;

fn main() {
    let mut buf = [MaybeUninit::uninit(); 16];

    let rfc3339_date = "2018-01-18T09:18:06Z";
    let iso8601 = date_to_iso8601(rfc3339_date, &mut buf)
        .expect("Failed to convert date");
    println!("RFC 3339:  {rfc3339_date}");
    println!("ISO 8601:  {iso8601}");

    let rfc5322_date = "Thu, 18 Jan 2018 09:18:06 GMT";
    let iso8601 = date_to_iso8601(rfc5322_date, &mut buf)
        .expect("Failed to convert date");
    println!("RFC 5322:  {rfc5322_date}");
    println!("ISO 8601:  {iso8601}");
}
