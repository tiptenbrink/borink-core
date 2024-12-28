use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::derive::{DerivedResponse, ResponseCache};
use borink_git::StoreAddress;
use borink_kv::{join_prefix_with_meta, read_meta, DatabaseRef, KvError, KvMetaValue, KvMetadata};

#[derive(Serialize, Deserialize)]
#[repr(transparent)]
struct DerivedResponseHeaders(pub Vec<(String, String)>);

const RESPONSE_PREFIX: [u8; 3] = [0x42, 0x44, 0x52];

fn write_response_meta(headers: DerivedResponseHeaders) -> Vec<u8> {
    let buf = rmp_serde::to_vec(&headers).unwrap();
    join_prefix_with_meta(&RESPONSE_PREFIX, &[], Some(&buf))
}

fn read_response_meta(meta: &[u8]) -> DerivedResponseHeaders {
    let KvMetadata { meta_bytes, .. } = read_meta(meta).unwrap();
    rmp_serde::decode::from_slice(&meta_bytes).unwrap()
}

impl<'a> ResponseCache for DatabaseRef<'a> {
    type Error = KvError;

    fn get<'b>(
        &'b self,
        derive_ctx: &str,
        address: &StoreAddress,
    ) -> Result<Option<Cow<'b, DerivedResponse>>, KvError> {
        // TODO: quite a few inefficient copies for the metadata right now
        Ok(self
            .get(Self::cache_key(derive_ctx, address).as_bytes())?
            .map(|KvMetaValue { value, metadata }| {
                Cow::Owned(DerivedResponse {
                    headers: read_response_meta(&metadata).0,
                    bytes: value,
                })
            }))
    }

    fn insert(
        &mut self,
        derive_ctx: &str,
        address: &StoreAddress,
        response: DerivedResponse,
    ) -> Result<(), KvError> {
        // TODO: quite a few inefficient copies for the metadata right now
        DatabaseRef::insert(
            self,
            Self::cache_key(derive_ctx, address).as_bytes(),
            &write_response_meta(DerivedResponseHeaders(response.headers)),
            &response.bytes,
        )
    }
}
