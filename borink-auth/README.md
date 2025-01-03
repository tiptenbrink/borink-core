31744 bytes of arbitrary data per user, any other data must come from some type of "deep storage"
1024 bytes of data for the actual authentication

We use some assumptions:
- On AWS, for $10-20k a year, you can get 100GB worth of memory and 32 vCPUs. Assuming 64 kB of memory per user, this could serve 1 billion accounts. 

Per month, this is 83 CPU-ms per user. We assume a heavy use scenario in which users make on average 10 requests per day, or 300 requests per month. This is 83/300 CPU-ms per request.

### user login with OPAQUE

```
opaque start login server:

(opaque_response, start_state) = login_server {
    server_keys,
    user_password_file,
    user_start_request,
    user_id
}

start_state is encrypted with a symmetric key derived from the current time and sent together with the response to the user (who performs further OPAQUE processing and derives a shared secret)
we do not store the start_state because we want to avoid writes as much as possible and be as stateless server-side as possible for everything that influences the actual logic and authentication

opaque finish login server:

opaque_shared_secret = login_server_finish {
    user_finish_request,
    start_state
}

if time has advanced too much (meaning a different symmetric key will be used), it will no longer be valid
we do not wish to store the shared secret, again because we want to avoid writes
we ask the user to immediately send the shared secret along with their request
if the provided shared secret matches what we compute, we generate a session token
however, a single login start should only be able to generate one session (as only a single authentication was performed), but currently we are completely stateless, meaning we cannot verify whether what the user sends us has been already used
therefore, we need to create a unique token (a u64) at login start time and we only return a session if that token has not been used before
note that the shared secret is larger than a u64, but a u64 is more than unique enough. furthermore we can control the u64s structure, allowing more efficient storage than the uniformly random shared secret
this gives, also with the requirement that a login finish must match the password file of the login start it is associated with (already ensured by opaque, but provides another early return):

FROM USER: user_login_request, user_id

(opaque_response, start_state) = login_server {
    server_keys,
    user_password_file,
    user_login_request,
    user_id
}

one_time_token = generate_token {}

ephemeral = encrypt(time_based_key) {
    one_time_token,
    start_state,
    hash(user_password_file)
}

TO USER: opaque_response, ephemeral

FROM USER: opaque_shared_secret, user_finish_request, ephemeral

check one_time_token unused!

opaque_shared_secret = login_server_finish {
    user_finish_request,
    start_state
}

check opaque_shared_secret match!
check hash(user_password_file) matches hash(current password file)!

TO USER: signed session token
```

All this requires only two internal state mutations, one to generate the u64 and one time to record it is used. 

The question is now to make this as scalable as possible and minimize memory use.

### Cache and disk

We primarily use a concurrent hash map for our storage. The only information that must be persisted to disk is the user data. Users are stored in blocks of 16 users.