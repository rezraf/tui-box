# Telemetry

## Current v0.1 behavior

Telemetry defaults to disabled. The CLI can persist consent:

```sh
tuibox telemetry status
tuibox telemetry enable
tuibox telemetry disable
```

In v0.1, application composition does not configure a telemetry endpoint or instantiate the telemetry sender. Enabling consent therefore causes no network request and sends no event.

The telemetry package exists as a closed schema and hardened sender for future integration. An empty endpoint is also an explicit no-op, even when `Enabled` is true.

## Consent storage

Consent is stored in `state.json` as:

```json
{
  "settings": {
    "telemetry_enabled": false
  }
}
```

A new state file and a legacy state file without `settings` both default to `false`. Consent changes do not fetch subscriptions, contact the daemon, or perform an update.

## Closed event schema

If a future build wires an endpoint, every event contains exactly these fields:

| Field | Allowed content |
| --- | --- |
| `app_version` | Validated release/build version, at most 64 bytes |
| `os` | Go runtime operating system |
| `arch` | Go runtime architecture |
| `event` | One allowlisted coarse event name |
| `protocol` | Empty or one supported protocol family |
| `mode` | Empty, `tun`, or `proxy` |
| `route` | Empty, `global`, `rule`, or `direct` |
| `success` | Boolean outcome |
| `duration_bucket` | Coarse duration bucket |

Allowlisted event names:

- `app_start`
- `subscription`
- `server`
- `connect`
- `disconnect`
- `status`
- `telemetry`
- `doctor`
- `update`
- `version`

Duration buckets:

- `under_100ms`
- `100ms_to_1s`
- `1s_to_10s`
- `10s_or_more`

The schema has no extension map, arbitrary metadata, free-form message, installation ID, user ID, subscription ID, endpoint ID, provider URL, host, port, credential, IP address, file path, command arguments, logs, RPC payload, or raw duration.

## Sender safeguards

The dormant sender implementation:

- returns without work when disabled, nil, or configured with an empty endpoint;
- accepts only HTTPS endpoints;
- rejects URL userinfo and fragments;
- removes any inherited HTTP cookie jar;
- rejects redirects;
- uses a maximum 5-second client timeout;
- limits request and response bodies to 4 KiB;
- sends JSON with `Content-Type: application/json` and `User-Agent: TuiBox-Telemetry/0.1`;
- accepts only successful 2xx responses;
- validates every enum and rejects negative durations before sending.

No hosted endpoint is defined by this repository.

## Future integration requirements

Wiring telemetry requires all of the following:

1. Keep default consent disabled.
2. Read consent before constructing or invoking a sender.
3. Configure an explicit reviewed HTTPS endpoint; no endpoint must remain a no-op.
4. Send only the closed documented schema.
5. Add offline tests proving disabled/no-endpoint behavior and field exclusion.
6. Update this document and the README before release.
7. Treat any new field, identifier, endpoint, retry queue, persistence, or third-party processor as a security/privacy review item.

A consent toggle alone is not authorization to expand the schema.
