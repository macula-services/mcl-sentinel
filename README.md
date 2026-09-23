# mcl-sentinel

**Correlates warden sightings into cross-border campaigns and publishes them, enriched, to the threat commons**

## Status: scaffold

The service boots, joins the mesh and answers `/health` on 8470. It
does nothing else yet.

It announces no capability and asks the realm for no authority, because it can do
nothing yet. Both lists grow when the thing they name exists. Advertising a
capability before it exists puts a lie on the mesh where another service can find
it and call it.

## Running it

    rebar3 compile
    rebar3 eunit
    rebar3 lint

    scripts/health.sh                      # against a running node

Building the image needs a Rust toolchain, because macula ships a QUIC NIF and
the alpine build compiles it from source rather than fetching one linked against
a different libc.

    podman build -t mcl-sentinel -f Containerfile .

## Configuration

| Variable | Default | Meaning |
|----------|---------|---------|
| `MCL_REALM` | required | 64-hex realm tag, the `sha256` of the realm's name. No default: a service that guesses its realm announces itself where nobody can attribute it. |
| `MCL_REALM_KEY` | required | The realm's public signing key, hex encoded: the **trust anchor**, not an identifier. Every org-namespaced advertisement is verified against it, so without it nothing resolves, the boot claim never reaches the realm, and the service stays green while unreachable. Public material, not a secret. |
| `MACULA_STATION_SEEDS` | required | Station hosts to dial, `host[:port]`, comma-separated. No default: naming a realm costs nothing, dialling a production station from every dev clone does. |
| `MACULA_STATION_NODE_IDS` | required | The matching 64-hex station node ids, comma-separated, index-paired with the seeds. The 11.x dial is pinned (D5): mcl_om refuses to boot a pool with an unpinned seed. |
| `MCL_HEALTH_PORT` | `8470` | Health endpoint. Host networking makes a collision a silent bind failure, so check the host before changing.  |
| `MCL_NODE_NAME` | `mcl_sentinel` | Erlang node name. |
| `MCL_NODE_HOST` | `127.0.0.1` | Erlang node host. |
| `MCL_COOKIE` | `mcl_sentinel` | Erlang cookie. |

`deploy/docker-compose.yml` runs it, and carries what the service knows about
itself. If you deploy through something else, let that carry **placement**: which
host, which station, which realm, which secret store. Keeping the two apart is
what stops a config table in a README and the real environment drifting.

## Deployment

CI builds on every push to `main` and pushes
`ghcr.io/macula-services/mcl-sentinel:latest` plus the semver tag. Pull `:latest` under
watchtower and a merge is a deploy, while a rollback is pinning to a semver tag.

Two things CI cannot do for you, both of which have bitten:

1. The registry package may be created **private**, and the pull then fails on
   the host with a bare `unauthorized` that names nothing. Check it after the
   first build. On ghcr the `org.opencontainers.image.source` label in the
   Containerfile is what links the package to the repository.
2. The host needs `MCL_REALM` and the pinned station pair supplied from
   somewhere they are not committed.

## The service contract

Six callbacks in `mcl_sentinel_service`, all required, all resolved **by name** by
`mcl_om` at startup on a live node. The `-behaviour(mcl_om_service)`
attribute turns a missing one into a compile error rather than an `undef` where
nobody is watching, and the eunit suite guards the attribute itself.

### The store

This service was scaffolded with `store=1`, so it owns a `reckon-db` store called
`mcl_sentinel_store`. `store_id/0` and `data_dir/0` are exported, `mcl_om:boot/1`
opens the store and its evoq subscription before `start/1` fires, and
`config/sys.config.src` carries the `evoq` adapter block that boot requires.

⚠ **The store id is written in two places**, `store_id/0` and the `evoq` block,
and nothing makes them agree by itself. A generated test compares them, along
with a second one asserting the `evoq` block is present at all. Keep both.

⚠ **`deploy/docker-compose.yml` mounts a volume, and on a node it must.** Without
it the record lives inside the container and every recreate destroys it, which is
the same as not keeping one.

The store is node-local. To make it span every node running the same `store_id`,
export the optional `store_mode/0` callback returning `cluster`, and `mcl_om`
starts it with reckon-db discovery and Ra clustering. It is not generated,
because `single` is the default and a scaffold should not decide that for you.

## Licence

Apache-2.0.
