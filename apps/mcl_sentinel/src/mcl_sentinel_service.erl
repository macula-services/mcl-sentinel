%% @doc The mcl_om service contract: what this service is and may do.
%%
%% SIX CALLBACKS, ALL REQUIRED. mcl_om resolves them BY NAME at startup, on a
%% live node, so a service that forgets one dies with `undef' where nobody is
%% watching. The `-behaviour' attribute below is what turns that into a compile
%% error instead, and the generated test suite guards the attribute itself.
%%
%% IT ANNOUNCES NOTHING AND ASKS FOR NOTHING, on purpose. A service that does
%% nothing yet has no capability to offer and needs no authority from the realm.
%% Advertising a capability before it exists puts a lie on the mesh that another
%% service can find and call. Both lists grow when the thing they name exists,
%% and a generated test fails when they change, so growing them is a deliberate
%% act rather than a comment someone forgot.
-module(mcl_sentinel_service).

-behaviour(mcl_om_service).

-export([info/0, start/1, stop/1, health/0, capabilities/0, identity_spec/0]).
%% ==========================================================================
%% AND THE STORE THIS SERVICE OWNS
%% ==========================================================================
%%
%% NOT an mcl_om callback: mcl_om opens no store since 0.35 (mcl-om#10).
%% mcl_sentinel_app reads event_store/0 and opens the store (mcl_sentinel_store)
%% before mcl_om:boot/1, with reckon_db, evoq and reckon_evoq declared here.
%% One map, NOT store_id/0 and data_dir/0: mcl_om 0.35 warns at every boot about
%% a service module exporting that pair.
%%
%% ⚠ `config/sys.config.src' MUST CARRY THE `evoq' BLOCK: the per-store evoq
%% subscription reads the global log, and crashes on
%% `{not_configured, event_store_adapter}' without it. A sibling put two of three
%% fleet nodes into a boot-crash loop this exact way.
-export([event_store/0]).
-export([hearing/1]).

info() ->
    #{name => <<"mcl-sentinel">>,
      version => <<"0.1.0">>,
      description => <<"Correlates warden sightings into cross-border campaigns and publishes them, enriched, to the threat commons">>}.

%% The realm name the topics carry must be the realm the pool is in, or the
%% sentinel subscribes where no warden publishes and looks like a quiet night.
start(_Opts) ->
    ok = mcl_sentinel_facts:check_realm_name(),
    mcl_sentinel_sup:start_link().

stop(_State) -> ok.

%% Health is whether the sentinel is HEARING the wardens: a deaf sentinel
%% publishes nothing and looks exactly like a quiet night. Missing geolocation
%% data is not a health failure; enrichment is additive.
health() ->
    try hear_warden_reports:subscribed() of
        Subscribed -> hearing(Subscribed)
    catch _:_ -> {down, not_hearing_wardens}
    end.

%% @doc Health from the subscription state. Exported for tests.
hearing(true)  -> ok;
hearing(false) -> {degraded, not_subscribed_to_wardens}.

%% Nothing callable. The sentinel's output is its four published facts.
capabilities() -> [].

%% THE AUTHORITY THIS SERVICE ASKS THE REALM FOR, and deliberately nothing more.
%% Ask for exactly the topics you publish and subscribe to. Popped, an attacker
%% gains precisely this and no more, which is the whole point of listing it.
%%
%% The scope is claimed now because it is the namespace every later resource
%% hangs under, and a scope costs nothing while a rename costs every deployed
%% peer.
identity_spec() ->
    #{scope => <<"mcl-sentinel">>,
      actions => [],
      resources => [],
      ttl_days => 30}.

%% ==========================================================================
%% The store
%% ==========================================================================

%% @doc The reckon-db store this service owns, as mcl_sentinel_app opens it.
%%
%% `id': ⚠ NAMED IN TWO PLACES, here and in the `evoq' block of
%% `config/sys.config.src' (and the read model's `event_store_id' app env); a
%% generated test compares them. Disagreeing opens one store and addresses another.
%%
%% `dir': where it lives (the store at <dir>/<id>/). ⚠ DEFAULTS TO A PATH INSIDE
%% THE CONTAINER AND MUST NOT STAY THERE ON A NODE: `deploy/docker-compose.yml'
%% mounts a volume and sets MCL_DATA_DIR.
%%
%% `indexes': sightings are looked up by address; indexing the payload lets an
%% abuse report find every sighting of an attacker without a full scan. Declared
%% when the store opens.
-spec event_store() -> #{id := atom(), dir := string(), indexes := [term()],
                         mode := single | cluster, integrity := disabled | map()}.
event_store() ->
    #{id => mcl_sentinel_store,
      dir => chosen(os:getenv("MCL_DATA_DIR")),
      indexes => [event_type, {payload, <<"source_ip">>}],
      mode => single,
      integrity => disabled}.

chosen(false) -> "/tmp/mcl_sentinel";
chosen("") -> "/tmp/mcl_sentinel";
chosen(Path) -> Path.
