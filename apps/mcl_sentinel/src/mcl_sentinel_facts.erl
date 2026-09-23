%%% @doc The sentinel's public contract, and the warden contract it reads.
%%%
%%% It hears mcl-warden's `attacker_sighted' and `attacker_ensnared' and
%%% publishes four facts of its own, org `mcl-sentinel', app `sentinel', domain
%%% `watch', for example `io.macula/mcl-sentinel/sentinel/watch/campaign_detected_v1':
%%%
%%%   attacker_sighted_v1    one recorded warden sighting, enriched with where
%%%                          the attacker is, and sequenced ({epoch, seq})
%%%   attacker_ensnared_v1   one tarpit capture, enriched
%%%   campaign_detected_v1   an attacker has now been seen by a SECOND warden
%%%   sentinel_checked_in_v1 heartbeat carrying the current {epoch, seq}, so a
%%%                          consumer can tell deaf from quiet
%%%
%%% `warden_id' is the warden's verified publisher (its node id, upper-case
%%% hex); `label' and `tenant_id' are what that warden says about itself.
%%% Geolocation (`country_iso', `country', `city', `lat_e6', `lng_e6', `asn',
%%% `asn_org', `net_type') comes from DB-IP Lite and is present only when the
%%% database is mounted and knows the address. IP geolocation by DB-IP
%%% (https://db-ip.com), CC BY 4.0.
%%%
%%% Values are binaries, integers and lists of binaries only. Times are
%%% milliseconds since the epoch, in `*_ms'.
-module(mcl_sentinel_facts).

-export([publish/2, check_realm_name/0, realm_name/0]).
-export([topic/2, warden_topic/2, check_realm_name/2,
         attacker_sighted/4, attacker_ensnared/2, campaign_detected/3,
         sentinel_checked_in/2, geo_fields/1, check_in_interval_ms/0]).

-define(VERSION, 1).
-define(CHECK_IN_INTERVAL_S, 60).
-define(MAX_USERNAMES, 20).

-type fact() :: attacker_sighted | attacker_ensnared | campaign_detected
              | sentinel_checked_in.
-type warden_fact() :: attacker_sighted | attacker_ensnared.
-type stamp() :: {integer(), non_neg_integer()}.

-export_type([fact/0, warden_fact/0, stamp/0]).

%%------------------------------------------------------------------------------
%% Publishing
%%------------------------------------------------------------------------------

%% @doc Publish one of the sentinel's facts. A dark mesh drops it; a refusal
%% is logged by mcl_om.
-spec publish(fact(), map()) -> ok.
publish(Fact, Payload) ->
    _ = mcl_om_pubsub:publish(topic(realm_name(), Fact), Payload,
                              #{mode => async_log}),
    ok.

%% @doc Refuse to start when the realm name the topics carry is not the realm
%% the pool is in.
-spec check_realm_name() -> ok.
check_realm_name() ->
    check_configured(realm_name(), mcl_om:realm()).

check_configured(Name, {ok, Tag}) -> check_realm_name(Name, Tag);
check_configured(Name, Other)     -> error({mcl_sentinel_realm_unset, Name, Other}).

-spec realm_name() -> binary().
realm_name() ->
    named(application:get_env(mcl_sentinel, realm_name, undefined)).

named(Name) when is_list(Name), Name =/= "" -> unicode:characters_to_binary(Name);
named(Name) when is_binary(Name), Name =/= <<>> -> Name;
named(_Unset) -> error({mcl_sentinel_realm_name_unset, realm_name}).

%%------------------------------------------------------------------------------
%% Topics
%%------------------------------------------------------------------------------

-spec topic(binary(), fact()) -> binary().
topic(RealmName, Fact) ->
    macula_topic:app_fact(RealmName, <<"mcl-sentinel">>, <<"sentinel">>, <<"watch">>,
                          atom_to_binary(Fact, utf8), ?VERSION).

%% @doc mcl-warden's topics, which this service subscribes to.
-spec warden_topic(binary(), warden_fact()) -> binary().
warden_topic(RealmName, Fact) ->
    macula_topic:app_fact(RealmName, <<"mcl-warden">>, <<"warden">>, <<"watch">>,
                          atom_to_binary(Fact, utf8), ?VERSION).

-spec check_realm_name(binary(), binary()) -> ok.
check_realm_name(Name, Tag) ->
    matched(crypto:hash(sha256, Name) =:= Tag, Name, Tag).

matched(true, _Name, _Tag) -> ok;
matched(false, Name, Tag)  -> error({mcl_sentinel_realm_name_mismatch, Name, Tag}).

%%------------------------------------------------------------------------------
%% Payloads, pure
%%------------------------------------------------------------------------------

%% @doc One recorded sighting. `Report' is an attributed warden report
%% (warden_report:attribute/3).
-spec attacker_sighted(binary(), map(), map(), stamp()) -> map().
attacker_sighted(SightingId, Report, Geo, {Epoch, Seq}) ->
    Base = maps:with([source_ip, warden_id, label, tenant_id, service, attempts,
                      window_s, at_ms], Report),
    maps:merge(Base#{sighting_id => SightingId, epoch => Epoch, seq => Seq,
                     usernames => capped(maps:get(usernames, Report, []))},
               geo_fields(Geo)).

-spec attacker_ensnared(map(), map()) -> map().
attacker_ensnared(Report, Geo) ->
    maps:merge(maps:with([source_ip, warden_id, label, tenant_id, held_ms, at_ms],
                         Report),
               geo_fields(Geo)).

%% @doc A read-model row that has just been seen by its second warden.
-spec campaign_detected(map(), map(), integer()) -> map().
campaign_detected(#{source_ip := Ip, wardens := Wardens, first_seen := First,
                    last_seen := Last} = Row, Geo, AtMs) ->
    Ids = lists:sort(maps:keys(Wardens)),
    Labels = lists:usort([L || #{label := L} <- maps:values(Wardens), is_binary(L)]),
    maps:merge(#{source_ip => Ip, warden_ids => Ids, warden_count => length(Ids),
                 labels => Labels, head_start_ms => max(0, Last - First),
                 total_attempts => maps:get(total_attempts, Row, 0),
                 usernames => capped(maps:get(usernames, Row, [])),
                 first_seen_ms => First, last_seen_ms => Last, at_ms => AtMs},
               geo_fields(Geo)).

-spec sentinel_checked_in(stamp(), integer()) -> map().
sentinel_checked_in({Epoch, Seq}, AtMs) ->
    #{epoch => Epoch, seq => Seq, interval_s => ?CHECK_IN_INTERVAL_S, at_ms => AtMs}.

-spec check_in_interval_ms() -> pos_integer().
check_in_interval_ms() -> ?CHECK_IN_INTERVAL_S * 1000.

%% @doc The geolocation keys a fact carries, from a sentinel_enrich:lookup/1
%% result. Absent keys stay absent; coordinates become integer micro-degrees.
-spec geo_fields(map()) -> map().
geo_fields(Geo) ->
    Fields = [{country_iso, maps:get(country_iso, Geo, undefined)},
              {country, maps:get(country, Geo, undefined)},
              {city, maps:get(city, Geo, undefined)},
              {lat_e6, e6(maps:get(lat, Geo, undefined))},
              {lng_e6, e6(maps:get(lng, Geo, undefined))},
              {asn, maps:get(asn, Geo, undefined)},
              {asn_org, maps:get(asn_org, Geo, undefined)},
              {net_type, maps:get(net_type, Geo, undefined)}],
    maps:from_list([{K, V} || {K, V} <- Fields, V =/= undefined]).

e6(F) when is_float(F)   -> round(F * 1000000);
e6(N) when is_integer(N) -> N * 1000000;
e6(_)                    -> undefined.

capped(Usernames) -> lists:sublist([U || U <- Usernames, is_binary(U)], ?MAX_USERNAMES).
