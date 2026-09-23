%%% @doc The sentinel's public contract, and the warden contract it reads.
%%%
%%% The portal's map is built against the four sentinel facts. A change that
%%% breaks one of these tests is a change to the contract, and it gets a new
%%% `_vN', not an edit.
-module(mcl_sentinel_facts_tests).

-include_lib("eunit/include/eunit.hrl").

-define(REALM_NAME, <<"io.macula">>).
-define(WARDEN, <<"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1">>).

%%------------------------------------------------------------------------------
%% Topics
%%------------------------------------------------------------------------------

sentinel_topics_are_the_published_contract_test() ->
    [?assertEqual(<<"io.macula/mcl-sentinel/sentinel/watch/", Name/binary, "_v1">>,
                  mcl_sentinel_facts:topic(?REALM_NAME, binary_to_atom(Name)))
     || Name <- [<<"attacker_sighted">>, <<"attacker_ensnared">>,
                 <<"campaign_detected">>, <<"sentinel_checked_in">>]].

%% The other half of mcl-warden's contract, spelled out rather than derived, so
%% a drift on either side fails here.
warden_topics_are_the_wardens_contract_test() ->
    ?assertEqual(<<"io.macula/mcl-warden/warden/watch/attacker_sighted_v1">>,
                 mcl_sentinel_facts:warden_topic(?REALM_NAME, attacker_sighted)),
    ?assertEqual(<<"io.macula/mcl-warden/warden/watch/attacker_ensnared_v1">>,
                 mcl_sentinel_facts:warden_topic(?REALM_NAME, attacker_ensnared)).

every_topic_is_a_canonical_app_fact_test() ->
    [?assertMatch({ok, #{tier := app, org := <<"mcl-sentinel">>,
                         app := <<"sentinel">>, domain := <<"watch">>}},
                  macula_topic:parse(mcl_sentinel_facts:topic(?REALM_NAME, F)))
     || F <- [attacker_sighted, attacker_ensnared, campaign_detected,
              sentinel_checked_in]].

realm_name_must_hash_to_the_realm_tag_test() ->
    ?assertEqual(ok, mcl_sentinel_facts:check_realm_name(
                       ?REALM_NAME, crypto:hash(sha256, ?REALM_NAME))),
    ?assertError({mcl_sentinel_realm_name_mismatch, ?REALM_NAME, _},
                 mcl_sentinel_facts:check_realm_name(?REALM_NAME, <<0:256>>)).

%%------------------------------------------------------------------------------
%% Payloads
%%------------------------------------------------------------------------------

attacker_sighted_is_the_report_enriched_and_sequenced_test() ->
    ?assertEqual(
       #{sighting_id => <<"abc">>, epoch => 7, seq => 3,
         source_ip => <<"203.0.113.7">>, warden_id => ?WARDEN,
         label => <<"helsinki">>, tenant_id => <<"acme">>,
         service => <<"ssh">>, attempts => 5, window_s => 300,
         usernames => [<<"root">>], at_ms => 1000,
         country_iso => <<"FI">>, lat_e6 => 60170000, lng_e6 => 24940000,
         asn => 1759, asn_org => <<"Telia Finland Oyj">>, net_type => <<"isp">>},
       mcl_sentinel_facts:attacker_sighted(<<"abc">>, report(), geo(), {7, 3})).

attacker_ensnared_is_the_report_enriched_test() ->
    Report = maps:without([service, attempts, window_s, usernames],
                          (report())#{held_ms => 4200}),
    ?assertEqual(
       #{source_ip => <<"203.0.113.7">>, warden_id => ?WARDEN,
         label => <<"helsinki">>, tenant_id => <<"acme">>,
         held_ms => 4200, at_ms => 1000,
         country_iso => <<"FI">>, lat_e6 => 60170000, lng_e6 => 24940000,
         asn => 1759, asn_org => <<"Telia Finland Oyj">>, net_type => <<"isp">>},
       mcl_sentinel_facts:attacker_ensnared(Report, geo())).

%% The same attacker on two or more wardens. `head_start_ms' is how long the
%% commons knew before the latest box was hit.
campaign_detected_names_every_warden_that_saw_it_test() ->
    Row = #{source_ip => <<"203.0.113.7">>,
            wardens => #{?WARDEN => #{label => <<"helsinki">>},
                         <<"B2">> => #{}},
            total_attempts => 12, usernames => [<<"admin">>, <<"root">>],
            first_seen => 1000, last_seen => 61000},
    Fact = mcl_sentinel_facts:campaign_detected(Row, #{}, 99),
    ?assertEqual(#{source_ip => <<"203.0.113.7">>,
                   warden_ids => [?WARDEN, <<"B2">>], warden_count => 2,
                   labels => [<<"helsinki">>], head_start_ms => 60000,
                   total_attempts => 12, usernames => [<<"admin">>, <<"root">>],
                   first_seen_ms => 1000, last_seen_ms => 61000, at_ms => 99},
                 Fact).

sentinel_checked_in_says_how_often_to_expect_it_test() ->
    ?assertEqual(#{epoch => 7, seq => 3, interval_s => 60, at_ms => 99},
                 mcl_sentinel_facts:sentinel_checked_in({7, 3}, 99)).

%% A missing geolocation database means no geo keys at all, never `undefined'.
no_geo_means_no_geo_keys_test() ->
    Fact = mcl_sentinel_facts:attacker_sighted(<<"abc">>, report(), #{}, {1, 1}),
    [?assertNot(maps:is_key(K, Fact))
     || K <- [country_iso, country, city, lat_e6, lng_e6, asn, asn_org, net_type]].

%% Coordinates are integer micro-degrees; floats are rounded, never sent.
coordinates_are_micro_degrees_test() ->
    #{lat_e6 := Lat, lng_e6 := Lng} =
        mcl_sentinel_facts:geo_fields(#{lat => -33.8688, lng => 151.2093}),
    ?assertEqual({-33868800, 151209300}, {Lat, Lng}).

usernames_are_capped_at_twenty_test() ->
    Many = [integer_to_binary(N) || N <- lists:seq(1, 30)],
    #{usernames := U} = mcl_sentinel_facts:attacker_sighted(
                          <<"abc">>, (report())#{usernames => Many}, #{}, {1, 1}),
    ?assertEqual(20, length(U)).

payloads_hold_only_wire_safe_values_test() ->
    Row = #{source_ip => <<"203.0.113.7">>, wardens => #{?WARDEN => #{}},
            total_attempts => 1, usernames => [], first_seen => 1, last_seen => 1},
    Facts = [mcl_sentinel_facts:attacker_sighted(<<"abc">>, report(), geo(), {1, 1}),
             mcl_sentinel_facts:attacker_ensnared((report())#{held_ms => 1}, geo()),
             mcl_sentinel_facts:campaign_detected(Row, geo(), 1),
             mcl_sentinel_facts:sentinel_checked_in({1, 1}, 1)],
    [?assert(wire_safe(V)) || F <- Facts, V <- maps:values(F)].

%%------------------------------------------------------------------------------
%% helpers
%%------------------------------------------------------------------------------

report() ->
    #{source_ip => <<"203.0.113.7">>, warden_id => ?WARDEN,
      label => <<"helsinki">>, tenant_id => <<"acme">>, service => <<"ssh">>,
      attempts => 5, window_s => 300, usernames => [<<"root">>], at_ms => 1000}.

%% The shape sentinel_enrich:lookup/1 returns.
geo() ->
    #{country_iso => <<"FI">>, lat => 60.17, lng => 24.94, asn => 1759,
      asn_org => <<"Telia Finland Oyj">>, net_type => <<"isp">>}.

wire_safe(V) when is_binary(V); is_integer(V) -> true;
wire_safe(L) when is_list(L) -> lists:all(fun is_binary/1, L);
wire_safe(_) -> false.
