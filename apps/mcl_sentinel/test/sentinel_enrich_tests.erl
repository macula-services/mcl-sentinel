%%% @doc Attacker enrichment, from the record shape DB-IP Lite actually returns.
-module(sentinel_enrich_tests).

-include_lib("eunit/include/eunit.hrl").

%% The two entries locus returned for 8.8.8.8 from dbip-city-lite-2026-09 and
%% dbip-asn-lite-2026-09, trimmed to the fields that are read.
city() ->
    #{<<"city">> => #{<<"names">> => #{<<"en">> => <<"Mountain View">>}},
      <<"country">> => #{<<"iso_code">> => <<"US">>,
                         <<"names">> => #{<<"en">> => <<"United States">>}},
      <<"location">> => #{<<"latitude">> => 37.422, <<"longitude">> => -122.085}}.

asn() ->
    #{<<"autonomous_system_number">> => 15169,
      <<"autonomous_system_organization">> => <<"Google LLC">>}.

a_full_record_flattens_test() ->
    ?assertEqual(#{country_iso => <<"US">>, country => <<"United States">>,
                   city => <<"Mountain View">>, lat => 37.422, lng => -122.085,
                   asn => 15169, asn_org => <<"Google LLC">>, net_type => <<"hosting">>},
                 sentinel_enrich:geo(city(), asn())).

a_missing_database_contributes_nothing_test() ->
    ?assertEqual(#{country_iso => <<"US">>, country => <<"United States">>,
                   city => <<"Mountain View">>, lat => 37.422, lng => -122.085},
                 sentinel_enrich:geo(city(), #{})),
    ?assertEqual(#{}, sentinel_enrich:geo(#{}, #{})).

%% net_type goes on the wire, so it is text, never an atom.
net_type_is_text_test() ->
    ?assertEqual(<<"hosting">>, sentinel_enrich:net_type(<<"Hetzner Online GmbH">>)),
    ?assertEqual(<<"isp">>, sentinel_enrich:net_type(<<"Deutsche Telekom AG">>)),
    ?assertEqual(<<"unknown">>, sentinel_enrich:net_type(<<"Example Org">>)),
    ?assertEqual(undefined, sentinel_enrich:net_type(undefined)).

%% With no database loaded a lookup answers empty rather than failing: the rest
%% of the sentinel does not depend on enrichment.
lookup_without_a_loaded_database_is_empty_test() ->
    ?assertEqual(#{}, sentinel_enrich:lookup(<<"203.0.113.7">>)).
