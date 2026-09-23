%%% @doc Which warden a report comes from, and whether it is a report at all.
-module(warden_report_tests).

-include_lib("eunit/include/eunit.hrl").

-define(A, binary:copy(<<16#A1>>, 32)).
-define(B, binary:copy(<<16#B2>>, 32)).
-define(C, binary:copy(<<16#C3>>, 32)).
-define(AT, 1785215553616).

%%------------------------------------------------------------------------------
%% The configured list
%%------------------------------------------------------------------------------

wardens_parse_in_any_case_and_separator_test() ->
    Text = <<(string:lowercase(hex(?B)))/binary, ", ", (hex(?A))/binary, "\n">>,
    ?assertEqual({ok, [hex(?A), hex(?B)]}, warden_report:parse_wardens(Text)).

a_missing_or_empty_list_is_refused_test() ->
    ?assertEqual({error, missing}, warden_report:parse_wardens(undefined)),
    ?assertEqual({error, empty}, warden_report:parse_wardens("  ,  ")),
    ?assertMatch({error, {not_64_hex, _}}, warden_report:parse_wardens("abc")).

%% A sentinel with no valid list would record nothing, or anyone. It does not
%% start.
wardens_raises_without_a_valid_list_test() ->
    ok = application:unset_env(mcl_sentinel, wardens),
    ?assertError({invalid_sentinel_wardens, missing}, warden_report:wardens()).

%%------------------------------------------------------------------------------
%% Attribution: by the publisher macula verified, and nothing else
%%------------------------------------------------------------------------------

a_listed_verified_publisher_is_the_warden_test() ->
    ?assertMatch({ok, #{warden_id := <<"A1A1", _/binary>>}},
                 warden_report:attribute(attacker_sighted, sighting(), meta(?A, true), wardens())).

an_unverified_publisher_is_refused_test() ->
    ?assertEqual({refused, unverified_publisher},
                 warden_report:attribute(attacker_sighted, sighting(), meta(?A, false), wardens())).

an_unlisted_publisher_is_refused_test() ->
    ?assertEqual({refused, unlisted_warden},
                 warden_report:attribute(attacker_sighted, sighting(), meta(?C, true), wardens())).

%% The warden contract carries no sender field. One that claims to be another
%% warden is not believed: warden_id is always the verified publisher.
a_self_asserted_warden_field_is_ignored_test() ->
    Fact = (sighting())#{warden => hex(?B)},
    {ok, Report} = warden_report:attribute(attacker_sighted, Fact, meta(?A, true), wardens()),
    ?assertEqual(hex(?A), maps:get(warden_id, Report)),
    ?assertNot(maps:is_key(warden, Report)).

%%------------------------------------------------------------------------------
%% Normalisation: the shape every later step can rely on
%%------------------------------------------------------------------------------

a_sighting_normalises_to_atom_keys_test() ->
    {ok, Report} = warden_report:attribute(attacker_sighted, sighting(), meta(?A, true), wardens()),
    ?assertEqual(#{warden_id => hex(?A), source_ip => <<"203.0.113.7">>,
                   service => <<"ssh">>, attempts => 5, window_s => 300,
                   usernames => [<<"root">>], at_ms => ?AT,
                   label => <<"helsinki">>, tenant_id => <<"acme">>},
                 Report).

%% macula decodes a key to an atom only when the atom already exists; otherwise
%% it arrives as {text, Name}. Text values may arrive tagged the same way.
keys_and_text_arrive_in_every_wire_form_test() ->
    Wire = #{{text, <<"source_ip">>} => {text, <<"203.0.113.7">>},
             <<"service">> => <<"ssh">>, attempts => 5,
             {text, <<"window_s">>} => 300, usernames => [{text, <<"root">>}],
             at_ms => ?AT, {text, <<"label">>} => {text, <<"helsinki">>}},
    {ok, Report} = warden_report:attribute(attacker_sighted, Wire, meta(?A, true), wardens()),
    ?assertMatch(#{source_ip := <<"203.0.113.7">>, window_s := 300,
                   usernames := [<<"root">>], label := <<"helsinki">>}, Report).

an_ensnare_normalises_test() ->
    Fact = #{source_ip => <<"2001:db8::7">>, held_ms => 4200, at_ms => ?AT},
    ?assertEqual({ok, #{warden_id => hex(?B), source_ip => <<"2001:db8::7">>,
                        held_ms => 4200, at_ms => ?AT}},
                 warden_report:attribute(attacker_ensnared, Fact, meta(?B, true), wardens())).

%% A report missing a field its fact requires, or carrying the wrong type, is
%% not evidence. Neither is a source that is not an address.
a_malformed_report_is_refused_test() ->
    Refused = {refused, malformed_fact},
    [?assertEqual(Refused, warden_report:attribute(attacker_sighted, F, meta(?A, true), wardens()))
     || F <- [maps:remove(attempts, sighting()),
              (sighting())#{attempts => <<"5">>},
              (sighting())#{source_ip => <<"not-an-ip">>},
              (sighting())#{usernames => <<"root">>},
              maps:remove(at_ms, sighting()),
              not_a_map]],
    ?assertEqual(Refused, warden_report:attribute(attacker_ensnared,
                                                  #{source_ip => <<"203.0.113.7">>, at_ms => ?AT},
                                                  meta(?A, true), wardens())).

%%------------------------------------------------------------------------------
%% helpers
%%------------------------------------------------------------------------------

wardens() -> [hex(?A), hex(?B)].

sighting() ->
    #{source_ip => <<"203.0.113.7">>, service => <<"ssh">>, attempts => 5,
      window_s => 300, usernames => [<<"root">>], at_ms => ?AT,
      label => <<"helsinki">>, tenant_id => <<"acme">>}.

meta(Key, Verified) ->
    #{publisher => Key, publisher_verified => Verified, delivered_via => direct}.

hex(Key) -> binary:encode_hex(Key).
