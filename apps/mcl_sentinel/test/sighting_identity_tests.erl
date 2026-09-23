%%% @doc A sighting's identity is the observation, not the delivery.
%%%
%%% A redelivered warden fact must address the stream it is already in, where
%%% the aggregate refuses it, or the evidence log inflates on every redelivery.
-module(sighting_identity_tests).

-include_lib("eunit/include/eunit.hrl").

-define(IP, <<"203.0.113.7">>).
-define(AT, 1785215553616).
-define(WARDEN, <<"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1">>).

same_observation_yields_same_id_test() ->
    ?assertEqual(id(report()), id(report())).

%% Each discriminating field must discriminate, or two distinct observations
%% collapse into one and evidence is lost.
distinct_observations_yield_distinct_ids_test() ->
    Base = id(report()),
    ?assertNotEqual(Base, id((report())#{source_ip => <<"198.51.100.9">>})),
    ?assertNotEqual(Base, id((report())#{warden_id => <<"B2">>})),
    ?assertNotEqual(Base, id((report())#{at_ms => ?AT + 1})),
    ?assertNotEqual(Base, id((report())#{service => <<"http">>})).

%% The label is what a warden says about itself. Relabelling a box does not
%% make its old sightings new ones.
the_label_is_not_part_of_the_identity_test() ->
    ?assertEqual(id(report()), id((report())#{label => <<"renamed">>})).

id_is_32_lower_hex_test() ->
    ?assertMatch({match, _}, re:run(id(report()), <<"^[0-9a-f]{32}$">>)).

recorded_sighting_refuses_a_duplicate_test() ->
    {ok, Fresh} = threat_aggregate:init(<<"sight-abc">>),
    {ok, [Event]} = threat_aggregate:execute(Fresh, command()),
    Recorded = threat_aggregate:apply(Fresh, Event),
    ?assertEqual({ok, []}, threat_aggregate:execute(Recorded, command())).

the_event_carries_the_evidence_test() ->
    {ok, Fresh} = threat_aggregate:init(<<"sight-abc">>),
    {ok, [Event]} = threat_aggregate:execute(Fresh, command()),
    ?assertMatch(#{event_type := <<"threat_sighted_v1">>, sighting_id := <<"abc">>,
                   warden_id := ?WARDEN, source_ip := ?IP, attempts := 5,
                   usernames := [<<"root">>], at_ms := ?AT}, Event).

%% Evidence is an address, and nothing else.
a_command_without_an_address_is_refused_test() ->
    {ok, Fresh} = threat_aggregate:init(<<"sight-abc">>),
    ?assertEqual({error, not_an_ip},
                 threat_aggregate:execute(Fresh, (command())#{source_ip => <<"x">>})).

unknown_commands_are_rejected_test() ->
    {ok, Fresh} = threat_aggregate:init(<<"sight-abc">>),
    ?assertEqual({error, unknown_command},
                 threat_aggregate:execute(Fresh, #{command_type => <<"nope">>})).

command_round_trips_from_an_attributed_report_test() ->
    {ok, Cmd} = report_threat_v1:new(<<"abc">>, report()),
    ?assertEqual(command(), report_threat_v1:to_map(Cmd)).

%% --- helpers ---

report() ->
    #{source_ip => ?IP, warden_id => ?WARDEN, label => <<"helsinki">>,
      service => <<"ssh">>, attempts => 5, window_s => 300,
      usernames => [<<"root">>], at_ms => ?AT}.

id(#{source_ip := Ip, warden_id := W, service := S, at_ms := At}) ->
    maybe_report_threat:sighting_id(Ip, W, S, At).

command() ->
    #{command_type => <<"report_threat">>, sighting_id => <<"abc">>,
      warden_id => ?WARDEN, label => <<"helsinki">>, source_ip => ?IP,
      service => <<"ssh">>, attempts => 5, window_s => 300,
      usernames => [<<"root">>], at_ms => ?AT}.
