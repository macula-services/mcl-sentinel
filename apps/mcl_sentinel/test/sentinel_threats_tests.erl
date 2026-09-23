%%% @doc The threat read model: aggregation, and the cross-border call.
-module(sentinel_threats_tests).

-include_lib("eunit/include/eunit.hrl").

-define(DE, <<"DEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDEDE">>).
-define(FR, <<"F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0F0">>).
-define(IT, <<"1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A">>).

model_test_() ->
    {foreach, fun setup/0, fun cleanup/1,
     [fun one_warden_is_noted/1,
      fun a_second_warden_crosses_the_border/1,
      fun the_same_warden_twice_is_not_a_campaign/1,
      fun attempts_and_usernames_aggregate/1,
      fun cross_border_lists_the_campaigns/1,
      fun ensnarements_add_up/1,
      fun rebuilding_folds_each_event_once/1]}.

setup() ->
    ok = application:unset_env(mcl_sentinel, event_store_id),
    {ok, Pid} = sentinel_threats:start_link(),
    Pid.

cleanup(Pid) ->
    unlink(Pid),
    gen_server:stop(Pid).

one_warden_is_noted(_) ->
    ?_assertEqual(noted, record(<<"192.0.2.1">>, ?DE, 20, [<<"root">>])).

%% The whole point: an address becomes a campaign the moment a SECOND warden
%% sees it, and only that sighting says so.
a_second_warden_crosses_the_border(_) ->
    First = record(<<"192.0.2.2">>, ?DE, 20, [<<"root">>]),
    Second = record(<<"192.0.2.2">>, ?FR, 15, [<<"admin">>]),
    Third = record(<<"192.0.2.2">>, ?IT, 1, []),
    ?_assertEqual([noted, crossed_border, noted], [First, Second, Third]).

%% Wardens are keyed by their verified id, so one warden reporting again, under
%% whatever label, is still one warden.
the_same_warden_twice_is_not_a_campaign(_) ->
    record(<<"192.0.2.3">>, ?DE, 5, []),
    R = sentinel_threats:record_sighting((sighting(<<"192.0.2.3">>, ?DE, 5, []))#{label => <<"x">>}),
    ?_assertEqual(noted, R).

attempts_and_usernames_aggregate(_) ->
    record(<<"192.0.2.4">>, ?DE, 20, [<<"root">>, <<"admin">>]),
    record(<<"192.0.2.4">>, ?FR, 30, [<<"admin">>, <<"oracle">>]),
    {ok, Row} = sentinel_threats:get(<<"192.0.2.4">>),
    [?_assertEqual(50, maps:get(total_attempts, Row)),
     ?_assertEqual([<<"admin">>, <<"oracle">>, <<"root">>], maps:get(usernames, Row)),
     ?_assertEqual(lists:sort([?DE, ?FR]), lists:sort(maps:keys(maps:get(wardens, Row))))].

cross_border_lists_the_campaigns(_) ->
    record(<<"192.0.2.5">>, ?DE, 5, []),
    record(<<"192.0.2.6">>, ?DE, 5, []),
    record(<<"192.0.2.6">>, ?IT, 5, []),
    Ips = [maps:get(source_ip, R) || R <- sentinel_threats:cross_border()],
    ?_assertEqual([<<"192.0.2.6">>], Ips).

ensnarements_add_up(_) ->
    ok = sentinel_threats:record_ensnared(<<"192.0.2.7">>, 1000),
    ok = sentinel_threats:record_ensnared(<<"192.0.2.7">>, 500),
    {ok, Row} = sentinel_threats:get(<<"192.0.2.7">>),
    ?_assertEqual(1500, maps:get(held_ms, Row)).

%% THE REGRESSION. hecate-sentinel folded the log at boot AND again through its
%% projection's catch-up, so every restart added every historical attempt a
%% second time. Here the log is folded once, by rebuild.
rebuilding_folds_each_event_once(Pid) ->
    Events = [(sighting(<<"192.0.2.8">>, ?DE, 3, []))#{event_type => <<"threat_sighted_v1">>},
              (sighting(<<"192.0.2.8">>, ?FR, 4, []))#{event_type => <<"threat_sighted_v1">>}],
    ok = sentinel_threats:rebuild(Pid, Events),
    {ok, Row} = sentinel_threats:get(<<"192.0.2.8">>),
    ?_assertEqual(7, maps:get(total_attempts, Row)).

%%------------------------------------------------------------------------------
%% Boot replay honesty
%%------------------------------------------------------------------------------

a_short_read_is_complete_test() ->
    ?assertMatch({complete, [a, b]}, sentinel_threats:replay_status({ok, [a, b]}, 50000)).

%% Exactly the limit is treated as truncated: the remedy is a log line, so that
%% is the safe direction to be wrong in.
a_read_at_the_limit_is_truncated_test() ->
    ?assertMatch({truncated, [a, b, c]}, sentinel_threats:replay_status({ok, [a, b, c]}, 3)).

a_failed_read_is_not_an_empty_log_test() ->
    ?assertMatch({{failed, _}, []}, sentinel_threats:replay_status({error, timeout}, 50000)).

%%------------------------------------------------------------------------------
%% helpers
%%------------------------------------------------------------------------------

record(Ip, Warden, Attempts, Users) ->
    sentinel_threats:record_sighting(sighting(Ip, Warden, Attempts, Users)).

sighting(Ip, Warden, Attempts, Users) ->
    #{source_ip => Ip, warden_id => Warden, service => <<"ssh">>,
      attempts => Attempts, usernames => Users,
      at_ms => erlang:system_time(millisecond)}.
