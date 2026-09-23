%%% @doc What a warden report turns into, end to end through the ingest.
%%%
%%% Recording, the read model and publishing are mocked, so each case sees
%%% exactly what the handler hands on. Mocks live in the test body, not a
%%% fixture setup, because eunit runs a fixture's setup in another process.
-module(hear_warden_reports_tests).

-include_lib("eunit/include/eunit.hrl").

-define(SIGHTED, <<"io.macula/mcl-warden/warden/watch/attacker_sighted_v1">>).
-define(ENSNARED, <<"io.macula/mcl-warden/warden/watch/attacker_ensnared_v1">>).
-define(IP, <<"203.0.113.7">>).
-define(AT, 1785215553616).
-define(A, binary:copy(<<16#A1>>, 32)).
-define(B, binary:copy(<<16#B2>>, 32)).
-define(C, binary:copy(<<16#C3>>, 32)).

%%------------------------------------------------------------------------------
%% Sightings: the evidence chain
%%------------------------------------------------------------------------------

an_unverified_sighting_records_nothing_test() ->
    with_handler(fun(St) ->
        deliver(?SIGHTED, sighting(), meta(?A, false), St),
        ?assertEqual(0, dispatched()),
        ?assertEqual([], published())
    end).

a_sighting_from_an_unlisted_publisher_records_nothing_test() ->
    with_handler(fun(St) ->
        deliver(?SIGHTED, sighting(), meta(?C, true), St),
        ?assertEqual(0, dispatched()),
        ?assertEqual([], published())
    end).

an_attributed_sighting_is_recorded_folded_and_published_test() ->
    with_handler(fun(St) ->
        St1 = deliver(?SIGHTED, sighting(), meta(?A, true), St),
        Cmd = meck:capture(first, maybe_report_threat, dispatch, '_', 1),
        ?assertMatch(#{warden_id := <<"A1A1", _/binary>>, source_ip := ?IP},
                     report_threat_v1:to_map(Cmd)),
        ?assertEqual(1, meck:num_calls(sentinel_threats, record_sighting, '_')),
        ?assertMatch([{attacker_sighted, #{seq := 1, source_ip := ?IP,
                                           warden_id := <<"A1A1", _/binary>>}}],
                     published()),
        ?assertEqual(1, seq(St1))
    end).

%% A redelivered observation addresses a stream that already holds it, and the
%% aggregate records nothing. Nothing new happened: no fold, no fact, no seq.
a_duplicate_sighting_is_silent_test() ->
    with_handler(fun(St) ->
        meck:expect(maybe_report_threat, dispatch, fun(_) -> {ok, 1, []} end),
        St1 = deliver(?SIGHTED, sighting(), meta(?A, true), St),
        ?assertEqual(0, meck:num_calls(sentinel_threats, record_sighting, '_')),
        ?assertEqual([], published()),
        ?assertEqual(0, seq(St1))
    end).

%% A sighting that could not be recorded is evidence we do not hold, so it is
%% not announced either.
a_sighting_that_failed_to_record_is_not_published_test() ->
    with_handler(fun(St) ->
        meck:expect(maybe_report_threat, dispatch, fun(_) -> {error, timeout} end),
        deliver(?SIGHTED, sighting(), meta(?A, true), St),
        ?assertEqual(0, meck:num_calls(sentinel_threats, record_sighting, '_')),
        ?assertEqual([], published())
    end).

%% The sighting that makes an address a campaign announces the campaign, once,
%% live.
the_crossing_sighting_announces_the_campaign_test() ->
    with_handler(fun(St) ->
        meck:expect(sentinel_threats, record_sighting, fun(_) -> crossed_border end),
        deliver(?SIGHTED, sighting(), meta(?B, true), St),
        ?assertMatch([{attacker_sighted, _},
                      {campaign_detected, #{source_ip := ?IP, warden_count := 2}}],
                     published())
    end).

%%------------------------------------------------------------------------------
%% Ensnarements: the tarpit tally
%%------------------------------------------------------------------------------

an_attributed_ensnare_is_folded_and_published_test() ->
    with_handler(fun(St) ->
        deliver(?ENSNARED, ensnare(), meta(?B, true), St),
        ?assertEqual(1, meck:num_calls(sentinel_threats, record_ensnared, [?IP, 4200])),
        ?assertMatch([{attacker_ensnared, #{held_ms := 4200, warden_id := <<"B2B2", _/binary>>}}],
                     published())
    end).

an_unverified_ensnare_is_dropped_test() ->
    with_handler(fun(St) ->
        deliver(?ENSNARED, ensnare(), meta(?B, false), St),
        ?assertEqual(0, meck:num_calls(sentinel_threats, record_ensnared, '_')),
        ?assertEqual([], published())
    end).

%%------------------------------------------------------------------------------
%% The heartbeat, and what does not belong here
%%------------------------------------------------------------------------------

the_heartbeat_carries_the_stamp_and_clears_refusals_test() ->
    with_handler(fun(St) ->
        St1 = deliver(?SIGHTED, sighting(), meta(?A, true), St),
        St2 = deliver(?SIGHTED, sighting(), meta(?C, true), St1),
        ?assertEqual(#{unlisted_warden => 1}, refused(St2)),
        {noreply, St3} = hear_warden_reports:handle_info(check_in, St2),
        ?assertMatch({sentinel_checked_in, #{seq := 1, interval_s := 60}}, lists:last(published())),
        ?assertEqual(#{}, refused(St3))
    end).

an_event_on_another_topic_is_ignored_test() ->
    with_handler(fun(St) ->
        deliver(<<"io.macula/other/app/x/y_v1">>, sighting(), meta(?A, true), St),
        ?assertEqual(0, dispatched()),
        ?assertEqual([], published())
    end).

%% Without a valid warden list the sentinel would record nothing or anyone, so
%% the ingest refuses to start.
init_refuses_without_wardens_test() ->
    ok = application:unset_env(mcl_sentinel, wardens),
    ?assertError({invalid_sentinel_wardens, missing}, hear_warden_reports:init([])).

%%------------------------------------------------------------------------------
%% helpers
%%------------------------------------------------------------------------------

with_handler(Test) ->
    ok = application:set_env(mcl_sentinel, wardens,
                             <<(hex(?A))/binary, ",", (hex(?B))/binary>>),
    ok = application:set_env(mcl_sentinel, realm_name, "io.macula"),
    mock(),
    try
        {ok, St} = hear_warden_reports:init([]),
        Test(St)
    after
        meck:unload(),
        application:unset_env(mcl_sentinel, wardens),
        application:unset_env(mcl_sentinel, realm_name)
    end.

mock() ->
    ok = meck:new(maybe_report_threat, [passthrough]),
    ok = meck:expect(maybe_report_threat, dispatch, fun(_Cmd) -> {ok, 1, [#{}]} end),
    ok = meck:new(sentinel_threats, [non_strict]),
    ok = meck:expect(sentinel_threats, record_sighting, fun(_) -> noted end),
    ok = meck:expect(sentinel_threats, record_ensnared, fun(_, _) -> ok end),
    ok = meck:expect(sentinel_threats, get,
                     fun(Ip) -> {ok, #{source_ip => Ip, wardens => #{hex(?A) => #{}, hex(?B) => #{}},
                                       total_attempts => 10, usernames => [],
                                       first_seen => 1, last_seen => 2, geo => #{}}}
                     end),
    ok = meck:new(sentinel_enrich, [non_strict]),
    ok = meck:expect(sentinel_enrich, lookup, fun(_) -> #{} end),
    ok = meck:new(mcl_sentinel_facts, [passthrough]),
    ok = meck:expect(mcl_sentinel_facts, publish, fun(_Fact, _Payload) -> ok end).

deliver(Topic, Fact, Meta, St) ->
    {noreply, St1} = hear_warden_reports:handle_info(
                       {macula_event, make_ref(), Topic, Fact, Meta}, St),
    St1.

dispatched() -> meck:num_calls(maybe_report_threat, dispatch, '_').

published() ->
    [{Fact, Payload} || {_Pid, {mcl_sentinel_facts, publish, [Fact, Payload]}, _}
                            <- meck:history(mcl_sentinel_facts)].

seq(St) -> hear_warden_reports:seq(St).

refused(St) -> hear_warden_reports:refused(St).

sighting() ->
    #{source_ip => ?IP, label => <<"helsinki">>, service => <<"ssh">>,
      attempts => 5, window_s => 300, usernames => [<<"root">>], at_ms => ?AT}.

ensnare() ->
    #{source_ip => ?IP, label => <<"helsinki">>, held_ms => 4200, at_ms => ?AT}.

meta(Key, Verified) ->
    #{publisher => Key, publisher_verified => Verified, delivered_via => direct}.

hex(Key) -> binary:encode_hex(Key).

%%------------------------------------------------------------------------------
%% Subscriptions are held per topic
%%------------------------------------------------------------------------------

%% Re-subscribing a topic that is still held would deliver its facts twice, and
%% an ensnarement has no deduplication. Only the missing topic is subscribed
%% again.
only_a_lost_subscription_is_renewed_test() ->
    with_handler(fun(St) ->
        ok = meck:new(mcl_om, [non_strict]),
        ok = meck:expect(mcl_om, mesh_handles, fun() -> {ok, pool, <<0:256>>} end),
        ok = meck:new(macula, [non_strict]),
        ok = meck:expect(macula, subscribe, fun(_P, _R, _T, _S) -> {ok, make_ref()} end),
        {noreply, St1} = hear_warden_reports:handle_info(subscribe, St),
        ?assertEqual(2, meck:num_calls(macula, subscribe, '_')),
        [{Lost, _} | _] = hear_warden_reports:refs(St1),
        {noreply, St2} = hear_warden_reports:handle_info({macula_event_gone, Lost, closed}, St1),
        {noreply, _St3} = hear_warden_reports:handle_info(subscribe, St2),
        ?assertEqual(3, meck:num_calls(macula, subscribe, '_'))
    end).

a_partial_subscription_is_not_hearing_test() ->
    with_handler(fun(St) ->
        ok = meck:new(mcl_om, [non_strict]),
        ok = meck:expect(mcl_om, mesh_handles, fun() -> {ok, pool, <<0:256>>} end),
        ok = meck:new(macula, [non_strict]),
        ok = meck:expect(macula, subscribe,
                         fun(_P, _R, ?SIGHTED, _S) -> {ok, make_ref()};
                            (_P, _R, _T, _S) -> {error, timeout} end),
        {noreply, St1} = hear_warden_reports:handle_info(subscribe, St),
        ?assertEqual(false, hear_warden_reports:is_subscribed(St1))
    end).
