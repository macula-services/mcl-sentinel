%%% @doc A redelivered sighting leaves the aggregate alive.
%%%
%%% `threat_aggregate:execute/2' answers a redelivery with the sanctioned no-op
%%% `{ok, []}' (`sighting_identity_tests' calls that directly, and it is right
%%% to). One layer up, inside evoq, the reply for an EMPTY event list used to be
%%% built by reaching for `hd/1' on it: the aggregate died with a `badarg' and
%%% the caller got an exit instead of `{ok, Version, []}' (evoq#16, fixed in
%%% evoq 1.26.3).
%%%
%%% That layer is exactly why a unit test of `execute/2' cannot pin this, and
%%% why this one runs the whole path against a REAL store: a real append for the
%%% first delivery, a real replay for the second, and the empty-event reply
%%% built by evoq itself. A mocked store would prove nothing here, because the
%%% defect was never in the answer the aggregate gives, only in what evoq did
%%% with it.
-module(redelivered_sighting_tests).

-include_lib("eunit/include/eunit.hrl").

-define(STORE, mcl_sentinel_store).
-define(IP, <<"203.0.113.7">>).
-define(AT, 1785215553616).
-define(WARDEN, <<"A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1">>).

redelivered_sighting_leaves_the_aggregate_alive_test_() ->
    {setup, fun open_store/0, fun close_store/1,
     fun(_State) -> [fun a_redelivery_is_refused_and_the_aggregate_survives/0] end}.

%% --- the test ---

a_redelivery_is_refused_and_the_aggregate_survives() ->
    Id = maybe_report_threat:sighting_id(?IP, ?WARDEN, <<"ssh">>, ?AT),
    {ok, Command} = report_threat_v1:new(Id, report()),
    Stream = threat_aggregate:stream_id(Id),

    %% The sighting goes on the record.
    ?assertMatch({ok, _Version, [#{event_type := <<"threat_sighted_v1">>}]},
                 maybe_report_threat:dispatch(Command)),

    %% The same observation, delivered again. Same id, same stream, refused there.
    ?assertMatch({ok, _Version2, []}, maybe_report_threat:dispatch(Command)),

    %% And the aggregate that refused it is still running. On evoq 1.26.2 this
    %% is where it failed: the dispatch above took the process down rather than
    %% answering, so the sentinel lost that sighting's stream and the caller got
    %% an exit where the service expects `duplicate'.
    {ok, Pid} = evoq_aggregate_registry:lookup(Stream),
    ?assert(is_process_alive(Pid)).

%% --- setup ---

%% A real store, opened the way the service opens it (mcl_sentinel_store:ensure/2
%% is the helper its own docs point tests at), pointed at a directory of this
%% test's own so nothing else in the suite sees it.
open_store() ->
    _ = application:load(evoq),
    ok = application:set_env(evoq, event_store_adapter, reckon_evoq_adapter),
    ok = application:set_env(evoq, subscription_adapter, reckon_evoq_adapter),
    ok = application:set_env(evoq, store_id, ?STORE),
    {ok, Store} = application:ensure_all_started(reckon_db),
    {ok, Evoq} = application:ensure_all_started(evoq),
    Dir = filename:join(tmpdir(), "mcl_sentinel_redelivery"),
    ok = filelib:ensure_path(Dir),
    ok = mcl_sentinel_store:ensure(?STORE, Dir),
    #{dir => Dir, started => Store ++ Evoq}.

close_store(#{dir := Dir, started := Started}) ->
    ok = stop_subscription(?STORE),
    _ = reckon_db_sup:stop_store(?STORE),
    lists:foreach(fun application:stop/1, lists:reverse(Started)),
    _ = file:del_dir_r(Dir),
    ok.

%% evoq registers a store's subscription under a name it derives itself
%% (evoq_store_subscription:registration_name/1), and starts it linked to
%% whoever called. This is the only place in the suite that starts one outside
%% a supervision tree, so it is also the only place that has to stop it.
stop_subscription(StoreId) ->
    case whereis(list_to_atom("evoq_store_sub_" ++ atom_to_list(StoreId))) of
        undefined -> ok;
        Pid       -> gen_server:stop(Pid, normal, 5000)
    end.

tmpdir() ->
    case os:getenv("TMPDIR") of
        false -> "/tmp";
        Dir   -> Dir
    end.

%% --- helpers ---

report() ->
    #{source_ip => ?IP, warden_id => ?WARDEN, label => <<"helsinki">>,
      service => <<"ssh">>, attempts => 5, window_s => 300,
      usernames => [<<"root">>], at_ms => ?AT}.
