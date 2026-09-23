%%% @doc Any evoq event handler here declares what it does with replay.
%%%
%%% The sentinel has none today: its read model is folded once at boot and
%%% then live by the ingest (see sentinel_threats), so there is nothing for
%%% evoq to replay into. If one is added, evoq (>= 1.24) hands it every stored
%%% event again on each restart, and a handler that publishes must declare
%%% `skip' or it re-publishes history. This test finds one that declares
%%% nothing.
-module(replay_policy_tests).

-include_lib("eunit/include/eunit.hrl").

every_event_handler_declares_a_replay_policy_test() ->
    _ = application:load(mcl_sentinel),
    {ok, Mods} = application:get_key(mcl_sentinel, modules),
    Handlers = [M || M <- Mods,
                     {module, M} =:= code:ensure_loaded(M),
                     lists:member(evoq_event_handler,
                                  lists:append([B || {behaviour, B} <- M:module_info(attributes)]))],
    ?assertEqual([], [M || M <- Handlers, not erlang:function_exported(M, replay_policy, 0)]).
