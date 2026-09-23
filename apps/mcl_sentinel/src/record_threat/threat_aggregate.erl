%%% @doc Aggregate for one threat sighting (`sight-{id}').
%%%
%%% One stream per sighting, one event. The stream exists because a sighting is
%%% evidence. The id is derived from the observation, so a redelivery addresses
%%% this same stream and is refused here with the sanctioned no-op `{ok, []}'.
-module(threat_aggregate).
-behaviour(evoq_aggregate).

-export([init/1, execute/2, apply/2, state_module/0, stream_id/1]).

-spec state_module() -> module().
state_module() -> sighting_state.

init(AggregateId) ->
    {ok, sighting_state:new(AggregateId)}.

-spec stream_id(binary()) -> binary().
stream_id(Id) when is_binary(Id) ->
    <<"sight-", Id/binary>>.

execute(#{recorded := true}, #{command_type := <<"report_threat">>}) ->
    {ok, []};
execute(_State, #{command_type := <<"report_threat">>} = Command) ->
    maybe_report_threat:handle(Command);
execute(_State, _Command) ->
    {error, unknown_command}.

apply(State, Event) ->
    sighting_state:apply_event(State, Event).
