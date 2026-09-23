%%% @doc State of one sighting stream: whether its one event is recorded, which
%%% is what lets threat_aggregate refuse a redelivered observation.
-module(sighting_state).
-behaviour(evoq_state).

-export([new/1, apply_event/2, to_map/1]).

new(_AggregateId) -> #{}.

apply_event(State, _Event) -> State#{recorded => true}.

to_map(State) -> State.
