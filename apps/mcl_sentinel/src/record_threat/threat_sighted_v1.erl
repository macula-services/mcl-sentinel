%%% @doc threat_sighted_v1: an attacker was seen by a warden, and it is now on
%%% the record. Immutable, timestamped, attributed to the warden that signed the
%%% report. It is what an abuse report is built from.
-module(threat_sighted_v1).
-behaviour(evoq_event).

-export([new/1, to_map/1, from_map/1, event_type/0]).

event_type() -> <<"threat_sighted_v1">>.

-spec new(map()) -> map().
new(Command) ->
    (maps:remove(command_type, Command))#{event_type => event_type()}.

-spec to_map(map()) -> map().
to_map(M) -> M.

-spec from_map(map()) -> {ok, map()} | {error, term()}.
from_map(#{sighting_id := _, source_ip := _, warden_id := _} = M) -> {ok, M};
from_map(_) -> {error, invalid_threat_sighted_event}.
