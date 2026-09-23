%%% @doc report_threat_v1: an attributed warden sighting, to be put on the record.
-module(report_threat_v1).
-behaviour(evoq_command).

-export([new/1, new/2, to_map/1, from_map/1, command_type/0]).

-record(report_threat_v1, {sighting_id :: binary(),
                           report      :: map()}).

-opaque report_threat_v1() :: #report_threat_v1{}.
-export_type([report_threat_v1/0]).

%% The evidence a sighting carries. `label' and `tenant_id' are kept when the
%% warden said them, and absent otherwise.
-define(REQUIRED, [warden_id, source_ip, service, attempts, window_s, usernames, at_ms]).
-define(OPTIONAL, [label, tenant_id]).

command_type() -> report_threat.

%% @doc From a map that names its sighting id.
-spec new(map()) -> {ok, report_threat_v1()} | {error, term()}.
new(#{sighting_id := Id} = M) -> new(Id, M);
new(_)                        -> {error, missing_fields}.

%% @doc From an attributed report (warden_report:attribute/4).
-spec new(binary(), map()) -> {ok, report_threat_v1()} | {error, missing_fields}.
new(SightingId, Report) when is_binary(SightingId) ->
    complete(lists:all(fun(K) -> maps:is_key(K, Report) end, ?REQUIRED),
             SightingId, Report).

complete(true, Id, Report) ->
    {ok, #report_threat_v1{sighting_id = Id,
                           report = maps:with(?REQUIRED ++ ?OPTIONAL, Report)}};
complete(false, _Id, _Report) ->
    {error, missing_fields}.

-spec to_map(report_threat_v1()) -> map().
to_map(#report_threat_v1{sighting_id = Id, report = Report}) ->
    Report#{command_type => <<"report_threat">>, sighting_id => Id}.

-spec from_map(map()) -> {ok, report_threat_v1()} | {error, term()}.
from_map(M) -> new(M).
