%%% @doc Handler for report_threat_v1: an address, and nothing else, goes on
%%% the record. Also where a sighting's identity is derived.
-module(maybe_report_threat).

-export([handle/1, dispatch/1, sighting_id/4]).

-dialyzer({nowarn_function, [dispatch/1]}).

-define(STORE_ID, mcl_sentinel_store).

-spec handle(map()) -> {ok, [map()]} | {error, term()}.
handle(#{source_ip := Ip} = Command) ->
    emitted(valid_ip(Ip), Command).

emitted(ok, Command)       -> {ok, [threat_sighted_v1:new(Command)]};
emitted(Error, _Command)   -> Error.

valid_ip(Ip) when is_binary(Ip) ->
    parsed(inet:parse_strict_address(binary_to_list(Ip)));
valid_ip(_) ->
    {error, not_an_ip}.

parsed({ok, _})    -> ok;
parsed({error, _}) -> {error, not_an_ip}.

%% @doc Record one sighting. `{ok, _, []}' means the stream already holds it.
-spec dispatch(report_threat_v1:report_threat_v1()) ->
    {ok, non_neg_integer(), [map()]} | {error, term()}.
dispatch(Cmd) ->
    #{sighting_id := Id} = CmdMap = report_threat_v1:to_map(Cmd),
    EvoqCmd = evoq_command:new(report_threat, threat_aggregate,
                               threat_aggregate:stream_id(Id), CmdMap,
                               #{timestamp => erlang:system_time(millisecond)}),
    evoq_command_router:dispatch(EvoqCmd, #{store_id => ?STORE_ID,
                                            adapter => reckon_evoq_adapter,
                                            consistency => eventual}).

%% @doc The identity of a sighting is the OBSERVATION: which warden saw which
%% address, on which service, at the warden's own timestamp. A redelivery and a
%% store replay both land on the same stream. The label is not part of it: it
%% is what a warden says about itself, and relabelling a box does not make its
%% sightings new.
-spec sighting_id(binary(), binary(), binary(), integer()) -> binary().
sighting_id(Ip, WardenId, Service, AtMs) ->
    Material = [Ip, 0, WardenId, 0, Service, 0, integer_to_binary(AtMs)],
    <<Id:16/binary, _/binary>> = crypto:hash(sha256, Material),
    binary:encode_hex(Id, lowercase).
