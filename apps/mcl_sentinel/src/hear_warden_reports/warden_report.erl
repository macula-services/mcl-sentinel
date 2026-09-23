%%% @doc Which warden a report comes from, and whether it is a report at all.
%%%
%%% A report is taken only when macula verified its publisher and that publisher
%%% is one of the wardens this sentinel is configured with. The warden contract
%%% carries no sender field, and anything in the payload that claims one is
%%% ignored: `warden_id' is always the verified publisher, upper-case hex.
%%%
%%% The list comes from our own inventory (each warden's stored node id), never
%%% from mesh or DHT records. A sentinel with no valid list refuses to start: it
%%% would otherwise record nothing, or record anyone.
%%%
%%% An accepted report is normalised to atom keys and checked against what its
%%% fact requires, so every later step reads one shape. macula decodes a key to
%%% an atom only when that atom already exists and otherwise leaves `{text, Name}',
%%% so each field is read under all three spellings.
-module(warden_report).

-export([wardens/0, parse_wardens/1, attribute/4]).

-type hex() :: binary().
-type refusal() :: malformed_fact | unverified_publisher | unlisted_warden.
-export_type([refusal/0]).

-define(HEX64, "^[0-9A-F]{64}$").
-define(SEPARATORS, [$,, $\s, $\t, $\n, $\r, "\r\n"]).

%% @doc The configured wardens. Raises when the setting is missing, empty or
%% malformed, so the process that asks for it at boot cannot start.
-spec wardens() -> [hex()].
wardens() ->
    configured(parse_wardens(application:get_env(mcl_sentinel, wardens, undefined))).

configured({ok, Wardens})   -> Wardens;
configured({error, Reason}) -> erlang:error({invalid_sentinel_wardens, Reason}).

%% @doc Node ids as 64 hex characters, separated by commas or white space, in
%% either case. Returned upper-case and sorted.
-spec parse_wardens(term()) ->
    {ok, [hex()]} | {error, missing | malformed | empty | {not_64_hex, binary()}}.
parse_wardens(undefined) ->
    {error, missing};
parse_wardens(Value) when is_list(Value) ->
    parse_wardens(unicode:characters_to_binary(Value));
parse_wardens(Value) when is_binary(Value) ->
    checked([string:uppercase(E) || E <- string:lexemes(Value, ?SEPARATORS)]);
parse_wardens(_Other) ->
    {error, malformed}.

checked([])      -> {error, empty};
checked(Entries) -> malformed(lists:filter(fun not_hex64/1, Entries), Entries).

malformed([], Entries)         -> {ok, lists:usort(Entries)};
malformed([Bad | _], _Entries) -> {error, {not_64_hex, Bad}}.

not_hex64(Entry) -> re:run(Entry, ?HEX64) =:= nomatch.

%% @doc Attribute one report to its verified publisher and normalise it, or
%% refuse it. `Meta' is the delivery metadata macula hands a subscriber.
-spec attribute(mcl_sentinel_facts:warden_fact(), term(), term(), [hex()]) ->
    {ok, map()} | {refused, refusal()}.
attribute(Kind, Fact, #{publisher := <<_:256>> = Publisher, publisher_verified := true},
          Wardens) when is_map(Fact) ->
    Hex = binary:encode_hex(Publisher),
    listed(lists:member(Hex, Wardens), Hex, Kind, Fact);
attribute(_Kind, Fact, _Meta, _Wardens) when is_map(Fact) ->
    {refused, unverified_publisher};
attribute(_Kind, _Fact, _Meta, _Wardens) ->
    {refused, malformed_fact}.

listed(true, Hex, Kind, Fact) -> normalised(fields(Kind, Fact), Hex);
listed(false, _Hex, _Kind, _Fact) -> {refused, unlisted_warden}.

normalised({ok, Report}, Hex) -> {ok, Report#{warden_id => Hex}};
normalised(error, _Hex)       -> {refused, malformed_fact}.

%%------------------------------------------------------------------------------
%% What each fact must carry
%%------------------------------------------------------------------------------

fields(attacker_sighted, Fact) ->
    collect(Fact, [{source_ip, ip}, {service, text}, {attempts, int},
                   {window_s, int}, {usernames, texts}, {at_ms, int}]);
fields(attacker_ensnared, Fact) ->
    collect(Fact, [{source_ip, ip}, {held_ms, int}, {at_ms, int}]).

%% Required fields must all be present and well typed. `label' and
%% `tenant_id' are optional, and dropped when they are not text.
collect(Fact, Required) ->
    Values = [{Key, typed(Type, read(Key, Fact))} || {Key, Type} <- Required],
    complete(lists:keymember(error, 2, Values), Values, optional(Fact)).

complete(true, _Values, _Optional) -> error;
complete(false, Values, Optional)  -> {ok, maps:merge(Optional, maps:from_list(Values))}.

optional(Fact) ->
    maps:from_list([{Key, V} || Key <- [label, tenant_id],
                                V <- [typed(text, read(Key, Fact))], V =/= error]).

read(Key, Fact) ->
    Name = atom_to_binary(Key, utf8),
    first([maps:find(K, Fact) || K <- [Key, Name, {text, Name}]]).

first([{ok, V} | _]) -> V;
first([error | T])   -> first(T);
first([])            -> undefined.

typed(int, I) when is_integer(I) -> I;
typed(text, T) -> text(T);
typed(texts, L) when is_list(L) -> all_text([text(T) || T <- L]);
typed(ip, T) -> address(text(T));
typed(_Type, _Value) -> error.

text({text, B}) when is_binary(B) -> text(B);
text(<<>>) -> error;
text(B) when is_binary(B) -> B;
text(_) -> error.

all_text(L) -> all_text(lists:member(error, L), L).

all_text(true, _L) -> error;
all_text(false, L) -> L.

address(error) -> error;
address(B) -> parsed(inet:parse_strict_address(binary_to_list(B)), B).

parsed({ok, _Ip}, B)   -> B;
parsed({error, _}, _B) -> error.
