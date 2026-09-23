%%% @doc The threat read model: who is attacking the commons, and from where.
%%%
%%% Owns the public ETS table `threats', keyed by source address. Each row
%%% aggregates every warden that has seen that address, keyed by the warden's
%%% verified id: attempts, usernames tried, when, and how long it was held in a
%%% tarpit. An address seen by two or more wardens is a campaign, and
%%% `record_sighting/1' says so on exactly the sighting that makes it one.
%%%
%%% ONE FOLDER. The model is rebuilt from the threat_sighted_v1 log once, in
%%% init/1, and after that folded only by the live ingest, after a sighting is
%%% recorded. There is deliberately no projection: evoq's store subscription
%%% replays the whole log to every handler on each boot with nothing marking it
%%% as a replay, so a projection would fold history a second time (hecate-sentinel
%%% counted every historical attempt again on every restart) and would announce
%%% every old campaign again as if it were new.
-module(sentinel_threats).
-behaviour(gen_server).

-export([start_link/0, record_sighting/1, record_ensnared/2, rebuild/2,
         get/1, all/0, cross_border/0, count/0]).
-export([replay_status/2]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(TABLE, threats).
%% A CAP on the boot read, not a page size: the store API takes a batch size
%% with no offset, so anything beyond it is not read. Truncation is logged.
-define(REPLAY_LIMIT, 50000).
-define(MAX_USERNAMES, 40).

-spec start_link() -> {ok, pid()} | {error, term()}.
start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Fold one recorded sighting in. `crossed_border' when this sighting is
%% the one that made the address a campaign (its second warden), else `noted'.
-spec record_sighting(map()) -> crossed_border | noted.
record_sighting(Sighting) ->
    gen_server:call(?MODULE, {sighting, Sighting}).

-spec record_ensnared(binary(), non_neg_integer()) -> ok.
record_ensnared(Ip, HeldMs) ->
    gen_server:call(?MODULE, {ensnared, Ip, HeldMs}).

%% @doc Fold a list of stored threat_sighted_v1 events. What init/1 does with
%% the log; exported so the fold can be tested without a store.
-spec rebuild(pid() | atom(), [map()]) -> ok.
rebuild(Server, Events) ->
    gen_server:call(Server, {rebuild, Events}, infinity).

-spec get(binary()) -> {ok, map()} | {error, not_found}.
get(Ip) ->
    found(ets:lookup(?TABLE, Ip)).

found([{_, Row}]) -> {ok, Row};
found([])         -> {error, not_found}.

-spec all() -> [map()].
all() ->
    [Row || {_Ip, Row} <- ets:tab2list(?TABLE)].

%% @doc The addresses seen by two or more wardens: the campaigns.
-spec cross_border() -> [map()].
cross_border() ->
    [Row || Row <- all(), map_size(maps:get(wardens, Row, #{})) >= 2].

-spec count() -> non_neg_integer().
count() ->
    ets:info(?TABLE, size).

%%------------------------------------------------------------------------------
%% gen_server
%%------------------------------------------------------------------------------

init([]) ->
    ?TABLE = ets:new(?TABLE, [set, protected, named_table, {read_concurrency, true}]),
    {Status, Events} = read_log(),
    fold_all(Events),
    log_rebuild(Status, length(Events), count()),
    {ok, #{}}.

handle_call({sighting, Sighting}, _From, S) ->
    {reply, fold_sighting(row(Sighting)), S};
handle_call({ensnared, Ip, HeldMs}, _From, S) ->
    {reply, fold_ensnared(Ip, HeldMs), S};
handle_call({rebuild, Events}, _From, S) ->
    {reply, fold_all(Events), S};
handle_call(_Req, _From, S) ->
    {reply, {error, unknown_call}, S}.

handle_cast(_Msg, S) -> {noreply, S}.
handle_info(_Info, S) -> {noreply, S}.
terminate(_Reason, _S) -> ok.

%%------------------------------------------------------------------------------
%% Folding
%%------------------------------------------------------------------------------

fold_all(Events) ->
    lists:foreach(fun(E) -> fold_sighting(row(E)) end, Events).

%% The fields a sighting or a stored event contributes, in one shape. A stored
%% event is flattened by evoq, so its data sits at the top level.
row(Data) ->
    #{source_ip => field(source_ip, Data),
      warden_id => field(warden_id, Data),
      label     => field(label, Data),
      attempts  => integer(field(attempts, Data), 1),
      usernames => texts(field(usernames, Data)),
      at_ms     => integer(field(at_ms, Data), erlang:system_time(millisecond))}.

fold_sighting(#{source_ip := Ip, warden_id := Warden} = In)
  when is_binary(Ip), is_binary(Warden) ->
    Before = existing(Ip),
    Merged = merge(Before, Warden, In),
    true = ets:insert(?TABLE, {Ip, Merged}),
    became_wide(wide(Before), wide(Merged));
fold_sighting(_Unattributed) ->
    noted.

wide(Row) -> map_size(maps:get(wardens, Row, #{})) >= 2.

became_wide(false, true) -> crossed_border;
became_wide(_, _)        -> noted.

fold_ensnared(Ip, HeldMs) when is_binary(Ip), is_integer(HeldMs) ->
    Row = existing(Ip),
    true = ets:insert(?TABLE, {Ip, Row#{held_ms => maps:get(held_ms, Row, 0) + HeldMs}}),
    ok;
fold_ensnared(_Ip, _HeldMs) ->
    ok.

existing(Ip) ->
    stored(ets:lookup(?TABLE, Ip), Ip).

%% First sight of an address: enrich it once with where it is. Enrichment is
%% additive; a missing database leaves `geo' empty.
stored([{_, Row}], _Ip) -> Row;
stored([], Ip) ->
    #{source_ip => Ip, wardens => #{}, total_attempts => 0, usernames => [],
      first_seen => undefined, last_seen => 0, held_ms => 0,
      geo => sentinel_enrich:lookup(Ip)}.

merge(Row, Warden, #{attempts := Attempts, usernames := Users, at_ms := At} = In) ->
    Entry = labelled(#{attempts => Attempts, last_seen => At, usernames => Users},
                     maps:get(label, In, undefined)),
    Row#{wardens => maps:put(Warden, Entry, maps:get(wardens, Row, #{})),
         total_attempts => maps:get(total_attempts, Row, 0) + Attempts,
         usernames => union(maps:get(usernames, Row, []), Users),
         first_seen => first_seen(maps:get(first_seen, Row, undefined), At),
         last_seen => max(maps:get(last_seen, Row, 0), At)}.

labelled(Entry, Label) when is_binary(Label) -> Entry#{label => Label};
labelled(Entry, _Label)                      -> Entry.

first_seen(undefined, At) -> At;
first_seen(Prev, At)      -> min(Prev, At).

union(A, B) -> lists:sublist(lists:usort(A ++ B), ?MAX_USERNAMES).

field(K, M) -> maps:get(K, M, maps:get(atom_to_binary(K, utf8), M, undefined)).

integer(N, _Default) when is_integer(N) -> N;
integer(_, Default)                     -> Default.

texts(L) when is_list(L) -> [U || U <- L, is_binary(U)];
texts(_)                 -> [].

%%------------------------------------------------------------------------------
%% The boot read
%%------------------------------------------------------------------------------

read_log() ->
    read_from(application:get_env(mcl_sentinel, event_store_id)).

read_from({ok, StoreId}) ->
    Limit = application:get_env(mcl_sentinel, replay_limit, ?REPLAY_LIMIT),
    replay_status(read_events(StoreId, Limit), Limit);
read_from(undefined) ->
    {{failed, no_event_store_configured}, []}.

read_events(StoreId, Limit) ->
    try evoq_event_store:read_events_by_types(StoreId, [<<"threat_sighted_v1">>], Limit)
    catch Class:Reason -> {error, {Class, Reason}}
    end.

%% @doc Classify a replay read. A truncated read misses the oldest history, so
%% an address whose only earlier sighting fell off looks new and can raise a
%% false campaign; a failed read rebuilds the model empty. Both are said.
-spec replay_status(term(), pos_integer()) ->
    {complete | truncated | {failed, term()}, [map()]}.
replay_status({ok, Events}, Limit) when is_list(Events), length(Events) >= Limit ->
    {truncated, Events};
replay_status({ok, Events}, _Limit) when is_list(Events) ->
    {complete, Events};
replay_status(Other, _Limit) ->
    {{failed, Other}, []}.

log_rebuild(complete, Events, Ips) ->
    logger:info("[sentinel] threat model rebuilt from the log: ~b events, ~b addresses",
                [Events, Ips]);
log_rebuild(truncated, Events, Ips) ->
    logger:warning("[sentinel] threat model rebuilt from a TRUNCATED read: ~b events "
                   "(the limit), ~b addresses. Older history is missing, so an address "
                   "may look new and raise a false campaign. Raise mcl_sentinel "
                   "replay_limit.", [Events, Ips]);
log_rebuild({failed, Reason}, _Events, _Ips) ->
    logger:error("[sentinel] threat model rebuild FAILED, the model is EMPTY: ~p", [Reason]).
