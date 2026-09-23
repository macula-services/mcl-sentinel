%%% @doc Hears the wardens, and says what it heard.
%%%
%%% Subscribes to mcl-warden's `attacker_sighted' and `attacker_ensnared'. A
%%% report counts only when warden_report attributes it to a configured warden
%%% by its verified publisher; anything else is counted as refused and logged
%%% once per heartbeat, never per report.
%%%
%%% A sighting is dispatched as report_threat_v1 and recorded as
%%% threat_sighted_v1, the evidence chain. Only a sighting that was actually
%%% recorded (not a redelivery the aggregate refused, not a failed write) is
%%% folded into the read model and published as `attacker_sighted', stamped
%%% {epoch, seq}. If that fold makes the address a campaign, `campaign_detected'
%%% follows. This is the ONLY place the read model is folded after boot, and the
%%% only place facts are published, so nothing is announced twice.
%%%
%%% `epoch' is set once per boot and `seq' counts recorded sightings within it,
%%% so a consumer that sees the epoch change knows no continuity is claimed
%%% across the restart. The heartbeat carries the current stamp, which turns a
%%% deaf subscription into a detectably deaf one within one interval.
%%%
%%% Re-subscribes when a subscription goes away. Degrades while the mesh is dark.
-module(hear_warden_reports).
-behaviour(gen_server).

-export([start_link/0, subscribed/0, seq/1, refused/1, refs/1, is_subscribed/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(RESUBSCRIBE_MS, 5000).

-record(st, {topics :: #{binary() => mcl_sentinel_facts:warden_fact()},
             %% One subscription per topic, held until macula says it is gone.
             refs = #{} :: #{reference() => binary()},
             wardens :: [binary()],
             epoch :: integer(),
             seq = 0 :: non_neg_integer(),
             refused = #{} :: #{warden_report:refusal() => pos_integer()}}).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Whether both warden subscriptions are held.
-spec subscribed() -> boolean().
subscribed() ->
    gen_server:call(?MODULE, subscribed, 1000).

%% @doc The subscriptions held, as {Ref, Topic}. For tests.
refs(#st{refs = Refs}) -> maps:to_list(Refs).

%% @doc Whether every warden topic is subscribed.
is_subscribed(#st{topics = Topics, refs = Refs}) ->
    map_size(Refs) =:= map_size(Topics).

%% @doc Recorded sightings this boot. For tests.
seq(#st{seq = Seq}) -> Seq.

%% @doc Refusals since the last heartbeat, by reason. For tests.
refused(#st{refused = Refused}) -> Refused.

%% The warden list is read first: without a valid one this raises and the node
%% does not boot.
init([]) ->
    Wardens = warden_report:wardens(),
    Realm = mcl_sentinel_facts:realm_name(),
    Topics = #{mcl_sentinel_facts:warden_topic(Realm, F) => F
               || F <- [attacker_sighted, attacker_ensnared]},
    self() ! subscribe,
    erlang:send_after(mcl_sentinel_facts:check_in_interval_ms(), self(), check_in),
    {ok, #st{topics = Topics, wardens = Wardens,
             epoch = erlang:system_time(microsecond)}}.

handle_call(subscribed, _From, St) ->
    {reply, is_subscribed(St), St};
handle_call(_Req, _From, St) ->
    {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.

handle_info(subscribe, St) ->
    {noreply, subscribe(mcl_om:mesh_handles(), St)};
handle_info({macula_event, _Ref, Topic, Fact, Meta}, #st{topics = Topics} = St) ->
    {noreply, heard(maps:find(Topic, Topics), Fact, Meta, St)};
handle_info({macula_event_gone, Ref, _Reason}, #st{refs = Refs} = St) ->
    self() ! subscribe,
    {noreply, St#st{refs = maps:remove(Ref, Refs)}};
handle_info(check_in, St) ->
    mcl_sentinel_facts:publish(sentinel_checked_in,
                               mcl_sentinel_facts:sentinel_checked_in(stamp(St), now_ms())),
    erlang:send_after(mcl_sentinel_facts:check_in_interval_ms(), self(), check_in),
    {noreply, report_refusals(St)};
handle_info(_Info, St) ->
    {noreply, St}.

terminate(_Reason, _St) -> ok.

%%------------------------------------------------------------------------------
%% Subscribing
%%------------------------------------------------------------------------------

%% Only the topics not already held are subscribed: subscribing a held one
%% again would deliver its facts twice, and an ensnarement is not deduplicated.
subscribe({ok, Pool, Realm}, #st{topics = Topics, refs = Refs} = St) ->
    Missing = maps:keys(Topics) -- maps:values(Refs),
    Held = lists:foldl(fun(Topic, Acc) ->
                               held(macula:subscribe(Pool, Realm, Topic, self()), Topic, Acc)
                       end, Refs, Missing),
    retry_unless_complete(St#st{refs = Held});
subscribe({error, mesh_unavailable}, St) ->
    retry_unless_complete(St).

held({ok, Ref}, Topic, Refs) ->
    Refs#{Ref => Topic};
held(Error, Topic, Refs) ->
    logger:warning("[sentinel] subscribing to ~s failed, retrying: ~p", [Topic, Error]),
    Refs.

%% A subscription that failed leaves the sentinel deaf to part of what the
%% wardens say, for good, unless it is retried. So it is.
retry_unless_complete(St) ->
    retried(is_subscribed(St)),
    St.

retried(true)  -> ok;
retried(false) -> erlang:send_after(?RESUBSCRIBE_MS, self(), subscribe), ok.

%%------------------------------------------------------------------------------
%% Hearing
%%------------------------------------------------------------------------------

heard({ok, Kind}, Fact, Meta, #st{wardens = Wardens} = St) ->
    attributed(warden_report:attribute(Kind, Fact, Meta, Wardens), Kind, St);
heard(error, _Fact, _Meta, St) ->
    St.

attributed({ok, Report}, attacker_sighted, St) ->
    sighted(Report, St);
attributed({ok, #{source_ip := Ip, held_ms := HeldMs} = Report}, attacker_ensnared, St) ->
    ok = sentinel_threats:record_ensnared(Ip, HeldMs),
    mcl_sentinel_facts:publish(attacker_ensnared,
                               mcl_sentinel_facts:attacker_ensnared(Report, sentinel_enrich:lookup(Ip))),
    St;
attributed({refused, Reason}, _Kind, #st{refused = Refused} = St) ->
    St#st{refused = maps:update_with(Reason, fun(N) -> N + 1 end, 1, Refused)}.

sighted(#{source_ip := Ip, warden_id := Warden, service := Service, at_ms := At} = Report, St) ->
    Id = maybe_report_threat:sighting_id(Ip, Warden, Service, At),
    {ok, Cmd} = report_threat_v1:new(Id, Report),
    recorded(outcome(maybe_report_threat:dispatch(Cmd)), Id, Report, St).

outcome({ok, _Version, [_ | _]}) -> recorded;
outcome({ok, _Version, []})      -> duplicate;
outcome(Other)                   -> {failed, Other}.

recorded(recorded, Id, #{source_ip := Ip} = Report, #st{seq = Seq} = St) ->
    St1 = St#st{seq = Seq + 1},
    Crossed = sentinel_threats:record_sighting(Report),
    mcl_sentinel_facts:publish(attacker_sighted,
                               mcl_sentinel_facts:attacker_sighted(
                                 Id, Report, sentinel_enrich:lookup(Ip), stamp(St1))),
    campaign(Crossed, Ip),
    St1;
recorded(duplicate, _Id, _Report, St) ->
    St;
%% Evidence we could not write is evidence we do not hold, so it is not
%% announced: a fact no replay could reproduce would split consumers for good.
recorded({failed, Reason}, _Id, _Report, St) ->
    logger:warning("[sentinel] sighting NOT recorded, not published: ~p", [Reason]),
    St.

campaign(crossed_border, Ip) ->
    announced(sentinel_threats:get(Ip));
campaign(noted, _Ip) ->
    ok.

announced({ok, Row}) ->
    mcl_sentinel_facts:publish(campaign_detected,
                               mcl_sentinel_facts:campaign_detected(
                                 Row, maps:get(geo, Row, #{}), now_ms()));
announced({error, not_found}) ->
    ok.

report_refusals(#st{refused = Refused} = St) when map_size(Refused) =:= 0 ->
    St;
report_refusals(#st{refused = Refused} = St) ->
    logger:warning("[sentinel] warden reports refused since the last heartbeat: ~p", [Refused]),
    St#st{refused = #{}}.

stamp(#st{epoch = Epoch, seq = Seq}) -> {Epoch, Seq}.

now_ms() -> erlang:system_time(millisecond).
