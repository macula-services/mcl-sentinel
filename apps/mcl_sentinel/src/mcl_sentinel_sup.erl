%% @doc Supervises the sentinel, in dependency order.
%%
%% Enrichment loads its databases before the read model rebuilds against them,
%% and the read model is up before the ingest folds into it. There is no
%% projection: the read model has exactly one folder (see sentinel_threats).
-module(mcl_sentinel_sup).

-behaviour(supervisor).

-export([start_link/0, init/1]).

start_link() -> supervisor:start_link({local, ?MODULE}, ?MODULE, []).

init([]) ->
    {ok, {#{strategy => rest_for_one, intensity => 5, period => 10},
          [worker(sentinel_enrich),
           worker(sentinel_threats),
           worker(hear_warden_reports)]}}.

worker(Module) ->
    #{id => Module,
      start => {Module, start_link, []},
      restart => permanent,
      shutdown => 5000,
      type => worker,
      modules => [Module]}.
