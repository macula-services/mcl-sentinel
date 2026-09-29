%% @doc OTP application entry.
%%
%% Opens this service's own reckon-db store and its evoq subscription
%% (mcl_sentinel_store, from mcl_sentinel_service:event_store/0), THEN lets
%% mcl_om:boot/1 wire the mesh, the realm identity and health and start the
%% service, so the campaign desks and the read model find the store up. mcl_om
%% opens no store (0.35, mcl-om#10).
-module(mcl_sentinel_app).

-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
    ok = mcl_sentinel_store:open(mcl_sentinel_service:event_store()),
    mcl_om:boot(mcl_sentinel_service).

stop(_State) -> ok.
