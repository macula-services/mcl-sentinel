%%% @doc Attacker enrichment: where an address is and what network it is on,
%%% from the DB-IP Lite City and ASN databases (MaxMind DB format, read with
%%% locus). IP geolocation by DB-IP (https://db-ip.com), CC BY 4.0.
%%%
%%% The network often says more than the country: a hosting ASN is a rented or
%%% compromised server built to attack, an ISP ASN more likely a compromised
%%% home device.
%%%
%%% The databases are MOUNTED, and optional. scripts/fetch-dbip-lite.sh fetches
%%% the monthly release. Absent, `lookup/1' answers an empty map and everything
%%% else carries on: enrichment is additive, never load-bearing.
-module(sentinel_enrich).
-behaviour(gen_server).

-export([start_link/0, lookup/1]).
-export([geo/2, net_type/1]).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2]).

-define(CITY, dbip_city).
-define(ASN, dbip_asn).
-define(LOAD_TIMEOUT_MS, 60000).

start_link() ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [], []).

%% @doc Country, city, coordinates, ASN and network type for an address. Empty
%% when the databases are not loaded or do not know it.
-spec lookup(binary()) -> map().
lookup(Ip) when is_binary(Ip) ->
    geo(entry(?CITY, Ip), entry(?ASN, Ip));
lookup(_) ->
    #{}.

%% Loaded synchronously here, so the read model's boot rebuild, which starts
%% after this, enriches against a loaded database instead of racing it.
init([]) ->
    load(?CITY, application:get_env(mcl_sentinel, geoip_city_db, undefined)),
    load(?ASN, application:get_env(mcl_sentinel, geoip_asn_db, undefined)),
    {ok, #{}}.

handle_call(_Req, _From, St) -> {reply, {error, unknown_call}, St}.
handle_cast(_Msg, St)        -> {noreply, St}.
handle_info(_Info, St)       -> {noreply, St}.
terminate(_Reason, _St)      -> ok.

%%------------------------------------------------------------------------------

load(_Id, undefined) ->
    ok;
load(Id, Path) ->
    load_if(filelib:is_regular(Path), Id, Path).

load_if(false, Id, Path) ->
    logger:warning("[sentinel] ~p not found at ~s: enrichment off for it", [Id, Path]);
load_if(true, Id, Path) ->
    started(locus:start_loader(Id, Path), Id).

started(ok, Id) ->
    loaded(locus:await_loader(Id, ?LOAD_TIMEOUT_MS), Id);
started(Other, Id) ->
    logger:warning("[sentinel] ~p loader: ~p", [Id, Other]).

loaded({ok, _}, Id)  -> logger:info("[sentinel] ~p loaded", [Id]);
loaded(Other, Id)    -> logger:warning("[sentinel] ~p did not load: ~p", [Id, Other]).

entry(Id, Ip) ->
    try locus:lookup(Id, Ip) of
        {ok, Entry} when is_map(Entry) -> Entry;
        _NotFound -> #{}
    catch _:_ -> #{}
    end.

%% @doc Flatten a city and an ASN entry into the fields a fact carries.
-spec geo(map(), map()) -> map().
geo(City, Asn) ->
    Org = path(Asn, [<<"autonomous_system_organization">>]),
    Fields = [{country_iso, path(City, [<<"country">>, <<"iso_code">>])},
              {country, path(City, [<<"country">>, <<"names">>, <<"en">>])},
              {city, path(City, [<<"city">>, <<"names">>, <<"en">>])},
              {lat, path(City, [<<"location">>, <<"latitude">>])},
              {lng, path(City, [<<"location">>, <<"longitude">>])},
              {asn, path(Asn, [<<"autonomous_system_number">>])},
              {asn_org, Org},
              {net_type, net_type(Org)}],
    maps:from_list([{K, V} || {K, V} <- Fields, V =/= undefined]).

%% @doc A best-effort class from the ASN organisation's name: `hosting',
%% `isp' or `unknown'. A heuristic on the name, not a database field.
-spec net_type(binary() | undefined) -> binary() | undefined.
net_type(Org) when is_binary(Org) -> classify(string:lowercase(Org));
net_type(_)                       -> undefined.

classify(L) ->
    class(contains_any(L, hosting_terms()), contains_any(L, isp_terms())).

class(true, _)      -> <<"hosting">>;
class(false, true)  -> <<"isp">>;
class(false, false) -> <<"unknown">>.

contains_any(L, Terms) ->
    lists:any(fun(T) -> string:find(L, T) =/= nomatch end, Terms).

hosting_terms() ->
    ["host", "cloud", "server", "datacenter", "data center", "colo", "vps",
     "ovh", "digitalocean", "amazon", "aws", "google", "azure", "microsoft",
     "alibaba", "hetzner", "linode", "vultr", "contabo", "leaseweb", "m247",
     "choopa", "unmanaged", "bulletproof", "technolog"].

isp_terms() ->
    ["telecom", "telekom", "communication", "broadband", "cable", "mobile",
     "wireless", "telefonica", "vodafone", "airtel", "comcast", "orange", "isp",
     "internet servic", "dsl", "fiber", "viettel", "mobifone"].

path(Map, [K | Rest]) when is_map(Map) -> path(maps:get(K, Map, undefined), Rest);
path(Value, [])                        -> Value;
path(_NotAMap, _Keys)                  -> undefined.
