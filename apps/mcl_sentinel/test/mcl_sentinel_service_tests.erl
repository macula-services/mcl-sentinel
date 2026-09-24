%% @doc The service contract, asserted locally.
%%
%% mcl_om resolves its six callbacks BY NAME at startup, on a live node, so a
%% service that forgets one dies with `undef' where nobody is watching. The
%% primary defence is the `-behaviour(mcl_om_service)' attribute on the
%% service module, which turns a missing callback into a compile error under
%% warnings_as_errors.
%%
%% What this suite adds is everything the compiler cannot see: that the attribute
%% has not been quietly dropped, that the values inside those callbacks are the
%% shapes mcl_om will destructure, and that the names and version this service
%% reports are the ones it actually has. Nothing local boots mcl_om, so
%% asserting the shape by hand is the closest available thing to a rehearsal.
-module(mcl_sentinel_service_tests).

-include_lib("eunit/include/eunit.hrl").

-define(APP, mcl_sentinel).
-define(SERVICE, mcl_sentinel_service).

%% Belt and braces with the behaviour attribute, and it survives the attribute
%% being removed. If mcl_om ever adds a SEVENTH required callback this test
%% keeps passing and the deploy still breaks, which is the honest limit of a
%% local assertion about a remote contract.
exports_every_required_callback_test() ->
    _ = code:ensure_loaded(?SERVICE),
    Required = [{info, 0}, {start, 1}, {stop, 1},
                {health, 0}, {capabilities, 0}, {identity_spec, 0}],
    Missing = [F || {N, A} = F <- Required,
                    not erlang:function_exported(?SERVICE, N, A)],
    ?assertEqual([], Missing).

info_carries_the_three_keys_test() ->
    #{name := Name, version := Vsn, description := Desc} = ?SERVICE:info(),
    ?assert(is_binary(Name)),
    ?assert(is_binary(Vsn)),
    ?assert(is_binary(Desc)),
    ?assertEqual(<<"mcl-sentinel">>, Name).

%% THE TWO NAMES MUST AGREE. The OTP application is snake_case because it is an
%% Erlang atom; the repository, the container image and the name this service
%% answers to on the mesh are kebab-case. They describe one service, so a
%% scaffold generated with a mismatched pair is caught here on the first eunit
%% run rather than by a puzzled reader months later.
mesh_name_matches_the_application_test() ->
    #{name := Wire} = ?SERVICE:info(),
    Snake = atom_to_binary(?APP, utf8),
    ?assertEqual(binary:replace(Snake, <<"_">>, <<"-">>, [global]), Wire).

%% The version in info/0 is what a peer reads off /health, so it disagreeing with
%% the application it describes is a lie that nothing else would catch.
info_version_matches_the_application_test() ->
    _ = application:load(?APP),
    {ok, Vsn} = application:get_key(?APP, vsn),
    #{version := Reported} = ?SERVICE:info(),
    ?assertEqual(list_to_binary(Vsn), Reported).

%% A sentinel that is not hearing the wardens looks exactly like a quiet night,
%% so health says which it is.
health_is_down_when_the_ingest_is_not_running_test() ->
    ?assertEqual({down, not_hearing_wardens}, ?SERVICE:health()).

health_is_degraded_until_the_wardens_are_subscribed_test() ->
    ?assertEqual({degraded, not_subscribed_to_wardens}, ?SERVICE:hearing(false)),
    ?assertEqual(ok, ?SERVICE:hearing(true)).

%% The sentinel serves nothing callable: its output is its four published facts.
announces_no_capability_test() ->
    ?assertEqual([], ?SERVICE:capabilities()).

identity_spec_has_the_shape_mcl_om_expects_test() ->
    #{scope := Scope, actions := Actions,
      resources := Resources, ttl_days := Ttl} = ?SERVICE:identity_spec(),
    ?assert(is_binary(Scope)),
    ?assert(is_list(Actions)),
    ?assert(is_list(Resources)),
    ?assert(is_integer(Ttl) andalso Ttl > 0).

%% A resource this service is not authorised for is a publish the realm would
%% refuse once UCAN delegation lands. Asking for nothing and claiming nothing
%% must stay in step, so the two are asserted together.
authority_matches_what_is_announced_test() ->
    #{actions := Actions, resources := Resources} = ?SERVICE:identity_spec(),
    ?assertEqual([], ?SERVICE:capabilities()),
    ?assertEqual([], Actions),
    ?assertEqual([], Resources).

%% Three children, in the order they depend on each other: enrichment loads
%% before the read model rebuilds against it, and the read model is up before
%% the ingest folds into it. NO PROJECTION: the read model has one folder (see
%% sentinel_threats), and a projection would fold history a second time on
%% every boot.
supervisor_children_are_enrich_model_ingest_test() ->
    {ok, {_Flags, Children}} = mcl_sentinel_sup:init([]),
    ?assertEqual([sentinel_enrich, sentinel_threats, hear_warden_reports],
                 [Id || #{id := Id} <- Children]).

start_refuses_without_a_realm_name_test() ->
    ok = application:unset_env(?APP, realm_name),
    ?assertError({mcl_sentinel_realm_name_unset, realm_name}, ?SERVICE:start(#{})).

%% The read model rebuilds from the store named in app env, which must be the
%% store mcl_om opens.
the_read_model_reads_the_store_the_service_opens_test() ->
    {ok, [{application, ?APP, Props}]} =
        file:consult(code:where_is_file("mcl_sentinel.app")),
    ?assertEqual(?SERVICE:store_id(),
                 proplists:get_value(event_store_id, proplists:get_value(env, Props))).

%%==============================================================================
%% The config the store cannot boot without
%%==============================================================================

%% ⚠ A SIBLING SERVICE'S FLEET CRASH-LOOPED ON TWO OF THREE NODES FOR WANT OF THE
%% `evoq' BLOCK.
%%
%% Exporting `store_id/0' makes `mcl_om:boot/1' start the store AND a per-store
%% evoq subscription. That subscription reads through evoq, which raises
%% `{not_configured, event_store_adapter}' unless sys.config names the adapter,
%% and evoq starts as a release-boot application before any service's `start/2'
%% runs, so nothing can inject it later.
%%
%% This reads the shipped config template, because the failure is a MISSING BLOCK
%% and no amount of exercising the code can notice something that is not there.
%% It compares the Erlang side of a boundary against the config side, which is
%% what neither side's own tests can do.
the_evoq_adapter_is_configured_wherever_a_store_is_opened_test() ->
    {ok, Text} = file:read_file(alongside("config/sys.config.src")),
    ?assert(erlang:function_exported(?SERVICE, store_id, 0)),
    lists:foreach(
      fun(Needed) ->
              ?assertNotEqual(nomatch, binary:match(Text, Needed),
                              {missing_from_sys_config, Needed})
      end,
      [<<"{evoq,">>, <<"event_store_adapter">>, <<"subscription_adapter">>,
       <<"reckon_evoq_adapter">>]).

%% ⚠ AND THE STORE ID IS IN TWO PLACES, WHICH IS ONE MORE THAN IT SHOULD BE.
%% `store_id/0' is what mcl_om opens; the `{store_id, ...}' in the evoq block
%% is what evoq falls back to when it resolves a dispatch before knowing there is
%% none. Nothing makes them agree, and disagreeing opens one store and addresses
%% another. Same boundary guard, other side.
the_store_id_agrees_between_erlang_and_config_test() ->
    {ok, Text} = file:read_file(alongside("config/sys.config.src")),
    Declared = atom_to_binary(?SERVICE:store_id(), utf8),
    ?assertNotEqual(nomatch, binary:match(Text, Declared),
                    {store_id_not_in_sys_config, Declared}).

%% The data directory must be somewhere, and a laptop default is fine. What is
%% not fine is shipping that default to a node, which is why the generated
%% compose file mounts a volume and sets the variable this reads.
the_data_directory_is_answerable_test() ->
    ?assert(erlang:function_exported(?SERVICE, data_dir, 0)),
    ?assert(is_list(?SERVICE:data_dir())),
    ?assertNotEqual("", ?SERVICE:data_dir()).
%%==============================================================================
%% The runtime is pinned in two places, and neither is the one you are running
%%==============================================================================

%% ⚠ THIS GUARD EXISTS BECAUSE A SIBLING SERVICE DID NOT HAVE IT, AND IT COST
%% THREE COMMITS AND AN IMAGE THAT SHIPPED ANYWAY.
%%
%% Its `Containerfile' said 27 while development ran on 28. So `rebar3 eunit'
%% passing locally meant "passing on 28" and nothing more, CI failed on a crash
%% that does not occur on 28 at all, and because the image build is a separate
%% workflow the image went to the fleet regardless.
%%
%% The release is pinned in TWO files, and the version actually running is a
%% third thing that agrees with neither by default. **A comment in each file
%% saying they must match is not a mechanism**, and both files carried one.
%%
%% ⚠⚠ IT FAILS RATHER THAN WARNS WHEN YOUR VM DIFFERS, AND THAT IS DELIBERATE.
%% Developing on a release you do not ship makes a green suite mean less than it
%% appears to. If you want to work on another release, move both pins and find
%% out what breaks, which is the whole point of having them.
the_runtime_agrees_between_the_image_the_ci_and_this_vm_test() ->
    %% The team images' tags name a date, not a release, so the builder and
    %% lint each assert the release in a check step; this compares those, the
    %% .tool-versions pin and this VM, to the patch.
    Check = "\\{<<\"([0-9]+\\.[0-9]+\\.[0-9]+)\">>, true\\} -> halt\\(0\\);",
    Image = pinned("Containerfile", Check),
    CiCheck = pinned(".github/workflows/lint.yml", Check),
    Tools = pinned(".tool-versions", "^erlang ([0-9]+\\.[0-9]+\\.[0-9]+)$"),
    %% Sorted and deduplicated, so a failure prints every version rather than
    %% the first pair that happened to be compared.
    ?assertEqual([Image], lists:usort([Image, CiCheck, Tools, running_otp()])).

%% Build, CI and runtime are the team pair, named by dated tag AND digest, so a
%% re-pushed tag cannot change what builds or what runs.
images_are_the_digest_pinned_team_pair_test() ->
    Digest = ":[0-9]{8}-[0-9]{4}@sha256:[0-9a-f]{64}",
    ?assertMatch(<<_/binary>>,
                 pinned("Containerfile",
                        "^FROM (ghcr\\.io/macula-io/macula-ci-otp)" ++ Digest ++ " AS builder$")),
    ?assertMatch(<<_/binary>>,
                 pinned("Containerfile",
                        "^FROM (ghcr\\.io/macula-io/macula-pq-runtime)" ++ Digest ++ "$")),
    ?assertMatch(<<_/binary>>,
                 pinned(".github/workflows/lint.yml",
                        "^\\s+image: (ghcr\\.io/macula-io/macula-ci-otp)" ++ Digest ++ "$")).

%% The full release, 28.4.3 and not 28: `otp_release' names only the major.
running_otp() ->
    {ok, Version} = file:read_file(filename:join([code:root_dir(), "releases",
                                                  erlang:system_info(otp_release),
                                                  "OTP_VERSION"])),
    string:trim(Version).

pinned(Relative, Pattern) ->
    {ok, Text} = file:read_file(alongside(Relative)),
    {match, [Version]} = re:run(Text, Pattern,
                                [multiline, {capture, all_but_first, binary}]),
    Version.

%% Relative to the beam rather than the working directory, because eunit runs
%% from wherever the developer happens to be standing.
alongside(Name) -> climb(filename:dirname(code:which(?MODULE)), Name, 8).

climb(_Dir, Name, 0) -> Name;
climb(Dir, Name, Left) ->
    Candidate = filename:join(Dir, Name),
    found(filelib:is_regular(Candidate), Candidate, Dir, Name, Left).

found(true, Candidate, _Dir, _Name, _Left) -> Candidate;
found(false, _Candidate, Dir, Name, Left) ->
    climb(filename:dirname(Dir), Name, Left - 1).

%%==============================================================================
%% The boot claim names the service and its box
%%==============================================================================

%% Every node that claims on the realm shows its service and host on the
%% Providers desk: mcl_om 0.27 reads MCL_SERVICE_NAME and MCL_BOX. The service
%% name is ours; the box is the deploying host's to say.
the_claim_names_the_service_and_its_box_test() ->
    {ok, Text} = file:read_file(alongside("deploy/docker-compose.yml")),
    ?assertMatch({match, _}, re:run(Text, <<"- MCL_SERVICE_NAME=mcl-sentinel\\n">>)),
    ?assertMatch({match, _}, re:run(Text, <<"- MCL_BOX=\\$\\{MCL_BOX:-\\}\\n">>)).

%% ⚠ NOT IN sys.config. mcl_om prefers its app env to the OS variables, so a
%% `service_name' or `box' line there, even an empty one, would hide the two
%% variables above (until mcl_om 0.27.1 treats empty as unset).
the_claim_labels_are_not_shadowed_by_app_env_test() ->
    {ok, Text} = file:read_file(alongside("config/sys.config.src")),
    ?assertEqual(nomatch, re:run(Text, <<"^\\s*\\{(service_name|box),">>, [multiline])).

%% The image says which commit IT was built from. Without its own label it
%% inherited the base image's (macula-ci-images' own commit), which names the
%% wrong repository; build-push passes the sha, the runtime stage labels it.
the_image_carries_its_revision_test() ->
    ?assertEqual(<<"REVISION">>, pinned("Containerfile", "^ARG (REVISION)=unknown$")),
    ?assertEqual(<<"${REVISION}">>,
                 pinned("Containerfile",
                        "^LABEL org\\.opencontainers\\.image\\.revision=\"([^\"]+)\"$")),
    ?assertEqual(<<"${{ github.sha }}">>,
                 pinned(".github/workflows/build-push.yml", "^\\s+REVISION=(.+)$")).

