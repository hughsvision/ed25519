-module(ed25519).

-export([keypair/0,
	 public_key/1]).

-type signature() :: binary().
-type secret() :: binary().
-type public() :: binary().
-on_load(init/0).

-define(APPNAME, ed25519).
-define(LIBNAME, ed25519).

-spec keypair() -> {ok, secret(), public()} | {error, atom()}.
keypair() ->
	"NIF library not loaded".

-spec public_key(secret()) -> {ok, public()} | {error, atom()}.
public_key(_Secret) -> 
	"NIF library not loaded".

init() ->
	SoName = case code:priv_dir(?APPNAME) of
			 {error, bad_name} ->
				 case filelib:is_dir(filename:join(["..", priv])) of
					 true ->
						 filename:join(["..", priv, ?LIBNAME]);
					 _ ->
						 filename:join([priv, ?LIBNAME])
				 end;
			 Dir ->
				 filename:join(Dir, ?LIBNAME)
		 end,
	erlang:load_nif(SoName, 0).




