#include "ed25519.h"
#include "erl_nif.h"
#include "erl_nif_compat.h"
// prototypes
ERL_NIF_TERM ed25519_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM ed25519_derive_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_update(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_final(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
//ERL_NIF_TERM ed25519_hash(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]);
ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error);

// lifecycle
int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info);
int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info);
int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info);
void unload(ErlNifEnv* env, void* priv);

static ErlNifFunc nif_funcs[] = 
{
	{"keypair", 0, ed25519_keypair},
	{"public_key", 1, ed25519_derive_public_key},
};

ERL_NIF_INIT(ed25519, nif_funcs, load, NULL, NULL, NULL)

int load(ErlNifEnv* env, void ** priv_data, ERL_NIF_TERM load_info)
{
	return 0;
}

int reload(ErlNifEnv* env, void** priv, ERL_NIF_TERM load_info)
{
	return 0;
}

int upgrade(ErlNifEnv* env, void** priv, void** old_priv, ERL_NIF_TERM load_info)
{
	return 0;
}

void unload(ErlNifEnv* env, void* priv)
{
	return;
}

ERL_NIF_TERM ed25519_keypair(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
	ErlNifBinary secret;
	ErlNifBinary public;
	ErlNifBinary seed;
	// handle badarg
		
	if (!enif_alloc_binary(64, &secret)){
		return make_error_tuple(env, "alloc_secret_failed");
	}

	if (!enif_alloc_binary(32, &public)){
		return make_error_tuple(env, "alloc_public_failed");
	}

	if (!enif_alloc_binary(32, &seed)){
		return make_error_tuple(env, "alloc_seed_failed");
	}

	// todo pointer release review
	ed25519_create_seed(seed.data);
	int result = ed25519_create_keypair(public.data, secret.data, seed.data);
	if (result!=0){
		return make_error_tuple(env, "ed25519_create_keypair_failed");
	}else{
		return enif_make_tuple3(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &secret),
				enif_make_binary(env, &public));
	}
	
}

ERL_NIF_TERM ed25519_derive_public_key(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[]) 
{
	ErlNifBinary secret;
	ErlNifBinary public;
	enif_inspect_binary(env, argv[0], &secret);	
	if (!enif_alloc_binary(32, &public)){
		return make_error_tuple(env, "alloc_public_failed");
	}
	int result = ed25519_public_key(public.data,secret.data);
	if (result!=0){
		return make_error_tuple(env, "ed25519_public_key");
	}else{
		return enif_make_tuple2(env, 
				enif_make_atom(env, "ok"), 
				enif_make_binary(env, &public));
	}
	

}

ERL_NIF_TERM make_error_tuple(ErlNifEnv *env, char *error)
{
    return enif_make_tuple2(env, enif_make_atom(env, "error"), enif_make_atom(env, error));
}


