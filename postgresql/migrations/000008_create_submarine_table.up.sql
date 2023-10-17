CREATE TABLE public.submarines (
    payment_hash bytea NOT NULL,
    htlc_key bytea NOT NULL,
    remote_node bytea NOT NULL,
    script bytea NOT NULL,
    script_address varchar NOT NULL,
    invoice varchar DEFAULT '',
    in_txid bytea,
    in_index integer DEFAULT -1,
    in_amount bigint DEFAULT -1,
    out_txid bytea,
    status integer NOT NULL,
    height integer NOT NULL,
	CONSTRAINT submarines_pkey PRIMARY KEY (payment_hash)
);