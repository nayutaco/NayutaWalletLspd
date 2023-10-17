CREATE TABLE public.submarines (
    payment_hash bytea NOT NULL,
    htlc_key bytea NOT NULL,
    remote_node bytea NOT NULL,
    script bytea NOT NULL,
    script_address character varying NOT NULL,
    invoice character varying DEFAULT ''::character varying,
    in_txid bytea,
    in_index integer DEFAULT '-1'::integer,
    in_amount bigint DEFAULT '-1'::integer,
    out_txid bytea,
    status integer NOT NULL,
    height integer NOT NULL,
    script_version integer DEFAULT 0
);
ALTER TABLE ONLY public.submarines
    ADD CONSTRAINT submarines_pkey PRIMARY KEY (payment_hash);
