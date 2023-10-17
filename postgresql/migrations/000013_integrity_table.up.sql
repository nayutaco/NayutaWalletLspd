CREATE TABLE public.integrity (
    nodeid bytea,
    id character varying NOT NULL,
    nonce_created_at timestamp without time zone,
    nonce character varying NOT NULL,
    integrity_executed_at timestamp without time zone,
    integrity_result boolean
);
ALTER TABLE ONLY public.integrity
    ADD CONSTRAINT nodeid_pkey PRIMARY KEY (nodeid);
