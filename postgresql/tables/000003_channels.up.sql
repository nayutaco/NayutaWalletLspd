CREATE TABLE public.channels (
    chanid numeric NOT NULL,
    channel_point character varying,
    nodeid bytea,
    last_update timestamp without time zone,
    reason character varying DEFAULT ''::character varying
);
ALTER TABLE ONLY public.channels
    ADD CONSTRAINT chanid_pkey PRIMARY KEY (chanid);
CREATE INDEX channels_nodeid_idx ON public.channels USING btree (nodeid);
