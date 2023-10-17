CREATE TABLE public.forwarding_history (
    "timestamp" bigint NOT NULL,
    chanid_in numeric NOT NULL,
    chanid_out numeric NOT NULL,
    amt_msat_in bigint NOT NULL,
    amt_msat_out bigint NOT NULL
);
ALTER TABLE ONLY public.forwarding_history
    ADD CONSTRAINT timestamp_pkey PRIMARY KEY ("timestamp");
CREATE INDEX forwarding_history_chanid_in_idx ON public.forwarding_history USING btree (chanid_in);
CREATE INDEX forwarding_history_chanid_out_idx ON public.forwarding_history USING btree (chanid_out);
