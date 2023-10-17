CREATE TABLE public.payments (
    payment_hash bytea NOT NULL,
    payment_secret bytea NOT NULL,
    destination bytea NOT NULL,
    incoming_amount_msat bigint NOT NULL,
    outgoing_amount_msat bigint NOT NULL,
    funding_tx_id bytea,
    funding_tx_outnum integer
);
ALTER TABLE ONLY public.payments
    ADD CONSTRAINT payments_pkey PRIMARY KEY (payment_hash);
CREATE INDEX probe_payment_hash ON public.payments USING btree (sha256(('\x70726f62696e672d30313a'::bytea || payment_hash)));
