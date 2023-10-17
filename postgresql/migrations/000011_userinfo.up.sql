CREATE TABLE public.userinfo (
    mail_address character varying NOT NULL,
    count integer
);
ALTER TABLE ONLY public.userinfo
    ADD CONSTRAINT userinfo_pkey PRIMARY KEY (mail_address);
