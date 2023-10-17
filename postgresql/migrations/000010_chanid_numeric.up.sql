ALTER TABLE public.channels ALTER COLUMN chanid TYPE numeric;
ALTER TABLE public.forwarding_history ALTER COLUMN chanid_in TYPE numeric;
ALTER TABLE public.forwarding_history ALTER COLUMN chanid_out TYPE numeric;