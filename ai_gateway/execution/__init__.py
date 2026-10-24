"""
The execution core (D-24, S-13).

One provider call follows the D-24 *Execution sequence* literally:

1. the job context is verified (the execution guard, before any I/O);
2. **reservation** (:mod:`.reservation`): one transaction resolves the
   destination (C-04, D-08), stamps the model's and the provider's first use,
   re-reads the frozen model identity, checks the identity pin, redeems the
   context's ``jti``, reserves the admission units of every scope, charges
   the rate windows and takes the client's occupancy slot, and records the
   resolved provider, boundary, model, profile revision, credential version
   and the context's ``exp`` on a ``pending`` row;
3. **credential material** for exactly the recorded version — the only
   credential-store I/O of the call;
4. the **marker** (:mod:`.settlement`) re-validates everything recorded and
   moves the row to ``dispatching`` before any provider I/O;
5. **provider I/O** under the stored absolute deadline, then one
   settlement from the recorded scope ids and budget day.

:mod:`.service` orchestrates the steps; :mod:`.settlement` holds every
transition of the D-24 table, for the handlers and the sweepers alike.
"""
