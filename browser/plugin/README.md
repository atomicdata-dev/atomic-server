# @tomic/plugin

A helper library for building custom views in AtomicServer.

See [the docs](https://docs.atomicdata.dev/plugins/custom-views.html) for more information on how to use it.


## View protocol v1

New SDK builds use `atomic.view.request` / `atomic.view.response` with `version: 1`,
a correlation `id`, an `op`, and an `args` object. The contract and request validator
live in `src/viewProtocol.ts`. Resource replies use `{ subject, title, props, loading }`.
Changes use `atomic.view.change` with a subject and, for packaged views, a resource.
The generated Store-like client uses the same envelope and resource representation;
its plain JS asset has a conformance test alongside this SDK.

The host chooses the view's scope and signing identity. Request arguments cannot
select a policy or grant permissions. Hosts still accept installed clients' older
`__atomic` and `requestId` envelopes. New clients require a v1-capable host; they do
not retry a mutation in a legacy format. Deploy the host before distributing a new
SDK build.

The contract does not promise every operation in every view profile. Generated
views support app/data discovery, get/query, create/save/destroy and subscriptions.
Packaged views support get, patch, context, navigation, pickers and
subscriptions; previously unimplemented query/search now return explicit errors.
`save` replaces a property snapshot; `patch` applies a set/remove mutation. These
are deliberately different operations. Existing public method names remain valid.

Generated writes retain app identity and app-subtree restrictions. Packaged writes
retain their page scope and explicit grants. Both use the shared host policy
evaluator, but backend signing and package lifecycle migration remain separate work.
