# Write-up

## What I built
TrustVault: authentication with three roles; upload/organise/search/manage documents; per-document read/edit grants to named people; owner-controlled grant and revoke (with optional expiry); a tamper-evident audit trail that records refused attempts; upload validation; an administrator view of activity, alerts and chain integrity; versions; soft delete with recovery and crypto-shred purge; rule-based sharing suggestions that cannot grant; and 189 automated tests plus a script that deletes authorisation checks one at a time to prove the tests notice.

## The decisions that matter
1. **One decision function.** `authz.authorize(db, user, doc_id, action)`. Every route with a document id is wrapped by one decorator that calls it and hands the handler the *authorised row*. A handler never fetches a document by id itself. If you delete the call, the handler never receives a row and the isolation tests fail (`scripts/mutation_check.py` mutation 10 does exactly this).
2. **Default deny.** A request hook refuses any endpoint not explicitly marked. A test inventories every URL rule.
3. **Nothing issued, nothing to revoke.** No tokens, no signed links, no cached permissions. Revocation is immediate because there is nothing else to expire.
4. **Decision + change + audit are one transaction**; the download audit row is written before the bytes are read.
5. **Admins can't read documents.** Separation of duties beats convenience; the cost (orphaned documents, no break-glass) is written down.
6. **404 for "no access" and "doesn't exist"** with identical bodies, so ids cannot be probed.
7. **No folders/groups.** Inheritance is the classic source of over-sharing; I preferred verbose and predictable.

## What I deliberately did not build
External sharing links (every recipient is an account), MFA/SSO, malware scanning, master-key rotation tooling, external audit anchoring, break-glass recovery, groups/folders, a general API rate limiter, any LLM call. Reasons are in `THREATS.md` §G.

## How AI was used, and where it was wrong
See `PROMPTS.md`. Short version: the assistant wrote most of the code and tests quickly, and its most dangerous errors were quiet ones — assertions that could never fail, a 403 that confirmed a deleted document existed, and checks that no test depended on.

## What is unfinished / not yet true
* **Not deployed.** The repository, tests and a Dockerfile exist; there is no live URL yet. The build environment had no route to a hosting provider or to GitHub (account not linked), so deploying and pushing are manual steps.
* **No demo video.**
* **History is short.** The commit history reflects one build session, not a week. `PROMPTS.md` entries cover only what actually happened in that session; the author must add their own dated entries.
* The UI was driven once in headless Chromium (log in as viewer/outsider/admin, search, download, chain banner) with no JavaScript errors, but it has no automated browser tests and I did not test it on mobile or other browsers.
* The mutation list is mine; a reviewer's list will differ.
* Timing side channels beyond login are not equalised.
