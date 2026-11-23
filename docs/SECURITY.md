# Security

## Reporting a vulnerability

Report it privately through GitHub's private vulnerability reporting: **Security → Report a
vulnerability** on this repository. Do not open a public issue. rxenstored copies
oxenstored's behaviour, so a flaw found here may also affect oxenstored or C xenstored: such
reports are passed to the [Xen Project security team](https://xenproject.org/developers/security-policy/)
under its disclosure policy.

rxenstored is experimental and has had no external review: do not expose it to guests you do
not trust.

## The xenstore XSAs

Every Xen security advisory about xenstore, XSA-38 (2013) to XSA-514 (2026), was read
against the code: 25 are covered by a named test, 7 do not apply, and XSA-419 is handled as
oxenstored 4.17 handles it. Daemon: ox = oxenstored, cx = C xenstored. Tests are in
`crates/xs-core/src/tests.rs` unless marked: (d) `crates/xs-daemon/tests/rings/main.rs`,
(r) `crates/xs-sys/src/ring.rs`, (w) `crates/xs-wire/src/lib.rs`.

| XSA | Daemon | Class | What rxenstored does | Test |
|---|---|---|---|---|
| 38 | ox | hostile ring indices | indices read once and checked; a corrupt ring is ignored until its domain dies | (r) `corrupt_indices_are_refused_and_nothing_moves`, (d) `a_guest_that_corrupts_its_ring_is_ignored_until_released` |
| 57 | libxl | toolstack permissions | not the daemon | |
| 72 | ox | oversized replies on a ring | `E2BIG` for what does not fit; `DIRECTORY_PART` lists the rest | `xsa_72_after_e2big_a_ring_goes_on_and_directory_part_lists_it_all` |
| 115 | both | watch events without permission checks | events checked against the store before and after a transaction | `xsa_115_a_commit_s_events_are_checked_against_the_store_before_and_after_the_transaction` |
| 206 | both | a guest starving dom0's transactions | oxenstored 4.17's conflict credit: the guest to blame is paused, dom0 never | `xsa_206_…` (11 tests), (d) `a_guest_paused_for_conflicts_is_served_again_with_nothing_else_happening` |
| 233 | cx | a connection unlinked twice at domain cleanup | a connection has one owner, the core's table of connections | |
| 272 | ox | quota bypass | every way of creating a node counts | `xsa_272_every_way_of_creating_a_node_counts` |
| 322 | both | a dead domain's rights inherited | its ACL entries go at death, in transactions too | `xsa_322_a_dead_domain_s_acl_entries_do_not_come_back_with_a_transaction` |
| 323 | ox | path length checked too early | counted after the domain's prefix | `xsa_323_the_length_limit_is_on_the_part_after_the_domain_s_home` |
| 324 | cx | oversized watch event | `ERROR E2BIG`, and the ring goes on | `xsa_324_after_an_oversized_event_a_ring_goes_on` |
| 325 | cx | protocol violation removes the domain | the guest is ignored, its domain still cleaned up at death | `xsa_325_a_guest_that_breaks_the_protocol_is_ignored_and_its_domain_still_dies`, (d) `xsa_325_…` |
| 326 | both | memory a guest can grow | oxenstored 4.17's quotas in the core; the guest that floods a watcher is held | `xsa_326a_…` to `xsa_326f_…`, (d) `a_guest_that_does_not_read_is_held_at_the_soft_limit` |
| 330 | ox | watches left after RESET_WATCHES | none left | `xsa_330_and_512_reset_and_reconnection_leave_no_watch_behind` |
| 349 | kernels | event queues in frontends | not the daemon | |
| 352 | ox | owner changed by a guest | only dom0 changes an owner, in transactions too | `xsa_352_a_guest_cannot_give_a_node_away_in_a_transaction_either` |
| 353 | ox | root not checked | the root is checked as any node | `xsa_353_the_root_is_checked_as_any_node` |
| 354 | xapi | toolstack memory | not the daemon | |
| 414 | cx | wrong pointer on an error path | safe Rust; the count stays right | `xsa_414_a_failed_creation_keeps_what_it_made_and_its_count` |
| 415 | cx | orphaned nodes after a failed creation in a transaction | a node exists only in its parent's map: nothing can be orphaned | |
| 416 | cx | memory kept until a reply is read | the ring is held at the soft limit | `xsa_416_a_ring_that_does_not_read_is_held_at_the_soft_limit` |
| 417 | cx | rights before a domain exists | they end with the domain | `xsa_417_permissions_granted_before_a_domain_exists_end_with_it` |
| 418 | cx | stack exhaustion | recursion bounded by the path length, measured | `xsa_418_the_deepest_paths_a_request_can_name_fit_in_the_stack` |
| 419 | both | nodes charged to the wrong domain | **as oxenstored 4.17**: a node counts for its owner (below) | `xsa_419_a_node_counts_for_its_owner_not_for_its_creator` |
| 420 | ox | packet length truncated | a length over 4,096 is refused before anything is allocated; the connection is closed once and its ring not read again | `xsa_420_any_length_past_a_payload_ends_the_ring_once`, (w) `decoder_rejects_oversized_length` |
| 421 | cx | nodes created and deleted in a transaction | they count for nothing | `xsa_421_create_then_delete_in_one_transaction_counts_nothing` |
| 425 | cx | connection freed during the loop | connections looked up by id after each step | (d) `xsa_425_connections_that_go_while_others_wait_in_the_same_pass` |
| 440 | cx | negative transient counts assert | counts saturate, no assertion | `xsa_440_two_transactions_removing_the_same_nodes_count_once` |
| 481 | cx | `/local/domain/` crashes | such paths refused or looked up as any | `xsa_481_paths_in_the_domain_prefix_are_refused_or_looked_up_as_any` |
| 483 | ox | quota counts outlive a domain | reset at death and release | `xsa_483_a_dead_or_released_domain_starts_again_from_nothing` |
| 484 | cx | RESET_WATCHES in a transaction | ends the transaction | `xsa_484_reset_watches_in_a_transaction_ends_it` |
| 496 | Xen | event-channel binding | not the daemon | |
| 512 | ox | watches accumulate over reconnections | none left | `xsa_330_and_512_reset_and_reconnection_leave_no_watch_behind` |
| 514 | cx | live-update record | no live update | |

Two more regression tests cover behaviours beyond the XSAs:
`a_target_that_dies_or_is_released_is_no_longer_acted_for` and
`release_of_domain_0_or_of_a_reserved_domid_touches_nothing`.

## Known limits

- **XSA-419 class, kept for compatibility**: nodes a guest creates below a dom0-owned node it
  may write count for dom0, which has no quota. On the one host where this was looked for,
  with Linux and Windows guests, the store had no such node (transient nodes not covered).
- **No per-domain memory bound and no transaction age limit**: the quotas bound nodes,
  watches, transactions, queued output and what a guest's open transactions keep of their
  requests (`quota-transaction-bytes`), not the memory a guest can make dom0 hold in total.
- **Work per request** is not constant everywhere: some requests cost in proportion to state
  a guest can build within its quotas.
- **The ring page** is written by the guest while the daemon reads it. Every access to it is
  atomic (Miri reported the earlier volatile accesses as data races) and each byte is read
  once and never trusted. Its read and write code is model-checked against any page contents,
sequentially and within bounds ([`TESTING.md`](TESTING.md)). Rust says nothing about memory
written from outside the program.
- **Not done**: an external review. Fuzzing has only started: see [`TESTING.md`](TESTING.md).
