# Prove a test can fail

The user names a test, or the tests added in the working tree. For each one:

1. **Find the fix it guards:** the lines in the diff that the test exists
   for. If there's no fix (a new feature), pick the line whose removal should
   break the behaviour.
2. **Save the current state.** Note the exact lines you will change. Don't
   use `git stash`, which would also hide unrelated work.
3. **Put the bug back.** Revert or break only those lines.
4. **Run only that test**, for example
   `cargo test -p integration_tests_core --test test_group_v3 <name>`.
   It must fail, and for the right reason: read the assertion message.
5. **Restore the fix exactly**, run the test again, and confirm it passes.
   Check with `git diff` that the tree matches the state saved in step 2.

Report a table:

| Test | Bug put back | Failed? | Failure message | Restored and passing |
|---|---|---|---|---|

A test that still passes with the bug back doesn't test the fix. Say so, and
propose what it should assert instead.
