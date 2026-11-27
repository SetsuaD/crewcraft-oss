# task-names.sh - the shapes a task's test_path and test_cmd may take. Sourced by tools/task.sh and ci/validate.sh,
# which both read task.json files a pull request can change, so only these shapes are ever copied or run.
# A test name is "t", the task number, an optional part suffix of letters and digits, "_" and a name:
# t001_base32, t611k_signin_link, t360e2_audio, t350d1_archive_push.
task_name='t[0-9]+[a-z0-9]*_[a-z0-9_]+'
task_path_re="^((crates|apps)/[a-z0-9-]+|xtask)/tests/${task_name}\.rs\$"
task_cmd_re="^cargo test -p [a-z0-9-]+ --test ${task_name}\$"
