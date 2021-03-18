# Contributing
## Contributing Guidlines
TBD

## Contributing Tips
For developing in an IDE,  the Intellij-Rust plugin is recommended.  
To quickly check if your modifications can be built, run `cargo check`.  
You should frequently lint your code using `cargo clippy`. It nicely checks for common mistakes. 
It is forced to be run before each commit anyway (using git hooks).
After committing your changes, you should run `cargo fmt`, which automatically formats your code according to Rust 
guidelines. You can use `git commit --amend` to add the formatting changes to your last commit.  
If you want to check for formatting errors without committing, use `cargo fmt -- --check`.

`cargo test && cargo fmt -- --check` is also run as git hook before pushing to prevent introducing regressions and formatting issues from beeing added to the repository.

