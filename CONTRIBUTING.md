# Contributing to T-Pot Payload Server

First off, thank you for considering contributing to the T-Pot Payload Server! 

## General Rules and Respect

GreedyBear welcomes contributors from anywhere and from any kind of education or skill level. We strive to create a community of developers that is welcoming, friendly and right.
For this reason it is important to follow some easy rules based on a simple but important concept: **Respect**.

- **Approval**: Before starting to work on an issue, you need to get the approval of one of the maintainers by asking to be assigned.
- **Commitment**: After having been assigned, you have a week of time to deliver your first draft PR. After that time has passed without any notice, you will be unassigned.
- **Documentation First**: Before asking questions regarding how the project works, please read through all the documentation and try it locally.
- **Draft Early**: Once you start working on an issue, please raise a draft PR early with incomplete changes so we can track progress and actively review.
- **Use AI Appropriately**: Do not just copy/paste LLM output without checking. AI abuse will result in automatic rejection of PRs.

## Where to Contribute

All active development happens on the **`develop`** branch. 
- Please **do not** open Pull Requests directly against `main`. 
- Always create your feature branch from `develop` and submit your Pull Request back to `develop`.

## Development Setup

We use `uv` for lightning-fast dependency management and `ruff` for strict code linting and formatting.

### 1. Install dependencies
Make sure you have [uv](https://github.com/astral-sh/uv) installed on your system.
```bash
# Clone the repository
git clone https://github.com/GreedyBear-Project/tpot-payload-server.git
cd tpot-payload-server

# Install all dependencies (including test and lint groups)
uv sync --all-groups
```

### 2. Set up Pre-Commit (One-time setup)
We use `pre-commit` to automatically run our linters and formatters before every commit. This ensures that no formatting errors make it into the codebase.

Run this command once to install the pre-commit hooks:
```bash
uv run pre-commit install -c .github/.pre-commit-config.yaml
```
Now, every time you run `git commit`, `ruff` will automatically check and format your code!

### 3. Running Tests
To ensure everything works as expected, run the backend test suite locally before pushing:
```bash
uv run pytest
```
All tests must pass locally before you can successfully open a Pull Request.

## Submitting an Issue

If you spot a bug or have a feature request, please use our provided Issue Template.
When creating an issue, try to fill out all sections:
1. **Problem / What it aims to solve**: Clear description of the bug or feature.
2. **Suggested approach**: If you have an idea on how to fix or implement it, let us know!
3. **Additional context**: Any logs, links, or screenshots.

## Submitting a Pull Request

When you are ready to submit your code:
1. Ensure your branch is based on `develop`.
2. Ensure you have run tests locally (`uv run pytest`).
3. Open a Pull Request against the `develop` branch.
4. Fill out the **Pull Request Template** completely. The checklist is mandatory and helps maintainers review your code faster.
5. Wait for the CI checks (CodeQL, Linter, Tests) to pass. If they fail, fix the issues and push again.
